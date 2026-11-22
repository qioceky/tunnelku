package id.tunnelku.vpn.stack

import java.io.InputStream
import java.io.OutputStream
import java.util.Base64
import java.util.TreeMap
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.Semaphore
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Forwarder TUN userspace — port perilaku `z7` XVEON (bukan stack naif):
 *
 * - SYN-ACK dikirim SETELAH stream upstream berhasil dibuka; gagal → RST+ACK.
 * - Tanpa retransmit/RTO/congestion-control buatan: window tetap 65535,
 *   ACK langsung per segment, keandalan dititipkan ke transport di bawahnya.
 * - MSS = clamp(clamp(mtu,1280,1500) − 140, 1140, 1360); MSS klien diabaikan.
 * - Sesi TCP cap 96 (evict-oldest), idle 120 dtk / 15 dtk setelah FIN klien,
 *   buffer out-of-order maks 32 segment/sesi.
 * - DNS jalur khusus: cache (key = question saja, TTL tetap 45 dtk) →
 *   DNS native engine → DNS-over-TCP (1 koneksi per query, 4000 ms) → UDPGW.
 * - UDP native (Xray): cap 48 sesi, idle 45 dtk. UDPGW: demux hanya clientPort.
 * - ICMP & IPv6 dibuang total.
 */
class TunStack(
    private val tunIn: InputStream,
    private val tunOut: OutputStream,
    private val engine: OutboundEngine,
    mtu: Int,
    private val tcpTimeoutMs: Int = 30000,
    private val udpTimeoutMs: Int = 10000,
    private val readBufferSize: Int = 4096,
    private val channelBufferSize: Int = 16384,
    private val log: (String) -> Unit = {},
    private val onEngineLost: (String) -> Unit = {},
    private val countUp: (Int) -> Unit = {},
    private val countDown: (Int) -> Unit = {},
) {
    private val mss: Int = (mtu.coerceIn(1280, 1500) - 140).coerceIn(1140, 1360)

    private val running = AtomicBoolean(false)
    private val lostNotified = AtomicBoolean(false)
    private val threadNo = AtomicInteger(0)
    private val pool = ThreadPoolExecutor(
        0, 96, 10, TimeUnit.SECONDS, SynchronousQueue(),
        { r ->
            Thread(null, r, "tunnelku-net-" + threadNo.incrementAndGet(), 262144L).apply {
                isDaemon = true; priority = 4
            }
        },
        ThreadPoolExecutor.AbortPolicy(),
    )

    private val writeLock = Object()

    // ---- TCP ----
    private data class TcpKey(val srcIp: Int, val srcPort: Int, val dstIp: Int, val dstPort: Int)
    private val tcpSessions = ConcurrentHashMap<TcpKey, TcpSession>()
    @Volatile private var lastSweepMs = 0L

    // ---- UDP native ----
    private data class UdpKey(val srcIp: Int, val srcPort: Int, val dstIp: Int, val dstPort: Int)
    private val udpSessions = ConcurrentHashMap<UdpKey, UdpSession>()

    // ---- DNS ----
    private data class DnsEntry(val data: ByteArray, val expiryMs: Long)
    private val dnsCache = ConcurrentHashMap<String, DnsEntry>()
    private val dnsSemaphore = Semaphore(16)
    private val dotSuccessStreak = AtomicInteger(0)
    private val nativeDnsDisabled = AtomicBoolean(false)

    // ---- UDPGW ----
    private data class GwDest(val clientIp: Int, val dstIp: Int, val dstPort: Int)
    private val gwReplies = ConcurrentHashMap<Int, GwDest>()
    private val gwQueue = LinkedBlockingQueue<ByteArray>(256)
    @Volatile private var gwHandle: TcpHandle? = null
    private val gwLock = Object()

    fun start() {
        if (!running.compareAndSet(false, true)) return
        Thread({ tunLoop() }, "tunnelku-tun").apply { isDaemon = true }.start()
        Thread({ udpSweeper() }, "tunnelku-udp-sweep").apply { isDaemon = true }.start()
        Thread({ gwWriterLoop() }, "tunnelku-udpgw").apply { isDaemon = true }.start()
    }

    fun stop() {
        running.set(false)
        for (s in tcpSessions.values) s.close()
        tcpSessions.clear()
        for (s in udpSessions.values) s.close()
        udpSessions.clear()
        synchronized(gwLock) {
            try { gwHandle?.close() } catch (e: Exception) { /* abaikan */ }
            gwHandle = null
        }
        pool.shutdownNow()
    }

    private fun notifyLost(msg: String) {
        if (lostNotified.compareAndSet(false, true)) onEngineLost(msg)
    }

    private fun writePacket(pkt: ByteArray) {
        synchronized(writeLock) {
            try {
                tunOut.write(pkt)
                tunOut.flush()
            } catch (e: Exception) {
                // TUN sudah mati — abaikan; loop baca akan berhenti sendiri.
            }
        }
        countDown(pkt.size)
    }

    // ================= TUN loop =================

    private fun tunLoop() {
        val buf = ByteArray(readBufferSize.coerceIn(2048, 65536))
        while (running.get()) {
            val n = try {
                tunIn.read(buf)
            } catch (e: Exception) {
                if (running.get()) notifyLost("TUN read error: ${e.message}")
                break
            }
            if (n <= 0) {
                try { Thread.sleep(5) } catch (e: InterruptedException) { break }
                continue
            }
            countUp(n)
            if (n < 20) continue
            if ((buf[0].toInt() shr 4) != 4) continue // IPv6 dibuang total
            val ihl = (buf[0].toInt() and 0x0F) * 4
            if (ihl < 20 || n < ihl) continue
            var total = Packets.u16(buf, 2)
            if (total <= 0 || total > n) total = n
            when (buf[9].toInt() and 0xFF) {
                6 -> dispatchTcp(buf, ihl, total)
                17 -> dispatchUdp(buf, ihl, total)
                else -> { /* ICMP & lainnya dibuang */ }
            }
        }
    }

    // ================= TCP =================

    private inner class TcpSession(val key: TcpKey, val clientIsn: Long, nowMs: Long) {
        val serverIsn: Long = System.nanoTime() and 0x3FFFFFFFL
        @Volatile var expectedSeq: Long = (clientIsn + 1) and 0xFFFFFFFFL
        @Volatile var serverSeq: Long = serverIsn
        @Volatile var synAckSent = false
        @Volatile var clientFin = false
        @Volatile var serverFin = false
        val closed = AtomicBoolean(false)
        @Volatile var lastActivityMs = nowMs
        var handle: TcpHandle? = null
        val sendQueue = LinkedBlockingQueue<ByteArray>()
        val ooo = TreeMap<Long, ByteArray>()
        val writerStarted = AtomicBoolean(false)

        fun reply(flags: Int, payload: ByteArray? = null, off: Int = 0, len: Int = 0, seq: Long = serverSeq, ack: Long = expectedSeq, withMss: Boolean = false) {
            writePacket(
                Packets.tcp(
                    key.dstIp, key.dstPort, key.srcIp, key.srcPort,
                    seq, ack, flags, payload, off, len, if (withMss) mss else null,
                ),
            )
        }

        fun sendAck() = reply(Packets.FLAG_ACK)

        fun sendSynAck() {
            reply(Packets.FLAG_SYN or Packets.FLAG_ACK, seq = serverIsn, ack = (clientIsn + 1) and 0xFFFFFFFFL, withMss = true)
            if (!synAckSent) {
                serverSeq = (serverIsn + 1) and 0xFFFFFFFFL
                synAckSent = true
            }
        }

        fun sendRst() {
            if (!closed.get()) reply(Packets.FLAG_RST or Packets.FLAG_ACK)
        }

        /** Task connect (m2 case 5): buka upstream DULU, baru SYN-ACK. */
        fun connectAndServe() {
            val h = try {
                engine.openTcp(
                    Packets.ipToString(key.dstIp), key.dstPort,
                    Packets.ipToString(key.srcIp), key.srcPort,
                    tcpTimeoutMs.coerceIn(2000, 60000),
                )
            } catch (e: Exception) {
                reply(Packets.FLAG_RST or Packets.FLAG_ACK, seq = serverIsn, ack = expectedSeq)
                close()
                return
            }
            if (closed.get()) {
                try { h.close() } catch (e: Exception) { /* abaikan */ }
                return
            }
            handle = h
            sendSynAck()
            if (writerStarted.compareAndSet(false, true)) {
                try {
                    pool.execute { writerLoop() }
                } catch (e: RejectedExecutionException) {
                    kill()
                    return
                }
            }
            readerLoop(h)
        }

        private fun writerLoop() {
            val out = handle?.output ?: return
            val buf = ByteArray(16384)
            try {
                while (!closed.get()) {
                    val first = sendQueue.poll(200, TimeUnit.MILLISECONDS) ?: continue
                    var filled = 0
                    System.arraycopy(first, 0, buf, 0, first.size)
                    filled = first.size
                    while (filled < 14336) {
                        val next = sendQueue.peek() ?: break
                        if (next.size > buf.size - filled) break
                        sendQueue.poll()
                        System.arraycopy(next, 0, buf, filled, next.size)
                        filled += next.size
                    }
                    out.write(buf, 0, filled)
                    if (sendQueue.isEmpty()) out.flush()
                }
            } catch (e: Exception) {
                if (!closed.get()) {
                    sendRst()
                    if (!engine.isConnected()) notifyLost("TCP write error: ${e.message}")
                }
                close()
            }
        }

        private fun readerLoop(h: TcpHandle) {
            val buf = ByteArray(channelBufferSize.coerceIn(1024, 65536))
            try {
                while (!closed.get()) {
                    val n = h.input.read(buf)
                    if (n <= 0) break
                    lastActivityMs = System.currentTimeMillis()
                    var off = 0
                    var remaining = n
                    while (remaining > 0) {
                        val chunk = minOf(remaining, mss)
                        reply(Packets.FLAG_PSH or Packets.FLAG_ACK, buf, off, chunk)
                        serverSeq = (serverSeq + chunk) and 0xFFFFFFFFL
                        off += chunk
                        remaining -= chunk
                    }
                }
            } catch (e: Exception) {
                if (!closed.get() && !engine.isConnected()) {
                    notifyLost("TCP read error: ${e.message}")
                }
                if (!closed.get()) sendRst()
                close()
                return
            }
            // EOF dari server
            if (!closed.get()) {
                reply(Packets.FLAG_FIN or Packets.FLAG_ACK)
                serverSeq = (serverSeq + 1) and 0xFFFFFFFFL
                serverFin = true
                if (clientFin) close()
            }
        }

        /** Paket data/ACK/FIN dari klien untuk sesi ini. */
        fun onPacket(seq: Long, flags: Int, payload: ByteArray, payloadOff: Int, payloadLen: Int) {
            lastActivityMs = System.currentTimeMillis()
            if (payloadLen > 0) onData(seq, payload, payloadOff, payloadLen)
            if (flags and Packets.FLAG_FIN != 0 && !clientFin) {
                val finEnd = (seq + payloadLen) and 0xFFFFFFFFL
                if (finEnd == expectedSeq) {
                    expectedSeq = (expectedSeq + 1) and 0xFFFFFFFFL
                    clientFin = true
                    sendAck()
                    if (serverFin) close()
                }
            }
        }

        private fun onData(seqIn: Long, payload: ByteArray, offIn: Int, lenIn: Int) {
            var seq = seqIn
            var off = offIn
            var len = lenIn
            val end = (seq + len) and 0xFFFFFFFFL
            if (end == expectedSeq || seqBefore(end, expectedSeq)) {
                // seluruhnya data lama (retransmit)
                sendAck()
                return
            }
            if (seqBefore(seq, expectedSeq)) {
                val trim = (expectedSeq - seq).toInt()
                if (trim >= len) {
                    sendAck()
                    return
                }
                off += trim
                len -= trim
                seq = expectedSeq
            }
            if (seq == expectedSeq) {
                sendQueue.offer(payload.copyOfRange(off, off + len))
                expectedSeq = (expectedSeq + len) and 0xFFFFFFFFL
                // drain buffer out-of-order (dengan trim tumpang tindih)
                while (true) {
                    val seg = synchronized(ooo) {
                        val firstKey = if (ooo.isEmpty()) null else ooo.firstKey()
                        when {
                            firstKey == null -> null
                            firstKey == expectedSeq -> ooo.remove(firstKey)
                            seqBefore(firstKey, expectedSeq) -> {
                                val s = ooo.remove(firstKey)!!
                                val trim = (expectedSeq - firstKey).toInt()
                                if (trim >= s.size) null else s.copyOfRange(trim, s.size)
                            }
                            else -> null
                        }
                    } ?: break
                    if (seg.isEmpty()) continue
                    sendQueue.offer(seg)
                    expectedSeq = (expectedSeq + seg.size) and 0xFFFFFFFFL
                }
                sendAck()
            } else {
                // masa depan → buffer OOO (maks 32)
                synchronized(ooo) {
                    if (ooo.size < 32 && !ooo.containsKey(seq)) {
                        ooo[seq] = payload.copyOfRange(off, off + len)
                    }
                }
                sendAck()
            }
        }

        fun kill() {
            sendRst()
            close()
        }

        fun close() {
            if (!closed.compareAndSet(false, true)) return
            tcpSessions.remove(key, this)
            try { handle?.close() } catch (e: Exception) { /* abaikan */ }
        }
    }

    /** Perbandingan seq TCP aman-wrap (a sebelum b?). */
    private fun seqBefore(a: Long, b: Long): Boolean {
        val diff = (b - a) and 0xFFFFFFFFL
        return diff != 0L && diff < 0x80000000L
    }

    private fun dispatchTcp(pkt: ByteArray, ihl: Int, total: Int) {
        val t = ihl
        if (total < t + 20) return
        val srcIp = Packets.ipBytesToInt(pkt, 12)
        val dstIp = Packets.ipBytesToInt(pkt, 16)
        val srcPort = Packets.u16(pkt, t)
        val dstPort = Packets.u16(pkt, t + 2)
        val seq = Packets.u32(pkt, t + 4)
        val ack = Packets.u32(pkt, t + 8)
        val dataOff = ((pkt[t + 12].toInt() shr 4) and 0x0F) * 4
        if (dataOff < 20 || t + dataOff > total) return
        val flags = pkt[t + 13].toInt() and 0xFF
        val payloadOff = t + dataOff
        val payloadLen = total - payloadOff
        val key = TcpKey(srcIp, srcPort, dstIp, dstPort)
        val now = System.currentTimeMillis()

        if (flags and Packets.FLAG_RST != 0) {
            tcpSessions.remove(key)?.close()
            return
        }

        if (flags and Packets.FLAG_SYN != 0 && flags and Packets.FLAG_ACK == 0) {
            val existing = tcpSessions[key]
            if (existing != null && existing.clientIsn == seq) {
                if (!existing.synAckSent || existing.closed.get()) return
                existing.sendSynAck()
                return
            }
            if (existing != null) {
                existing.close()
                tcpSessions.remove(key)
            }
            maybeSweep(now)
            if (tcpSessions.size >= 96) {
                tcpSessions.values.minByOrNull { it.lastActivityMs }?.let {
                    it.close()
                    tcpSessions.remove(it.key)
                }
            }
            val sess = TcpSession(key, seq, now)
            tcpSessions[key] = sess
            try {
                pool.execute { sess.connectAndServe() }
            } catch (e: RejectedExecutionException) {
                sess.close()
            }
            return
        }

        val sess = tcpSessions[key]
        if (sess == null) {
            val isPureAck = flags and Packets.FLAG_ACK != 0 && flags and Packets.FLAG_FIN == 0 &&
                flags and Packets.FLAG_SYN == 0 && payloadLen == 0
            if (isPureAck) return
            writePacket(
                Packets.tcp(
                    dstIp, dstPort, srcIp, srcPort,
                    seq = ack, ack = (seq + maxOf(1, payloadLen)) and 0xFFFFFFFFL,
                    flags = Packets.FLAG_RST or Packets.FLAG_ACK,
                ),
            )
            return
        }
        if (sess.closed.get()) return
        sess.onPacket(seq, flags, pkt, payloadOff, payloadLen)
    }

    private fun maybeSweep(now: Long) {
        if (now - lastSweepMs < 30000) return
        if (tcpSessions.size < 48 && udpSessions.size < 24) return
        lastSweepMs = now
        val it = tcpSessions.entries.iterator()
        while (it.hasNext()) {
            val s = it.next().value
            if (s.closed.get() || (s.clientFin && now - s.lastActivityMs > 15000) || now - s.lastActivityMs > 120000) {
                it.remove()
                s.close()
            }
        }
        if (dnsCache.size > 128) {
            val dit = dnsCache.entries.iterator()
            while (dit.hasNext()) {
                if (now > dit.next().value.expiryMs) dit.remove()
            }
        }
        if (gwReplies.size > 512) gwReplies.clear()
    }

    // ================= UDP =================

    private inner class UdpSession(val key: UdpKey, val handle: UdpHandle) {
        @Volatile var lastActivityMs = System.currentTimeMillis()
        val closed = AtomicBoolean(false)
        val sendQueue = LinkedBlockingQueue<ByteArray>(48)
        val writerStarted = AtomicBoolean(false)

        fun enqueue(data: ByteArray) {
            lastActivityMs = System.currentTimeMillis()
            if (!sendQueue.offer(data)) {
                sendQueue.poll()
                sendQueue.offer(data)
            }
            if (writerStarted.compareAndSet(false, true)) {
                try {
                    pool.execute { writerLoop() }
                } catch (e: RejectedExecutionException) {
                    close()
                }
            }
        }

        private fun writerLoop() {
            try {
                while (!closed.get()) {
                    val first = sendQueue.poll(200, TimeUnit.MILLISECONDS) ?: continue
                    handle.send(first, 0, first.size)
                    var extra = 0
                    while (extra < 8) {
                        val next = sendQueue.poll() ?: break
                        handle.send(next, 0, next.size)
                        extra++
                    }
                    handle.flush()
                }
            } catch (e: Exception) {
                close()
            }
        }

        fun onReply(srcIp: Int, srcPort: Int, data: ByteArray, off: Int, len: Int) {
            lastActivityMs = System.currentTimeMillis()
            writePacket(Packets.udp(srcIp, srcPort, key.srcIp, key.srcPort, data, off, len))
        }

        fun close() {
            if (!closed.compareAndSet(false, true)) return
            udpSessions.remove(key, this)
            try { handle.close() } catch (e: Exception) { /* abaikan */ }
        }
    }

    private fun udpSweeper() {
        while (running.get()) {
            try { Thread.sleep(30000) } catch (e: InterruptedException) { break }
            val now = System.currentTimeMillis()
            val it = udpSessions.entries.iterator()
            while (it.hasNext()) {
                val s = it.next().value
                if (s.closed.get() || now - s.lastActivityMs > 45000) {
                    it.remove()
                    s.close()
                }
            }
        }
    }

    private fun dispatchUdp(pkt: ByteArray, ihl: Int, total: Int) {
        val u = ihl
        if (total < u + 8) return
        val srcIp = Packets.ipBytesToInt(pkt, 12)
        val dstIp = Packets.ipBytesToInt(pkt, 16)
        val srcPort = Packets.u16(pkt, u)
        val dstPort = Packets.u16(pkt, u + 2)
        val udpLen = Packets.u16(pkt, u + 4)
        val payloadOff = u + 8
        var payloadLen = minOf(udpLen - 8, total - payloadOff)
        if (payloadLen <= 0 || payloadLen > 32768) return
        val payload = pkt.copyOfRange(payloadOff, payloadOff + payloadLen)

        if (dstPort == 53) {
            handleDns(srcIp, srcPort, dstIp, payload)
            return
        }
        if (engine.nativeUdpAvailable()) {
            val key = if (engine.sharesUdpAssociation()) {
                UdpKey(srcIp, srcPort, 0, 0)
            } else {
                UdpKey(srcIp, srcPort, dstIp, dstPort)
            }
            var sess = udpSessions[key]
            if (sess == null || sess.closed.get()) {
                if (udpSessions.size >= 48) {
                    val now = System.currentTimeMillis()
                    val it = udpSessions.entries.iterator()
                    while (it.hasNext()) {
                        val s = it.next().value
                        if (s.closed.get() || now - s.lastActivityMs > 45000) {
                            it.remove(); s.close()
                        }
                    }
                    if (udpSessions.size >= 48) {
                        udpSessions.values.minByOrNull { it.lastActivityMs }?.close()
                    }
                }
                val handle = try {
                    engine.openUdpSession(Packets.ipToString(dstIp), dstPort, udpTimeoutMs)
                } catch (e: Exception) {
                    log("Sesi UDP gagal ke ${Packets.ipToString(dstIp)}:$dstPort — ${e.message}")
                    return
                }
                val created = UdpSession(key, handle)
                handle.startReceiver { rSrcIp, rSrcPort, data, off, len ->
                    val replySrcIp = if (engine.sharesUdpAssociation()) rSrcIp else dstIp
                    val replySrcPort = if (engine.sharesUdpAssociation()) rSrcPort else dstPort
                    created.onReply(replySrcIp, replySrcPort, data, off, len)
                }
                udpSessions[key] = created
                sess = created
            }
            sess.enqueue(payload)
            return
        }
        if (engine.udpForwardingEnabled()) {
            gwSend(srcIp, srcPort, dstIp, dstPort, payload)
        }
        // selain itu: dibuang diam-diam (sama seperti XVEON)
    }

    // ================= DNS =================

    private fun dnsQuestionKey(query: ByteArray): String? {
        if (query.size <= 12 || query.size > 512) return null
        val flags = Packets.u16(query, 2)
        if (flags and 0xF800 != 0) return null
        if (Packets.u16(query, 4) != 1) return null
        return Base64.getEncoder().encodeToString(query.copyOfRange(12, query.size))
    }

    private fun dnsCacheable(resp: ByteArray): Boolean {
        if (resp.size < 12 || resp.size > 4096) return false
        if (resp[3].toInt() and 0x0F != 0) return false // RCODE
        if (Packets.u16(resp, 6) <= 0) return false // ANCOUNT
        return true
    }

    private fun cacheDns(key: String?, resp: ByteArray) {
        if (key == null || !dnsCacheable(resp)) return
        if (dnsCache.size >= 160) dnsCache.clear()
        dnsCache[key] = DnsEntry(resp.copyOf(), System.currentTimeMillis() + 45000)
    }

    private fun injectDnsReply(clientIp: Int, clientPort: Int, serverIp: Int, query: ByteArray, respIn: ByteArray) {
        val resp = respIn.copyOf()
        if (resp.size >= 2 && query.size >= 2) {
            resp[0] = query[0]; resp[1] = query[1]
        }
        writePacket(Packets.udp(serverIp, 53, clientIp, clientPort, resp))
    }

    private fun handleDns(clientIp: Int, clientPort: Int, serverIp: Int, query: ByteArray) {
        val key = dnsQuestionKey(query)
        if (key != null) {
            val entry = dnsCache[key]
            if (entry != null) {
                if (System.currentTimeMillis() < entry.expiryMs) {
                    injectDnsReply(clientIp, clientPort, serverIp, query, entry.data)
                    return
                }
                dnsCache.remove(key)
            }
        }
        try {
            pool.execute { resolveDns(clientIp, clientPort, serverIp, query, key) }
        } catch (e: RejectedExecutionException) {
            // pool penuh — query dibuang
        }
    }

    private fun resolveDns(clientIp: Int, clientPort: Int, serverIp: Int, query: ByteArray, key: String?) {
        // (2) DNS native engine (Xray)
        if (engine.nativeUdpAvailable() && !nativeDnsDisabled.get()) {
            val resp = try {
                engine.exchangeDns(Packets.ipToString(serverIp), query)
            } catch (e: Exception) {
                null
            }
            if (resp != null) {
                dotSuccessStreak.set(0)
                cacheDns(key, resp)
                injectDnsReply(clientIp, clientPort, serverIp, query, resp)
                return
            }
        }
        // (3) DNS-over-TCP
        if (!dnsSemaphore.tryAcquire()) {
            if (engine.udpForwardingEnabled()) {
                gwSend(clientIp, clientPort, serverIp, 53, query)
            }
            return
        }
        try {
            val resolvers = LinkedHashSet<Int>()
            resolvers.add(serverIp)
            resolvers.add(Packets.ipToInt("1.1.1.1"))
            resolvers.add(Packets.ipToInt("8.8.8.8"))
            for (resolver in resolvers) {
                val resp = dnsOverTcp(clientIp, clientPort, resolver, query) ?: continue
                cacheDns(key, resp)
                injectDnsReply(clientIp, clientPort, serverIp, query, resp)
                if (dotSuccessStreak.incrementAndGet() >= 2) nativeDnsDisabled.set(true)
                return
            }
            // (4) fallback UDPGW
            if (engine.udpForwardingEnabled()) {
                gwSend(clientIp, clientPort, serverIp, 53, query)
            }
        } finally {
            dnsSemaphore.release()
        }
    }

    private fun dnsOverTcp(clientIp: Int, clientPort: Int, resolver: Int, query: ByteArray): ByteArray? {
        var handle: TcpHandle? = null
        return try {
            handle = engine.openTcp(Packets.ipToString(resolver), 53, Packets.ipToString(clientIp), clientPort, 4000)
            handle.setTimeout(4000)
            val out = handle.output
            val frame = ByteArray(2 + query.size)
            Packets.put16(frame, 0, query.size)
            System.arraycopy(query, 0, frame, 2, query.size)
            out.write(frame)
            out.flush()
            val inp = handle.input
            val lenBuf = ByteArray(2)
            if (!readFully(inp, lenBuf, 0, 2)) return null
            val respLen = Packets.u16(lenBuf, 0)
            if (respLen < 1 || respLen > 16384) return null
            val resp = ByteArray(respLen)
            if (!readFully(inp, resp, 0, respLen)) return null
            resp
        } catch (e: Exception) {
            null
        } finally {
            try { handle?.close() } catch (e: Exception) { /* abaikan */ }
        }
    }

    private fun readFully(inp: InputStream, buf: ByteArray, off: Int, len: Int): Boolean {
        var read = 0
        while (read < len) {
            val n = inp.read(buf, off + read, len - read)
            if (n <= 0) return false
            read += n
        }
        return true
    }

    // ================= UDPGW =================

    private fun gwSend(clientIp: Int, clientPort: Int, dstIp: Int, dstPort: Int, payload: ByteArray) {
        if (gwReplies.size > 512) gwReplies.clear()
        gwReplies[clientPort] = GwDest(clientIp, dstIp, dstPort)
        val frameLen = 9 + payload.size
        val frame = ByteArray(2 + frameLen)
        frame[0] = (frameLen and 0xFF).toByte()
        frame[1] = ((frameLen shr 8) and 0xFF).toByte()
        frame[2] = 0x01
        frame[3] = (clientPort and 0xFF).toByte()
        frame[4] = ((clientPort shr 8) and 0xFF).toByte()
        Packets.put32(frame, 5, dstIp.toLong())
        Packets.put16(frame, 9, dstPort)
        System.arraycopy(payload, 0, frame, 11, payload.size)
        if (!gwQueue.offer(frame)) {
            gwQueue.poll()
            gwQueue.offer(frame)
        }
    }

    private fun gwEnsureOpen(): TcpHandle? {
        synchronized(gwLock) {
            gwHandle?.let { if (it.isConnected()) return it }
            val h = try {
                engine.openUdpGw()
            } catch (e: Exception) {
                null
            }
            gwHandle = h
            if (h != null) {
                Thread({ gwReaderLoop(h) }, "tunnelku-udpgw-read").apply { isDaemon = true }.start()
            }
            return h
        }
    }

    private fun gwWriterLoop() {
        while (running.get()) {
            val first = try {
                gwQueue.poll(10, TimeUnit.SECONDS)
            } catch (e: InterruptedException) {
                break
            } ?: continue
            val h = gwEnsureOpen()
            if (h == null) {
                continue // gateway tidak tersedia — frame dibuang
            }
            try {
                val out = h.output
                out.write(first)
                var extra = 0
                while (extra < 16) {
                    val next = gwQueue.poll() ?: break
                    out.write(next)
                    extra++
                }
                out.flush()
            } catch (e: Exception) {
                synchronized(gwLock) {
                    if (gwHandle === h) gwHandle = null
                }
                try { h.close() } catch (e2: Exception) { /* abaikan */ }
            }
        }
    }

    private fun gwReaderLoop(h: TcpHandle) {
        val inp = h.input
        val lenBuf = ByteArray(2)
        try {
            while (running.get()) {
                if (!readFully(inp, lenBuf, 0, 2)) break
                val len = (lenBuf[0].toInt() and 0xFF) or ((lenBuf[1].toInt() and 0xFF) shl 8)
                if (len < 9 || len > 65535) break
                val frame = ByteArray(len)
                if (!readFully(inp, frame, 0, len)) break
                val flags = frame[0].toInt() and 0xFF
                val addrLen = if (flags and 0x04 != 0) 16 else 4
                if (len < 1 + 2 + addrLen + 2) continue
                val clientPort = (frame[1].toInt() and 0xFF) or ((frame[2].toInt() and 0xFF) shl 8)
                val payloadOff = 1 + 2 + addrLen + 2
                val dest = gwReplies[clientPort] ?: continue
                writePacket(
                    Packets.udp(
                        dest.dstIp, dest.dstPort, dest.clientIp, clientPort,
                        frame, payloadOff, len - payloadOff,
                    ),
                )
            }
        } catch (e: Exception) {
            // stream mati — writer akan membuka ulang saat ada frame baru
        } finally {
            synchronized(gwLock) {
                if (gwHandle === h) gwHandle = null
            }
            try { h.close() } catch (e: Exception) { /* abaikan */ }
        }
    }
}
