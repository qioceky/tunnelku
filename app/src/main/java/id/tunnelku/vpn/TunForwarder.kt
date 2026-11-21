package id.tunnelku.vpn

import com.jcraft.jsch.ChannelDirectTCPIP
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import kotlin.concurrent.thread
import kotlin.random.Random

/**
 * Mesin TUN -> SSH TunnelKu v0.1 (Java/Kotlin murni, tanpa native):
 * tumpukan TCP userspace sederhana di atas channel direct-tcpip JSch.
 * - TCP: state machine ringkas (SYN/DATA/FIN/RST), go-back-N untuk segmen tak urut.
 * - UDP: hanya DNS (port 53) yang diteruskan, lewat DNS-over-TCP di dalam SSH;
 *   UDP lain dibuang (UDP penuh via UDPGW menyusul di v0.2).
 * - IPv6: dibuang (route ::/0 diarahkan ke TUN agar tidak bocor keluar VPN).
 */
class TunForwarder(
    private val tunIn: InputStream,
    private val tunOut: OutputStream,
    private val ssh: SshTunnel,
    private val dnsServer: String,
    private val log: (String) -> Unit,
) {
    @Volatile private var running = false
    private val writeQueue = LinkedBlockingQueue<ByteArray>()
    private val flows = ConcurrentHashMap<String, TcpFlow>()
    private var ipId = Random.nextInt(1, 30000)
    private var lastCleanup = 0L
    @Volatile private var udpDropLogged = false

    private inner class TcpFlow(
        val key: String,
        val clientIp: Int, val clientPort: Int,
        val dstIp: Int, val dstPort: Int,
    ) {
        var clientNextSeq: Long = 0
        var serverSeq: Long = Random.nextInt(1, Int.MAX_VALUE).toLong()
        var channel: ChannelDirectTCPIP? = null
        var out: OutputStream? = null
        @Volatile var closed = false
        @Volatile var clientFin = false
        @Volatile var serverFinSent = false
        var lastActive = System.currentTimeMillis()
        val pending = LinkedBlockingQueue<ByteArray>()
        @Volatile var pendingBytes = 0
        val sendLock = Object()
    }

    fun start() {
        running = true
        thread(name = "tk-tun-writer", isDaemon = true) {
            while (running) {
                try {
                    val pkt = writeQueue.take()
                    synchronized(tunOut) {
                        tunOut.write(pkt)
                        tunOut.flush()
                    }
                } catch (e: Exception) {
                    if (running) log("TUN writer berhenti: ${e.message}")
                    break
                }
            }
        }
        thread(name = "tk-tun-reader", isDaemon = true) { readLoop() }
        log("Mesin TUN aktif (DNS via $dnsServer, UDP selain DNS menyusul v0.2)")
    }

    fun stop() {
        running = false
        flows.values.forEach { closeFlow(it, sendRst = false) }
        flows.clear()
        writeQueue.offer(ByteArray(0))
    }

    private fun readLoop() {
        val buf = ByteArray(32767)
        while (running) {
            val n = try { tunIn.read(buf) } catch (e: Exception) { -1 }
            if (n <= 0) {
                if (running) log("TUN reader selesai")
                break
            }
            try {
                handlePacket(buf.copyOf(n))
            } catch (e: Exception) {
                // Paket rusak tidak boleh mematikan loop.
            }
            val now = System.currentTimeMillis()
            if (now - lastCleanup > 30_000) {
                lastCleanup = now
                flows.values.filter { now - it.lastActive > 240_000 }.forEach {
                    closeFlow(it, sendRst = false); flows.remove(it.key)
                }
            }
        }
    }

    private fun handlePacket(pkt: ByteArray) {
        if (pkt.isEmpty()) return
        val version = (pkt[0].toInt() shr 4) and 0xF
        if (version != 4) return // IPv6: buang (anti-bocor)
        val ihl = (pkt[0].toInt() and 0xF) * 4
        if (pkt.size < ihl + 8) return
        val totalLen = u16(pkt, 2).coerceAtMost(pkt.size)
        val protocol = pkt[9].toInt() and 0xFF
        val srcIp = i32(pkt, 12)
        val dstIp = i32(pkt, 16)
        when (protocol) {
            6 -> handleTcp(pkt, ihl, totalLen, srcIp, dstIp)
            17 -> handleUdp(pkt, ihl, totalLen, srcIp, dstIp)
            else -> Unit // ICMP & lainnya: buang
        }
    }

    // ---------------- TCP ----------------

    private fun handleTcp(pkt: ByteArray, ihl: Int, totalLen: Int, srcIp: Int, dstIp: Int) {
        if (totalLen < ihl + 20) return
        val srcPort = u16(pkt, ihl)
        val dstPort = u16(pkt, ihl + 2)
        val seq = u32(pkt, ihl + 4)
        val ack = u32(pkt, ihl + 8)
        val dataOff = ((pkt[ihl + 12].toInt() shr 4) and 0xF) * 4
        val flags = pkt[ihl + 13].toInt() and 0xFF
        val payloadOff = ihl + dataOff
        val payloadLen = (totalLen - payloadOff).coerceAtLeast(0)
        val key = "$srcIp:$srcPort>$dstIp:$dstPort"

        val syn = flags and 0x02 != 0
        val rst = flags and 0x04 != 0
        val fin = flags and 0x01 != 0
        val ackFlag = flags and 0x10 != 0

        var flow = flows[key]
        if (flow == null) {
            if (!syn) {
                // Paket nyasar untuk aliran tak dikenal: balas RST agar app klien cepat menyerah.
                if (!rst) sendTcpPacket(dstIp, dstPort, srcIp, srcPort, ack, 0, 0x04 /*RST*/, null)
                return
            }
            flow = TcpFlow(key, srcIp, srcPort, dstIp, dstPort)
            flow.clientNextSeq = seq + 1
            flows[key] = flow
            val serverSeq0 = flow.serverSeq
            sendTcpPacket(dstIp, dstPort, srcIp, srcPort, serverSeq0, flow.clientNextSeq, 0x12 /*SYN+ACK*/, null)
            flow.serverSeq = serverSeq0 + 1
            openChannelForFlow(flow)
            return
        }

        synchronized(flow.sendLock) {
            flow.lastActive = System.currentTimeMillis()
            if (rst) {
                closeFlow(flow, sendRst = false)
                flows.remove(key)
                return
            }
            if (payloadLen > 0) {
                if (seq == flow.clientNextSeq) {
                    if (flow.pendingBytes + payloadLen <= 1_048_576) {
                        val data = pkt.copyOfRange(payloadOff, payloadOff + payloadLen)
                        flow.pending.offer(data)
                        flow.pendingBytes += payloadLen
                        flow.clientNextSeq += payloadLen
                        LogBus.addTraffic(0, payloadLen.toLong())
                    }
                    // Bila antrean penuh: segmen dibuang tanpa ACK, klien akan kirim ulang.
                }
                // Segmen tak urut / kirim ulang: cukup ACK posisi terakhir yang diterima utuh.
                sendTcpPacket(dstIp, dstPort, srcIp, srcPort, flow.serverSeq, flow.clientNextSeq, 0x10 /*ACK*/, null)
            }
            if (fin) {
                flow.clientNextSeq += 1
                flow.clientFin = true
                sendTcpPacket(dstIp, dstPort, srcIp, srcPort, flow.serverSeq, flow.clientNextSeq, 0x10, null)
                try { flow.out?.close() } catch (e: Exception) { /* abaikan */ }
            }
            if (ackFlag && flow.serverFinSent && ack >= flow.serverSeq) {
                closeFlow(flow, sendRst = false)
                flows.remove(key)
            }
        }
    }

    private fun openChannelForFlow(flow: TcpFlow) {
        thread(name = "tk-flow-${flow.dstPort}", isDaemon = true) {
            try {
                val channel = ssh.openStream(ipToString(flow.dstIp), flow.dstPort)
                flow.channel = channel
                val out = channel.outputStream
                flow.out = out
                // Tulis antrean data klien yang sudah di-ACK.
                thread(name = "tk-flow-w", isDaemon = true) {
                    try {
                        while (!flow.closed) {
                            val data = flow.pending.take()
                            flow.pendingBytes -= data.size
                            out.write(data)
                            out.flush()
                        }
                    } catch (e: Exception) { /* aliran selesai */ }
                }
                // Baca balasan server -> paket TUN.
                val inp = channel.inputStream
                val rbuf = ByteArray(8192)
                while (!flow.closed) {
                    val n = inp.read(rbuf)
                    if (n < 0) break
                    if (n == 0) continue
                    var off = 0
                    while (off < n) {
                        val chunk = minOf(1380, n - off)
                        val data = rbuf.copyOfRange(off, off + chunk)
                        synchronized(flow.sendLock) {
                            sendTcpPacket(
                                flow.dstIp, flow.dstPort, flow.clientIp, flow.clientPort,
                                flow.serverSeq, flow.clientNextSeq, 0x18 /*PSH+ACK*/, data,
                            )
                            flow.serverSeq += chunk
                        }
                        LogBus.addTraffic(chunk.toLong(), 0)
                        off += chunk
                    }
                    flow.lastActive = System.currentTimeMillis()
                }
            } catch (e: Exception) {
                // Server menolak / SSH putus: RST ke klien.
                synchronized(flow.sendLock) {
                    if (!flow.closed) {
                        sendTcpPacket(flow.dstIp, flow.dstPort, flow.clientIp, flow.clientPort,
                            flow.serverSeq, flow.clientNextSeq, 0x04, null)
                    }
                }
            } finally {
                synchronized(flow.sendLock) {
                    if (!flow.serverFinSent && !flow.closed) {
                        sendTcpPacket(flow.dstIp, flow.dstPort, flow.clientIp, flow.clientPort,
                            flow.serverSeq, flow.clientNextSeq, 0x11 /*FIN+ACK*/, null)
                        flow.serverSeq += 1
                        flow.serverFinSent = true
                    }
                }
                // Beri waktu ACK terakhir sebelum aliran dibersihkan total.
                thread(isDaemon = true) {
                    Thread.sleep(5_000)
                    closeFlow(flow, sendRst = false)
                    flows.remove(flow.key)
                }
            }
        }
    }

    private fun closeFlow(flow: TcpFlow, sendRst: Boolean) {
        flow.closed = true
        try { flow.channel?.disconnect() } catch (e: Exception) { /* abaikan */ }
    }

    private fun sendTcpPacket(
        srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int,
        seq: Long, ack: Long, flags: Int, payload: ByteArray?,
    ) {
        val payloadLen = payload?.size ?: 0
        val total = 20 + 20 + payloadLen
        val pkt = ByteArray(total)
        // IP header
        pkt[0] = 0x45
        put16(pkt, 2, total)
        ipId = (ipId + 1) and 0xFFFF
        put16(pkt, 4, ipId)
        put16(pkt, 6, 0x4000)
        pkt[8] = 64
        pkt[9] = 6
        put32(pkt, 12, srcIp)
        put32(pkt, 16, dstIp)
        put16(pkt, 10, sumWords(pkt, 0, 20, 0).inv() and 0xFFFF)
        // TCP header
        val t = 20
        put16(pkt, t, srcPort)
        put16(pkt, t + 2, dstPort)
        put32(pkt, t + 4, (seq and 0xFFFFFFFFL).toInt())
        put32(pkt, t + 8, (ack and 0xFFFFFFFFL).toInt())
        pkt[t + 12] = (5 shl 4).toByte()
        pkt[t + 13] = flags.toByte()
        put16(pkt, t + 14, 65535)
        if (payload != null) System.arraycopy(payload, 0, pkt, t + 20, payloadLen)
        // TCP checksum dengan pseudo-header
        val pseudo = ByteArray(12)
        put32(pseudo, 0, srcIp); put32(pseudo, 4, dstIp)
        pseudo[8] = 0; pseudo[9] = 6
        put16(pseudo, 10, 20 + payloadLen)
        var sum = sumWords(pseudo, 0, 12, 0)
        sum = sumWords(pkt, t, 20 + payloadLen, sum)
        put16(pkt, t + 16, sum.inv() and 0xFFFF)
        writeQueue.offer(pkt)
    }

    // ---------------- UDP (DNS saja) ----------------

    private fun handleUdp(pkt: ByteArray, ihl: Int, totalLen: Int, srcIp: Int, dstIp: Int) {
        if (totalLen < ihl + 8) return
        val srcPort = u16(pkt, ihl)
        val dstPort = u16(pkt, ihl + 2)
        val udpLen = u16(pkt, ihl + 4)
        val payloadOff = ihl + 8
        val payloadLen = (minOf(totalLen, ihl + udpLen) - payloadOff).coerceAtLeast(0)
        if (dstPort != 53) {
            if (!udpDropLogged) {
                udpDropLogged = true
                log("UDP non-DNS dibuang (v0.1) — UDP penuh menyusul di v0.2")
            }
            return
        }
        val query = pkt.copyOfRange(payloadOff, payloadOff + payloadLen)
        LogBus.addTraffic(0, payloadLen.toLong())
        thread(name = "tk-dns", isDaemon = true) {
            try {
                val channel = ssh.openStream(dnsServer, 53)
                val out = channel.outputStream
                val inp = channel.inputStream
                val framed = ByteArray(2 + query.size)
                framed[0] = (query.size shr 8).toByte()
                framed[1] = (query.size and 0xFF).toByte()
                System.arraycopy(query, 0, framed, 2, query.size)
                out.write(framed); out.flush()
                val lenBuf = ByteArray(2)
                readFully(inp, lenBuf)
                val rlen = u16(lenBuf, 0)
                val resp = ByteArray(rlen)
                readFully(inp, resp)
                channel.disconnect()
                sendUdpPacket(dstIp, 53, srcIp, srcPort, resp)
                LogBus.addTraffic(rlen.toLong(), 0)
            } catch (e: Exception) {
                // DNS gagal: diam, klien akan mencoba lagi / fallback.
            }
        }
    }

    private fun sendUdpPacket(srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int, payload: ByteArray) {
        val total = 20 + 8 + payload.size
        val pkt = ByteArray(total)
        pkt[0] = 0x45
        put16(pkt, 2, total)
        ipId = (ipId + 1) and 0xFFFF
        put16(pkt, 4, ipId)
        put16(pkt, 6, 0x4000)
        pkt[8] = 64
        pkt[9] = 17
        put32(pkt, 12, srcIp)
        put32(pkt, 16, dstIp)
        put16(pkt, 10, sumWords(pkt, 0, 20, 0).inv() and 0xFFFF)
        val u = 20
        put16(pkt, u, srcPort)
        put16(pkt, u + 2, dstPort)
        put16(pkt, u + 4, 8 + payload.size)
        System.arraycopy(payload, 0, pkt, u + 8, payload.size)
        val pseudo = ByteArray(12)
        put32(pseudo, 0, srcIp); put32(pseudo, 4, dstIp)
        pseudo[8] = 0; pseudo[9] = 17
        put16(pseudo, 10, 8 + payload.size)
        var sum = sumWords(pseudo, 0, 12, 0)
        sum = sumWords(pkt, u, 8 + payload.size, sum)
        val udpChecksum = sum.inv() and 0xFFFF
        put16(pkt, u + 6, if (udpChecksum == 0) 0xFFFF else udpChecksum)
        writeQueue.offer(pkt)
    }

    // ---------------- util ----------------

    private fun readFully(inp: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = inp.read(buf, off, buf.size - off)
            if (n < 0) throw IllegalStateException("EOF")
            off += n
        }
    }

    private fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    private fun u32(b: ByteArray, off: Int): Long =
        ((b[off].toLong() and 0xFF) shl 24) or ((b[off + 1].toLong() and 0xFF) shl 16) or
            ((b[off + 2].toLong() and 0xFF) shl 8) or (b[off + 3].toLong() and 0xFF)

    private fun i32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    private fun put16(b: ByteArray, off: Int, v: Int) {
        b[off] = (v shr 8).toByte(); b[off + 1] = (v and 0xFF).toByte()
    }

    private fun put32(b: ByteArray, off: Int, v: Int) {
        b[off] = (v shr 24).toByte(); b[off + 1] = (v shr 16).toByte()
        b[off + 2] = (v shr 8).toByte(); b[off + 3] = (v and 0xFF).toByte()
    }

    /** Jumlah kata 16-bit (one's complement sum, BELUM dikomplemenkan). */
    private fun sumWords(b: ByteArray, off: Int, len: Int, initial: Int): Int {
        var sum = initial
        var i = off
        val end = off + len
        while (i + 1 < end) {
            sum += ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (b[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum
    }

    private fun ipToString(ip: Int): String =
        "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 8) and 0xFF}.${ip and 0xFF}"
}
