import id.tunnelku.vpn.stack.OutboundEngine
import id.tunnelku.vpn.stack.Packets
import id.tunnelku.vpn.stack.TcpHandle
import id.tunnelku.vpn.stack.TunStack
import id.tunnelku.vpn.stack.UdpHandle
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

// ===== Uji TunStack: TUN pipa semu + engine echo palsu =====
var sFailures = 0
fun sCheck(name: String, cond: Boolean, detail: String = "") {
    if (cond) println("PASS $name") else { println("FAIL $name $detail"); sFailures++ }
}

class EchoHandle : TcpHandle {
    private val clientIn = PipedInputStream(1 shl 20)
    private val serverOut = PipedOutputStream(clientIn)
    private val serverIn = PipedInputStream(1 shl 20)
    private val clientOut = PipedOutputStream(serverIn)
    @Volatile private var serverAlive = true

    init {
        thread(name = "fake-echo", isDaemon = true) {
            val buf = ByteArray(8192)
            try {
                while (serverAlive) {
                    val n = serverIn.read(buf)
                    if (n <= 0) break
                    serverOut.write(buf, 0, n)
                    serverOut.flush()
                }
            } catch (e: Exception) { /* server ditutup */ }
        }
    }

    override val input: InputStream = clientIn
    override val output: OutputStream = clientOut
    override fun isConnected(): Boolean = serverAlive
    override fun setTimeout(ms: Int) {}
    override fun close() {
        serverAlive = false
        try { clientOut.close() } catch (e: Exception) {}
        try { serverOut.close() } catch (e: Exception) {}
    }

    /** Simulasikan server menutup koneksi (EOF untuk stack). */
    fun serverClose() {
        serverAlive = false
        try { serverOut.close() } catch (e: Exception) {}
        try { clientOut.close() } catch (e: Exception) {}
    }
}

/** Handle DNS-over-TCP palsu: membaca frame [len][query], menjawab [len][respons]. */
class DotHandle(private val responder: (ByteArray) -> ByteArray) : TcpHandle {
    private val replyQueue = LinkedBlockingQueue<ByteArray>()
    @Volatile private var current: ByteArray? = null
    private var pos = 0
    private val collect = ByteArrayOutputStream()

    override val output: OutputStream = object : OutputStream() {
        override fun write(b: Int) { collect.write(b); maybeRespond() }
        override fun write(b: ByteArray, off: Int, len: Int) { collect.write(b, off, len); maybeRespond() }
        override fun flush() { maybeRespond() }
    }

    private fun maybeRespond() {
        val data = collect.toByteArray()
        if (data.size < 2) return
        val len = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
        if (data.size < 2 + len) return
        val query = data.copyOfRange(2, 2 + len)
        collect.reset()
        val resp = responder(query)
        val frame = ByteArray(2 + resp.size)
        frame[0] = (resp.size shr 8).toByte(); frame[1] = (resp.size and 0xFF).toByte()
        System.arraycopy(resp, 0, frame, 2, resp.size)
        replyQueue.offer(frame)
    }

    override val input: InputStream = object : InputStream() {
        override fun read(): Int {
            val b = ByteArray(1)
            val n = read(b, 0, 1)
            return if (n < 0) -1 else b[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            while (true) {
                val cur = current
                if (cur != null && pos < cur.size) {
                    val take = minOf(len, cur.size - pos)
                    System.arraycopy(cur, pos, b, off, take)
                    pos += take
                    return take
                }
                current = replyQueue.poll(5, TimeUnit.SECONDS) ?: return -1
                pos = 0
            }
        }
    }

    override fun isConnected(): Boolean = true
    override fun setTimeout(ms: Int) {}
    override fun close() {}
}

class FakeEngine : OutboundEngine {
    val tcpOpens = CopyOnWriteArrayList<Pair<String, Int>>()
    @Volatile var lastEcho: EchoHandle? = null
    @Volatile var dotResponder: (ByteArray) -> ByteArray = { q -> q }

    override fun isConnected(): Boolean = true
    override fun openTcp(host: String, port: Int, orgIp: String, orgPort: Int, timeoutMs: Int): TcpHandle {
        tcpOpens.add(host to port)
        if (port == 53) return DotHandle(dotResponder)
        val h = EchoHandle()
        lastEcho = h
        return h
    }

    override fun openUdpSession(dstIp: String, dstPort: Int, timeoutMs: Int): UdpHandle =
        throw UnsupportedOperationException("tidak dipakai di uji stack")

    override fun exchangeDns(host: String, payload: ByteArray): ByteArray? = null
    override fun nativeUdpAvailable(): Boolean = false
    override fun udpForwardingEnabled(): Boolean = false
    override fun openUdpGw(): TcpHandle? = null
    override fun close() {}
}

/** Pengumpul paket dari sisi TUN keluar: membingkai ulang berdasarkan total length IP. */
class PacketCollector(inp: InputStream) {
    val queue = LinkedBlockingQueue<ByteArray>()

    init {
        thread(name = "tun-collector", isDaemon = true) {
            val buf = ByteArrayOutputStream()
            val chunk = ByteArray(8192)
            try {
                while (true) {
                    val n = inp.read(chunk)
                    if (n <= 0) break
                    buf.write(chunk, 0, n)
                    while (true) {
                        val data = buf.toByteArray()
                        if (data.size < 20) break
                        val total = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
                        if (total <= 0 || data.size < total) break
                        queue.offer(data.copyOfRange(0, total))
                        val rest = data.copyOfRange(total, data.size)
                        buf.reset()
                        buf.write(rest)
                    }
                }
            } catch (e: Exception) { /* selesai */ }
        }
    }

    fun next(timeoutMs: Long = 5000): ByteArray? = queue.poll(timeoutMs, TimeUnit.MILLISECONDS)
}

fun tcpFlags(pkt: ByteArray): Int = pkt[20 + 13].toInt() and 0xFF
fun tcpSeq(pkt: ByteArray): Long = Packets.u32(pkt, 20 + 4)
fun tcpAck(pkt: ByteArray): Long = Packets.u32(pkt, 20 + 8)
fun tcpPayload(pkt: ByteArray): ByteArray {
    val dataOff = ((pkt[20 + 12].toInt() shr 4) and 0x0F) * 4
    return pkt.copyOfRange(20 + dataOff, pkt.size)
}

fun dnsQuery(id: Int, name: String): ByteArray {
    val out = ByteArrayOutputStream()
    out.write(byteArrayOf((id shr 8).toByte(), id.toByte(), 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
    for (label in name.split('.')) {
        out.write(label.length)
        out.write(label.toByteArray(Charsets.US_ASCII))
    }
    out.write(0)
    out.write(byteArrayOf(0, 1, 0, 1))
    return out.toByteArray()
}

fun dnsResponse(query: ByteArray): ByteArray {
    val out = ByteArrayOutputStream()
    out.write(query.copyOfRange(0, 2)) // ID sama
    out.write(byteArrayOf(0x81.toByte(), 0x80.toByte())) // QR+RD / RA, RCODE 0
    out.write(byteArrayOf(0, 1, 0, 1, 0, 0, 0, 0)) // QD=1 AN=1
    out.write(query.copyOfRange(12, query.size)) // question
    out.write(byteArrayOf(0xC0.toByte(), 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4)) // answer A 1.2.3.4
    return out.toByteArray()
}

fun main() {
    val clientIp = Packets.ipToInt("10.11.12.2")
    val serverIp = Packets.ipToInt("93.184.216.34")
    val dnsIp = Packets.ipToInt("1.1.1.1")

    val tunStackIn = PipedInputStream(1 shl 20)
    val testToStack = PipedOutputStream(tunStackIn)
    val stackToTest = PipedOutputStream()
    val tunStackOutIn = PipedInputStream(stackToTest, 1 shl 20)
    val collector = PacketCollector(tunStackOutIn)

    val engine = FakeEngine()
    engine.dotResponder = { q -> dnsResponse(q) }

    val stack = TunStack(
        tunIn = tunStackIn,
        tunOut = stackToTest,
        engine = engine,
        mtu = 1400,
        log = { println("  [stack] $it") },
        onEngineLost = { println("  [stack] engine lost: $it") },
    )
    stack.start()
    Thread.sleep(200)

    // 1) SYN → openTcp tercatat + SYN-ACK (ack=1001, MSS 1260)
    testToStack.write(Packets.tcp(clientIp, 40000, serverIp, 80, 1000, 0, Packets.FLAG_SYN))
    testToStack.flush()
    val synAck = collector.next()
    sCheck("syn-terima-synack", synAck != null)
    if (synAck != null) {
        sCheck("synack-flags", tcpFlags(synAck) == 0x12, "flags=${tcpFlags(synAck)}")
        sCheck("synack-ack", tcpAck(synAck) == 1001L, "ack=${tcpAck(synAck)}")
        val dataOff = ((synAck[20 + 12].toInt() shr 4) and 0x0F) * 4
        sCheck("synack-hdrlen-24", dataOff == 24, "dataOff=$dataOff")
        val mss = if (dataOff == 24) ((synAck[20 + 22].toInt() and 0xFF) shl 8) or (synAck[20 + 23].toInt() and 0xFF) else -1
        sCheck("synack-mss-1260", mss == 1260, "mss=$mss")
    }
    sCheck("syn-opentcp", engine.tcpOpens.any { it == "93.184.216.34" to 80 }, "${engine.tcpOpens}")
    val serverSeq = if (synAck != null) tcpSeq(synAck) else 0L

    // 2) SYN duplikat → SYN-ACK dikirim ulang dengan seq server yang sama
    testToStack.write(Packets.tcp(clientIp, 40000, serverIp, 80, 1000, 0, Packets.FLAG_SYN))
    testToStack.flush()
    val synAck2 = collector.next()
    sCheck("syn-duplikat-resend", synAck2 != null && tcpFlags(synAck2) == 0x12 && tcpSeq(synAck2) == serverSeq,
        "pkt=${synAck2?.let { "flags=${tcpFlags(it)} seq=${tcpSeq(it)}" }}")

    // 3) Data klien → echo kembali sebagai PSH+ACK
    val data = "PING-DATA".toByteArray()
    testToStack.write(Packets.tcp(clientIp, 40000, serverIp, 80, 1001, (serverSeq + 1) and 0xFFFFFFFFL, Packets.FLAG_PSH or Packets.FLAG_ACK, data))
    testToStack.flush()
    var echoPkt: ByteArray? = null
    var ackPkt: ByteArray? = null
    val deadline = System.currentTimeMillis() + 5000
    while (System.currentTimeMillis() < deadline && (echoPkt == null || ackPkt == null)) {
        val p = collector.next(1000) ?: continue
        val pl = tcpPayload(p)
        if (pl.contentEquals(data)) echoPkt = p else if (pl.isEmpty()) ackPkt = p
    }
    sCheck("echo-payload", echoPkt != null, "echo tidak kembali")
    if (echoPkt != null) {
        sCheck("echo-seq", tcpSeq(echoPkt) == (serverSeq + 1) and 0xFFFFFFFFL, "seq=${tcpSeq(echoPkt)}")
        sCheck("echo-ack", tcpAck(echoPkt) == 1001L + data.size, "ack=${tcpAck(echoPkt)}")
    }
    sCheck("ack-murni", ackPkt != null && tcpFlags(ackPkt) == Packets.FLAG_ACK, "ack=${ackPkt?.let { tcpFlags(it) }}")

    // 4) Server EOF → FIN+ACK; FIN klien → sesi tutup; data yatim → RST+ACK
    engine.lastEcho?.serverClose()
    val finPkt = collector.next()
    sCheck("server-fin", finPkt != null && tcpFlags(finPkt) == (Packets.FLAG_FIN or Packets.FLAG_ACK),
        "pkt=${finPkt?.let { tcpFlags(it) }}")
    val clientSeqAfterData = 1001L + data.size
    testToStack.write(Packets.tcp(clientIp, 40000, serverIp, 80, clientSeqAfterData, 0, Packets.FLAG_FIN or Packets.FLAG_ACK))
    testToStack.flush()
    Thread.sleep(300)
    testToStack.write(Packets.tcp(clientIp, 40000, serverIp, 80, clientSeqAfterData + 1, 12345, Packets.FLAG_PSH or Packets.FLAG_ACK, "X".toByteArray()))
    testToStack.flush()
    var rstPkt: ByteArray? = null
    val dl2 = System.currentTimeMillis() + 4000
    while (System.currentTimeMillis() < dl2 && rstPkt == null) {
        val p = collector.next(500) ?: continue
        if (tcpFlags(p) == (Packets.FLAG_RST or Packets.FLAG_ACK)) rstPkt = p
    }
    sCheck("yatim-rst", rstPkt != null)
    if (rstPkt != null) {
        sCheck("yatim-rst-seq", tcpSeq(rstPkt) == 12345L, "seq=${tcpSeq(rstPkt)}")
        sCheck("yatim-rst-ack", tcpAck(rstPkt) == clientSeqAfterData + 2, "ack=${tcpAck(rstPkt)}")
    }

    // 5) DNS: query pertama lewat DoT, query sama (ID beda) dari cache
    val opensBefore = engine.tcpOpens.count { it.second == 53 }
    val q1 = dnsQuery(0x1111, "a.com")
    testToStack.write(Packets.udp(clientIp, 50053, dnsIp, 53, q1))
    testToStack.flush()
    val dnsReply = collector.next()
    sCheck("dns-balasan", dnsReply != null)
    if (dnsReply != null) {
        val udpPayloadOff = 20 + 8
        val rid = ((dnsReply[udpPayloadOff].toInt() and 0xFF) shl 8) or (dnsReply[udpPayloadOff + 1].toInt() and 0xFF)
        sCheck("dns-id", rid == 0x1111, "id=$rid")
        val ancount = ((dnsReply[udpPayloadOff + 6].toInt() and 0xFF) shl 8) or (dnsReply[udpPayloadOff + 7].toInt() and 0xFF)
        sCheck("dns-ancount", ancount == 1, "ancount=$ancount")
    }
    val q2 = dnsQuery(0x2222, "a.com")
    testToStack.write(Packets.udp(clientIp, 50054, dnsIp, 53, q2))
    testToStack.flush()
    val dnsReply2 = collector.next()
    sCheck("dns-cache-balasan", dnsReply2 != null)
    if (dnsReply2 != null) {
        val udpPayloadOff = 20 + 8
        val rid2 = ((dnsReply2[udpPayloadOff].toInt() and 0xFF) shl 8) or (dnsReply2[udpPayloadOff + 1].toInt() and 0xFF)
        sCheck("dns-cache-id-dipatch", rid2 == 0x2222, "id=$rid2")
    }
    val opensAfter = engine.tcpOpens.count { it.second == 53 }
    sCheck("dns-cache-tanpa-dot-baru", opensAfter - opensBefore == 1, "opens 53: $opensBefore->$opensAfter")

    stack.stop()
    println(if (sFailures == 0) "STACK-ALL-DONE" else "STACK-FAILURES=$sFailures")
    if (sFailures > 0) kotlin.system.exitProcess(1)
}
