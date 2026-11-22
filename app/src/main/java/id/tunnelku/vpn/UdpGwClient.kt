package id.tunnelku.vpn

import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

/**
 * Klien BadVPN UDPGW (protokol dari sumber badvpn: protocol/udpgw_proto.h).
 *
 * Satu koneksi TCP (di dalam SSH, ke udpgw di sisi server, default 127.0.0.1:7300)
 * membawa semua aliran UDP dari TUN, dibingkai PacketProto:
 *   [len u16 LE][flags u8][conid u16 LE][ip tujuan 4 byte][port tujuan u16 BE][payload]
 * Balasan server memakai bingkai yang sama; alamat di dalamnya = sumber balasan.
 * flags: KEEPALIVE=1, REBIND=2, DNS=4, IPV6=8. Server memutus klien yang diam
 * 20 detik, jadi keepalive dikirim tiap 10 detik.
 */
class UdpGwClient(
    private val out: OutputStream,
    private val inp: InputStream,
    private val onPacket: (srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int, payload: ByteArray) -> Unit,
    private val onDead: (String) -> Unit,
    private val log: (String) -> Unit,
) {
    @Volatile var alive = true
        private set

    private data class Flow(val clientIp: Int, val clientPort: Int, val dstIp: Int, val dstPort: Int)

    private val flowsByKey = ConcurrentHashMap<String, Int>()
    private val flowsByConid = ConcurrentHashMap<Int, Flow>()
    private var nextConid = 1
    private val writeLock = Object()

    fun start() {
        thread(name = "tk-udpgw-r", isDaemon = true) { readLoop() }
        thread(name = "tk-udpgw-ka", isDaemon = true) {
            while (alive) {
                Thread.sleep(10_000)
                if (!alive) break
                try {
                    sendFrame(FLAG_KEEPALIVE, 0, null)
                } catch (e: Exception) {
                    die("keepalive gagal: ${e.message}")
                    break
                }
            }
        }
        log("UDPGW tersambung — UDP penuh aktif")
    }

    /** Kirim satu datagram UDP dari klien TUN (clientIp:clientPort) ke (dstIp:dstPort). */
    fun send(clientIp: Int, clientPort: Int, dstIp: Int, dstPort: Int, payload: ByteArray, isDns: Boolean) {
        if (!alive) return
        val key = "$clientIp:$clientPort>$dstIp:$dstPort"
        var conid = flowsByKey[key]
        var flags = if (isDns) FLAG_DNS else 0
        if (conid == null) {
            synchronized(writeLock) {
                conid = flowsByKey[key]
                if (conid == null) {
                    conid = nextConid
                    nextConid = if (nextConid >= 65535) 1 else nextConid + 1
                    flowsByKey[key] = conid!!
                    flowsByConid[conid!!] = Flow(clientIp, clientPort, dstIp, dstPort)
                    flags = flags or FLAG_REBIND
                }
            }
        }
        val frame = ByteArray(3 + 6 + payload.size)
        frame[0] = flags.toByte()
        frame[1] = (conid!! and 0xFF).toByte()
        frame[2] = ((conid!! shr 8) and 0xFF).toByte()
        frame[3] = (dstIp shr 24).toByte()
        frame[4] = (dstIp shr 16).toByte()
        frame[5] = (dstIp shr 8).toByte()
        frame[6] = dstIp.toByte()
        frame[7] = (dstPort shr 8).toByte()
        frame[8] = (dstPort and 0xFF).toByte()
        System.arraycopy(payload, 0, frame, 9, payload.size)
        try {
            sendFrameRaw(frame)
        } catch (e: Exception) {
            die("tulis UDPGW gagal: ${e.message}")
        }
    }

    private fun sendFrame(flags: Int, conid: Int, payload: ByteArray?) {
        val body = ByteArray(3 + (payload?.size ?: 0))
        body[0] = flags.toByte()
        body[1] = (conid and 0xFF).toByte()
        body[2] = ((conid shr 8) and 0xFF).toByte()
        if (payload != null) System.arraycopy(payload, 0, body, 3, payload.size)
        sendFrameRaw(body)
    }

    private fun sendFrameRaw(body: ByteArray) {
        synchronized(writeLock) {
            val len = body.size
            out.write(len and 0xFF)
            out.write((len shr 8) and 0xFF)
            out.write(body)
            out.flush()
        }
    }

    private fun readLoop() {
        val lenBuf = ByteArray(2)
        try {
            while (alive) {
                readFully(inp, lenBuf)
                val len = (lenBuf[0].toInt() and 0xFF) or ((lenBuf[1].toInt() and 0xFF) shl 8)
                if (len < 3) continue
                val body = ByteArray(len)
                readFully(inp, body)
                val flags = body[0].toInt() and 0xFF
                if (flags and FLAG_KEEPALIVE != 0) continue
                val conid = (body[1].toInt() and 0xFF) or ((body[2].toInt() and 0xFF) shl 8)
                val flow = flowsByConid[conid] ?: continue
                if (flags and FLAG_IPV6 != 0) continue // balasan IPv6 belum didukung
                if (len < 9) continue
                val srcIp = ((body[3].toInt() and 0xFF) shl 24) or ((body[4].toInt() and 0xFF) shl 16) or
                    ((body[5].toInt() and 0xFF) shl 8) or (body[6].toInt() and 0xFF)
                val srcPort = ((body[7].toInt() and 0xFF) shl 8) or (body[8].toInt() and 0xFF)
                val payload = body.copyOfRange(9, len)
                onPacket(srcIp, srcPort, flow.clientIp, flow.clientPort, payload)
            }
        } catch (e: Exception) {
            if (alive) die("baca UDPGW gagal: ${e.message}")
        }
    }

    private fun die(reason: String) {
        if (!alive) return
        alive = false
        try { inp.close() } catch (e: Exception) { /* abaikan */ }
        try { out.close() } catch (e: Exception) { /* abaikan */ }
        onDead(reason)
    }

    fun close() {
        alive = false
        try { inp.close() } catch (e: Exception) { /* abaikan */ }
        try { out.close() } catch (e: Exception) { /* abaikan */ }
    }

    private fun readFully(inp: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = inp.read(buf, off, buf.size - off)
            if (n < 0) throw IllegalStateException("EOF")
            off += n
        }
    }

    companion object {
        const val FLAG_KEEPALIVE = 1
        const val FLAG_REBIND = 2
        const val FLAG_DNS = 4
        const val FLAG_IPV6 = 8
    }
}
