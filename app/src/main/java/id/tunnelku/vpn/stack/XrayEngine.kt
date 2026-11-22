package id.tunnelku.vpn.stack

import id.tunnelku.model.SshProfile
import id.tunnelku.xray.SsProto
import id.tunnelku.xray.TrojanProto
import id.tunnelku.xray.VlessProto
import id.tunnelku.xray.VmessProto
import id.tunnelku.xray.XrayDialer
import id.tunnelku.xray.XrayProto
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.DatagramSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.random.Random

/**
 * Adapter Xray (klien protokol Kotlin) ke kontrak [OutboundEngine] — port `da`
 * XVEON: stream langsung per aliran (tanpa server SOCKS lokal), sesi UDP native
 * per tujuan (Trojan berbagi asosiasi), "XrayDNS" = satu pertukaran DNS di
 * dalam UDP protokol (2500 ms, balasan pertama menang), dan gerbang verifikasi
 * sesi (probe DNS + HTTP) sebelum TUN dinyatakan terhubung.
 */
class XrayEngine(
    private val profile: SshProfile,
    protectSocket: (Socket) -> Boolean,
    protectDatagram: (DatagramSocket) -> Boolean,
    private val log: (String) -> Unit,
) : OutboundEngine {

    private val dialer = XrayDialer(profile, protectSocket, protectDatagram, log)

    @Volatile private var closing = false
    @Volatile var verified: Boolean = false
        private set
    @Volatile private var vmessLegacy = false

    private fun newProto(): XrayProto = when (profile.xrayProtocol) {
        "vless" -> VlessProto(profile, dialer)
        "vmess" -> VmessProto(profile, dialer, legacy = vmessLegacy)
        "trojan" -> TrojanProto(profile, dialer)
        "ss" -> SsProto(profile, dialer)
        else -> throw IllegalStateException("Protokol Xray tidak dikenal: ${profile.xrayProtocol}")
    }

    override fun isConnected(): Boolean = !closing && verified

    override fun openTcp(host: String, port: Int, orgIp: String, orgPort: Int, timeoutMs: Int): TcpHandle {
        dialer.nextReadTimeoutMs = if (timeoutMs in 1..10000) timeoutMs else 0
        val stream = newProto().openTcp(host, port)
        return object : TcpHandle {
            override val input = stream.input
            override val output = stream.output
            override fun isConnected(): Boolean = !closing
            override fun setTimeout(ms: Int) { /* timeout diatur lewat dialer sebelum dial */ }
            override fun close() = stream.close()
        }
    }

    override fun openUdpSession(dstIp: String, dstPort: Int, timeoutMs: Int): UdpHandle {
        val receiverRef = AtomicReference<((Int, Int, ByteArray, Int, Int) -> Unit)?>(null)
        val session = newProto().openUdp(dstIp, dstPort) { srcHost, srcPort, payload ->
            val cb = receiverRef.get() ?: return@openUdp
            val srcIpInt = try {
                Packets.ipToInt(srcHost)
            } catch (e: Exception) {
                0
            }
            cb(srcIpInt, srcPort, payload, 0, payload.size)
        }
        return object : UdpHandle {
            override fun isAlive(): Boolean = !closing
            override fun startReceiver(onPacket: (Int, Int, ByteArray, Int, Int) -> Unit) {
                receiverRef.set(onPacket)
            }

            override fun send(data: ByteArray, off: Int, len: Int) {
                session.send(if (off == 0 && len == data.size) data else data.copyOfRange(off, off + len))
            }

            override fun flush() { /* protokol mengirim langsung */ }
            override fun setTimeout(ms: Int) { /* tidak berlaku untuk sesi protokol */ }
            override fun close() = session.close()
        }
    }

    /** XrayDNS ala `da.O()`: satu pertukaran DNS mentah di dalam UDP protokol. */
    override fun exchangeDns(host: String, payload: ByteArray): ByteArray? {
        var handle: UdpHandle? = null
        return try {
            val latch = CountDownLatch(1)
            val result = AtomicReference<ByteArray?>(null)
            handle = openUdpSession(host, 53, 2500)
            handle.startReceiver { _, _, data, off, len ->
                if (result.compareAndSet(null, data.copyOfRange(off, off + len))) {
                    latch.countDown()
                }
            }
            handle.send(payload, 0, payload.size)
            handle.flush()
            if (latch.await(2500, TimeUnit.MILLISECONDS)) result.get() else null
        } catch (e: Exception) {
            null
        } finally {
            try { handle?.close() } catch (e: Exception) { /* abaikan */ }
        }
    }

    override fun nativeUdpAvailable(): Boolean = when (profile.xrayProtocol) {
        "vless", "vmess", "trojan" -> true
        // SS: UDP selalu lewat DatagramSocket langsung di klien ini (lebih longgar
        // dari gerbang `da`, yang membatasi SS-UDP pada transport TCP polos).
        "ss" -> true
        else -> false
    }

    override fun udpForwardingEnabled(): Boolean = false

    override fun openUdpGw(): TcpHandle? = null

    override fun sharesUdpAssociation(): Boolean = profile.xrayProtocol == "trojan"

    override fun close() {
        closing = true
        verified = false
    }

    // ================= Verifikasi sesi (port `da.l1I()`) =================

    /**
     * Probe round-trip sebelum sesi dinyatakan hidup:
     * DNS one.one.one.one via 1.1.1.1 → HEAD /generate_204 → DNS via 8.8.8.8.
     * VMess alterId > 0: coba AEAD dulu, gagal → flip ke legacy dan ulangi.
     */
    fun verify() {
        val attempts: List<Boolean> =
            if (profile.xrayProtocol == "vmess" && profile.xrayAlterId > 0) {
                listOf(false, true)
            } else {
                listOf(vmessLegacy)
            }
        var lastErr: Exception? = null
        for (legacyTry in attempts) {
            vmessLegacy = legacyTry
            try {
                probeDns("1.1.1.1")
                probeHttp()
                probeDns("8.8.8.8")
                verified = true
                if (legacyTry && profile.xrayProtocol == "vmess") {
                    log("VMess terverifikasi dalam mode LEGACY (alterId ${profile.xrayAlterId})")
                }
                log("Verifikasi sesi Xray lolos (DNS + HTTP round-trip)")
                return
            } catch (e: Exception) {
                lastErr = e
                log("Probe verifikasi gagal${if (attempts.size > 1) " (mode ${if (legacyTry) "legacy" else "AEAD"})" else ""}: ${e.message}")
            }
        }
        verified = false
        val msg = lastErr?.message ?: "tidak diketahui"
        val credential = msg.contains("verifikasi", ignoreCase = true) ||
            msg.contains("Auth", ignoreCase = true) || msg.contains("versi respons", ignoreCase = true)
        throw IllegalStateException(
            if (credential) {
                "Kredensial ditolak server — probe protokol gagal verifikasi ($msg)"
            } else {
                "Server tidak menjawab probe verifikasi — timeout/upstream ($msg)"
            },
        )
    }

    private fun buildDnsQuery(id: Int, name: String): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(
            byteArrayOf(
                (id shr 8).toByte(), id.toByte(),
                0x01, 0x00, // RD=1
                0x00, 0x01, // QDCOUNT=1
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ),
        )
        for (label in name.split('.')) {
            val lb = label.toByteArray(Charsets.US_ASCII)
            out.write(lb.size)
            out.write(lb)
        }
        out.write(0)
        out.write(byteArrayOf(0x00, 0x01, 0x00, 0x01)) // A / IN
        return out.toByteArray()
    }

    private fun probeDns(server: String) {
        val id = Random.nextInt(65536)
        val resp = exchangeDns(server, buildDnsQuery(id, "one.one.one.one"))
            ?: throw IOException("DNS ke $server tidak dijawab dalam 2500 ms")
        if (resp.size < 12 || resp.size > 4096) {
            throw IOException("DNS ke $server: ukuran respons janggal (${resp.size} byte)")
        }
        val rid = ((resp[0].toInt() and 0xFF) shl 8) or (resp[1].toInt() and 0xFF)
        if (rid != id) throw IOException("DNS ke $server: ID respons tidak cocok")
        if (resp[2].toInt() and 0x80 == 0) throw IOException("DNS ke $server: QR bit tidak terpasang")
    }

    private fun probeHttp() {
        var lastErr: Exception? = null
        for (host in listOf("cp.cloudflare.com", "connectivitycheck.gstatic.com")) {
            var handle: TcpHandle? = null
            try {
                handle = openTcp(host, 80, "127.0.0.1", 0, 10000)
                val req = "HEAD /generate_204 HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n"
                handle.output.write(req.toByteArray(Charsets.US_ASCII))
                handle.output.flush()
                val head = readHeadWithTimeout(handle, 10000)
                if (head.startsWith("HTTP")) {
                    log("Probe HTTP $host OK (${head.lineSequence().firstOrNull() ?: ""})")
                    return
                }
                throw IOException("respons bukan HTTP: ${head.take(40)}")
            } catch (e: Exception) {
                lastErr = e
                log("Probe HTTP $host gagal: ${e.message}")
            } finally {
                try { handle?.close() } catch (e: Exception) { /* abaikan */ }
            }
        }
        throw IOException("semua target probe HTTP gagal (${lastErr?.message})")
    }

    /** Baca head HTTP dengan batas waktu (stream protokol tidak punya read timeout). */
    private fun readHeadWithTimeout(handle: TcpHandle, timeoutMs: Long): String {
        val latch = CountDownLatch(1)
        val result = AtomicReference("")
        val failure = AtomicReference<Exception?>(null)
        val t = thread(name = "tk-probe-http", isDaemon = true) {
            try {
                val sb = StringBuilder()
                var state = 0
                var count = 0
                while (count < 4096) {
                    val b = handle.input.read()
                    if (b < 0) break
                    count++
                    sb.append(b.toChar())
                    state = when {
                        state == 0 && b == '\r'.code -> 1
                        state == 1 && b == '\n'.code -> 2
                        state == 2 && b == '\r'.code -> 3
                        state == 3 && b == '\n'.code -> 4
                        b == '\r'.code -> 1
                        else -> 0
                    }
                    if (state == 4) break
                }
                result.set(sb.toString())
            } catch (e: Exception) {
                failure.set(e)
            } finally {
                latch.countDown()
            }
        }
        if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
            try { handle.close() } catch (e: Exception) { /* abaikan */ }
            throw IOException("timeout ${timeoutMs} ms menunggu respons HTTP")
        }
        failure.get()?.let { throw it }
        return result.get()
    }
}
