package id.tunnelku.xray

import id.tunnelku.model.SshProfile
import id.tunnelku.vpn.DuplexStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class SocketStream(val socket: Socket) : DuplexStream {
    override val input: InputStream get() = socket.getInputStream()
    override val output: OutputStream get() = socket.getOutputStream()
    override fun close() {
        try { socket.close() } catch (e: Exception) { /* abaikan */ }
    }
}

/**
 * Pembuka koneksi ke server Xray: socket polos (di-protect VPN) → TLS (bila
 * security=tls) → WebSocket (bila network=ws). REALITY & gRPC ditolak dengan
 * pesan jelas — klien Kotlin tidak mendukung keduanya.
 */
open class XrayDialer(
    private val profile: SshProfile,
    private val protectSocket: (Socket) -> Boolean,
    private val protectDatagram: (DatagramSocket) -> Boolean,
    private val log: (String) -> Unit,
) {
    open fun dialServer(): DuplexStream {
        if (profile.xrayNetwork == "grpc") {
            throw IllegalStateException("Transport gRPC belum didukung klien Kotlin — pakai TCP/WS")
        }
        if (profile.xraySecurity == "reality") {
            throw IllegalStateException("REALITY belum didukung klien Kotlin — pakai TLS")
        }
        val socket = Socket()
        protectSocket(socket)
        socket.tcpNoDelay = true
        socket.soTimeout = 30_000
        socket.connect(InetSocketAddress(profile.host, profile.port), 15_000)
        var stream: DuplexStream = SocketStream(socket)
        if (profile.xraySecurity == "tls") {
            stream = wrapTls(stream, socket)
        }
        if (profile.xrayNetwork == "ws") {
            val sniHost = profile.xrayWsHost.ifBlank { profile.xraySni.ifBlank { profile.host } }
            stream = WsClientStream(stream, sniHost, profile.xrayWsPath.ifBlank { "/" })
        }
        socket.soTimeout = 0
        return stream
    }

    /** Socket UDP langsung ke server (untuk UDP Shadowsocks). */
    open fun dialUdpSocket(): DatagramSocket {
        val s = DatagramSocket()
        protectDatagram(s)
        s.connect(InetSocketAddress(profile.host, profile.port))
        return s
    }

    private fun wrapTls(base: DuplexStream, raw: Socket): DuplexStream {
        val sni = profile.xraySni.ifBlank { profile.host }
        val factory = if (profile.xrayInsecure) {
            val tm = arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            })
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, tm, SecureRandom())
            ctx.socketFactory
        } else {
            SSLContext.getDefault().socketFactory
        }
        val ssl = factory.createSocket(raw, profile.host, profile.port, true) as SSLSocket
        ssl.soTimeout = 30_000
        val params = ssl.sslParameters
        if (sni.isNotBlank() && Addr.parseIpv4(sni) == null && !sni.contains(":")) {
            params.serverNames = listOf(SNIHostName(sni))
        }
        if (!profile.xrayInsecure) {
            params.endpointIdentificationAlgorithm = "HTTPS"
        }
        if (profile.xrayAlpn.isNotBlank()) {
            try {
                params.applicationProtocols = profile.xrayAlpn.split(",").map { it.trim() }.toTypedArray()
            } catch (e: Throwable) {
                // API < 29 tidak punya setApplicationProtocols — ALPN opsional, abaikan.
                log("ALPN diabaikan di Android ini")
            }
        }
        ssl.sslParameters = params
        ssl.startHandshake()
        return SocketStream(ssl)
    }
}

/** Klien WebSocket minimal (RFC 6455): frame biner ter-mask, rakit fragment, balas ping. */
class WsClientStream(
    private val base: DuplexStream,
    hostHeader: String,
    path: String,
) : DuplexStream {
    private val inp = base.input
    private val out = base.output
    private val random = SecureRandom()
    @Volatile private var closed = false

    init {
        val key = ByteArray(16)
        random.nextBytes(key)
        val b64 = java.util.Base64.getEncoder().encodeToString(key)
        val req = StringBuilder()
        req.append("GET $path HTTP/1.1\r\n")
        req.append("Host: $hostHeader\r\n")
        req.append("Upgrade: websocket\r\n")
        req.append("Connection: Upgrade\r\n")
        req.append("Sec-WebSocket-Key: $b64\r\n")
        req.append("Sec-WebSocket-Version: 13\r\n")
        req.append("User-Agent: TunnelKu\r\n")
        req.append("\r\n")
        out.write(req.toString().toByteArray(Charsets.US_ASCII))
        out.flush()
        // Baca header respons sampai CRLFCRLF
        val head = StringBuilder()
        var state = 0
        while (state < 4) {
            val c = inp.read()
            if (c < 0) throw IllegalStateException("WS: koneksi tertutup saat handshake")
            head.append(c.toChar())
            state = when {
                state == 0 && c == '\r'.code -> 1
                state == 1 && c == '\n'.code -> 2
                state == 2 && c == '\r'.code -> 3
                state == 3 && c == '\n'.code -> 4
                else -> 0
            }
        }
        val firstLine = head.toString().lineSequence().firstOrNull() ?: ""
        if (!firstLine.contains("101")) {
            throw IllegalStateException("WS handshake gagal: $firstLine")
        }
    }

    override val input: InputStream = object : InputStream() {
        private var cur: ByteArray = ByteArray(0)
        private var pos = 0
        private var eof = false

        override fun read(): Int {
            val b = ByteArray(1)
            val n = read(b, 0, 1)
            return if (n < 0) -1 else b[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            while (pos >= cur.size) {
                if (eof) return -1
                if (!nextFrame()) {
                    eof = true
                    return -1
                }
            }
            val take = minOf(len, cur.size - pos)
            System.arraycopy(cur, pos, b, off, take)
            pos += take
            return take
        }

        /** Baca satu pesan utuh (merakit fragment). false = stream selesai. */
        private fun nextFrame(): Boolean {
            var assembled: ByteArray? = null
            while (true) {
                val h = readNOrNull(2) ?: return false
                val fin = h[0].toInt() and 0x80 != 0
                val opcode = h[0].toInt() and 0x0F
                val masked = h[1].toInt() and 0x80 != 0
                var len = (h[1].toInt() and 0x7F).toLong()
                if (len == 126L) {
                    val e = readNOrNull(2) ?: return false
                    len = (((e[0].toInt() and 0xFF) shl 8) or (e[1].toInt() and 0xFF)).toLong()
                } else if (len == 127L) {
                    val e = readNOrNull(8) ?: return false
                    len = 0
                    for (x in e) len = (len shl 8) or (x.toInt() and 0xFF).toLong()
                }
                if (len > 16 * 1024 * 1024) throw IllegalStateException("WS: frame terlalu besar")
                val mask = if (masked) (readNOrNull(4) ?: return false) else null
                val payload = readNOrNull(len.toInt()) ?: return false
                if (mask != null) {
                    for (i in payload.indices) payload[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
                }
                when (opcode) {
                    9 -> { // ping → pong
                        writeFrame(0x0A, payload)
                    }
                    8 -> return false // close
                    0, 1, 2 -> {
                        assembled = if (assembled == null) payload else assembled + payload
                        if (fin) {
                            cur = assembled!!
                            pos = 0
                            return true
                        }
                    }
                }
            }
        }

        private fun readNOrNull(n: Int): ByteArray? {
            val buf = ByteArray(n)
            var off = 0
            while (off < n) {
                val r = inp.read(buf, off, n - off)
                if (r < 0) return null
                off += r
            }
            return buf
        }
    }

    override val output: OutputStream = object : OutputStream() {
        override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)
        override fun write(b: ByteArray, off: Int, len: Int) {
            if (closed) throw IllegalStateException("WS tertutup")
            writeFrame(0x2, b.copyOfRange(off, off + len))
        }
        override fun flush() = out.flush()
        override fun close() = this@WsClientStream.close()
    }

    @Synchronized
    private fun writeFrame(opcode: Int, payload: ByteArray) {
        val mask = ByteArray(4)
        random.nextBytes(mask)
        val header = ArrayList<Byte>()
        header.add((0x80 or opcode).toByte())
        val len = payload.size
        when {
            len < 126 -> header.add((0x80 or len).toByte())
            len <= 0xFFFF -> {
                header.add((0x80 or 126).toByte())
                header.add((len shr 8).toByte()); header.add((len and 0xFF).toByte())
            }
            else -> {
                header.add((0x80 or 127).toByte())
                for (i in 7 downTo 0) header.add((len.toLong() ushr (8 * i)).toByte())
            }
        }
        val masked = ByteArray(payload.size) { (payload[it].toInt() xor mask[it % 4].toInt()).toByte() }
        out.write(header.toByteArray())
        out.write(mask)
        out.write(masked)
        out.flush()
    }

    override fun close() {
        closed = true
        try { base.close() } catch (e: Exception) { /* abaikan */ }
    }
}
