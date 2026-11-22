package id.tunnelku.xray

import id.tunnelku.model.SshProfile
import id.tunnelku.vpn.DuplexStream
import id.tunnelku.vpn.FragmentingSocket
import id.tunnelku.vpn.PayloadVars
import id.tunnelku.vpn.Payloads
import id.tunnelku.vpn.StreamSocket
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.net.DatagramSocket
import java.net.InetAddress
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

/** Penanda kegagalan handshake TLS (untuk retry fragmentasi ala XVEON). */
class TlsHandshakeException(cause: Throwable) : IOException("TLS handshake gagal: ${cause.message}", cause)

/**
 * Stripper respons HTTP di kepala stream (port `u9` XVEON): pada bacaan
 * pertama, bila stream diawali respons HTTP, kuras sampai 4 respons sebelum
 * byte protokol mengalir; selain itu stream diteruskan utuh.
 */
class HttpResponseStripper(base: InputStream) : InputStream() {
    @Volatile private var current: InputStream = PushbackInputStream(base, 16384)
    @Volatile private var checked = false

    private fun ensure() {
        if (checked) return
        synchronized(this) {
            if (checked) return
            checked = true
            val push = current as PushbackInputStream
            val first = try { push.read() } catch (e: Exception) { -1 }
            if (first >= 0) {
                push.unread(first)
                if (first == 'H'.code) {
                    current = Payloads.drainHttpResponses(push, 4).first
                }
            }
        }
    }

    override fun read(): Int {
        ensure()
        return current.read()
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        ensure()
        return current.read(b, off, len)
    }

    override fun available(): Int = current.available()
    override fun close() = current.close()
}

/**
 * Pembuka koneksi ke server Xray — port rantai `da.o0()` XVEON (injector,
 * bukan dialer polos):
 *   socket polos (≤6 alamat, protect) → (SOCKS5) → (fronting proxy:
 *   payload kustom ATAU CONNECT) → (TLS: SNI template, tanpa verifikasi
 *   hostname, ALPN http/1.1; retry fragmentasi ClientHello bila handshake
 *   gagal & allowInsecure) → transport (WS / TCP-camo) → protokol.
 * REALITY & gRPC ditolak dengan pesan jelas.
 */
open class XrayDialer(
    private val profile: SshProfile,
    private val protectSocket: (Socket) -> Boolean,
    private val protectDatagram: (DatagramSocket) -> Boolean,
    private val log: (String) -> Unit,
) {
    /**
     * Timeout baca (ms) yang diterapkan pada dial berikutnya lalu direset ke 0.
     * Dipakai adapter engine untuk aliran berumur pendek (DNS-over-TCP).
     */
    @Volatile var nextReadTimeoutMs: Int = 0
    open fun dialServer(timeoutMs: Int = 30000): DuplexStream {
        if (profile.xrayNetwork == "grpc") {
            throw IllegalStateException("Transport gRPC belum didukung klien Kotlin — pakai TCP/WS")
        }
        if (profile.xraySecurity == "reality") {
            throw IllegalStateException("REALITY belum didukung klien Kotlin — pakai TLS")
        }
        var frag = false
        while (true) {
            try {
                return dialOnce(timeoutMs, frag)
            } catch (e: TlsHandshakeException) {
                if (!frag && profile.xrayInsecure) {
                    log("TLS handshake gagal (${e.cause?.message}) — ulangi dengan fragmentasi ClientHello")
                    frag = true
                    continue
                }
                throw e.cause ?: e
            }
        }
    }

    private fun dialOnce(timeoutMs: Int, frag: Boolean): DuplexStream {
        val useProxy = profile.proxyEnabled && profile.proxyHost.isNotBlank()
        val useSocks = useProxy && profile.proxyType.equals("SOCKS5", true)
        val connectHost = if (useProxy) profile.proxyHost else profile.host
        val connectPort = if (useProxy) profile.proxyPort else profile.port
        val socket = connectPlain(connectHost, connectPort, timeoutMs)
        var input: InputStream = socket.getInputStream()
        var output: OutputStream = socket.getOutputStream()
        var setTimeout: (Int) -> Unit = { ms -> try { socket.soTimeout = ms } catch (e: Exception) { /* abaikan */ } }
        try {
            if (useSocks) {
                socks5Handshake(socket, profile.host, profile.port)
                log("Proxy SOCKS5: tunnel ke ${profile.host}:${profile.port} dibuka")
            }
            // Fronting proxy (payload / CONNECT) — di luar TLS, ala `da`
            var payloadConsumed = false
            val payloadText = if (profile.payloadEnabled) profile.payload else ""
            if (useProxy && !useSocks) {
                val firstLine = payloadText.lineSequence().firstOrNull() ?: ""
                val httpLine = listOf("CONNECT ", "GET ", "POST ", "HEAD ", "PUT ")
                    .any { firstLine.startsWith(it, ignoreCase = true) }
                val usable = payloadText.isNotBlank() &&
                    (profile.xraySecurity != "tls" || profile.xrayNetwork == "tcp" || httpLine)
                setTimeout(timeoutMs.coerceIn(3000, 15000))
                if (usable) {
                    val rendered = Payloads.render(payloadText, payloadVars(""))
                    Payloads.sendWithSplits(output, rendered)
                    val maxResp = countCrlfPairs(rendered).coerceIn(1, 4)
                    val (s2, status) = Payloads.drainHttpResponses(input, maxResp)
                    input = s2
                    checkHttpStatus(status, "Fronting")
                    payloadConsumed = true
                    log("Fronting payload terkirim ke proxy ${profile.proxyHost}:${profile.proxyPort}")
                } else {
                    val req = "CONNECT ${profile.host}:${profile.port} HTTP/1.1\r\n" +
                        "Host: ${profile.host}:${profile.port}\r\n" +
                        "Connection: keep-alive\r\n\r\n"
                    output.write(req.toByteArray(Charsets.ISO_8859_1))
                    output.flush()
                    val (s2, status) = Payloads.drainHttpResponses(input, 1)
                    input = s2
                    if (status == null || !status.contains("200")) {
                        throw IOException("Proxy menolak CONNECT: ${status ?: "tanpa respons"}")
                    }
                    log("Proxy CONNECT ke ${profile.host}:${profile.port} diterima")
                }
            }
            // TLS
            if (profile.xraySecurity == "tls") {
                val sni = resolveSni()
                val base: Socket = if (frag) {
                    FragmentingSocket(socket, sni, input)
                } else {
                    StreamSocket(socket, input, output)
                }
                val ssl = tlsFactory().createSocket(base, profile.host, profile.port, true) as SSLSocket
                try {
                    val params = ssl.sslParameters
                    if (sni.isNotBlank() && Addr.parseIpv4(sni) == null && !sni.contains(":")) {
                        params.serverNames = listOf(SNIHostName(sni))
                    }
                    try {
                        params.applicationProtocols = arrayOf(
                            profile.xrayAlpn.ifBlank { "http/1.1" },
                        )
                    } catch (e: Throwable) {
                        log("ALPN diabaikan di Android ini")
                    }
                    ssl.sslParameters = params
                } catch (e: Exception) {
                    log("Parameter TLS diabaikan: ${e.message}")
                }
                ssl.soTimeout = timeoutMs.coerceIn(4000, 20000)
                try {
                    ssl.startHandshake()
                } catch (e: Exception) {
                    throw TlsHandshakeException(e)
                }
                input = ssl.inputStream
                output = ssl.outputStream
                val sslRef = ssl
                setTimeout = { ms -> try { sslRef.soTimeout = ms } catch (e: Exception) { /* abaikan */ } }
                log("TLS aktif, SNI = $sni" + if (frag) " (fragmentasi ClientHello)" else "")
            }
            // Transport
            var stream: DuplexStream = simpleStream(input, output) { socket.close() }
            when (profile.xrayNetwork) {
                "ws" -> {
                    stream = wsHandshake(stream, setTimeout, timeoutMs, payloadText, payloadConsumed) {
                        socket.close()
                    }
                }
                else -> { // tcp
                    if (payloadText.isNotBlank() && !payloadConsumed) {
                        val rendered = Payloads.render(payloadText, payloadVars(""))
                        Payloads.sendWithSplits(output, rendered)
                        stream = simpleStream(HttpResponseStripper(input), output) { socket.close() }
                        log("Payload TCP terkirim (${rendered.length} byte)")
                    } else if (profile.xrayWsHost.isNotBlank()) {
                        val camo = "GET ${wsPath()} HTTP/1.1\r\n" +
                            "Host: ${wsHost()}\r\n" +
                            "User-Agent: ${PayloadVars().ua}\r\n" +
                            "Accept-Encoding: gzip, deflate\r\n" +
                            "Connection: keep-alive\r\n" +
                            "Pragma: no-cache\r\n\r\n"
                        output.write(camo.toByteArray(Charsets.US_ASCII))
                        output.flush()
                        stream = simpleStream(HttpResponseStripper(input), output) { socket.close() }
                        log("Kamuflase HTTP terkirim (Host: ${wsHost()})")
                    }
                }
            }
            val rt = nextReadTimeoutMs
            nextReadTimeoutMs = 0
            setTimeout(rt)
            return stream
        } catch (e: Exception) {
            try { socket.close() } catch (e2: Exception) { /* abaikan */ }
            throw e
        }
    }

    /** Socket UDP langsung ke server (untuk UDP Shadowsocks). */
    open fun dialUdpSocket(): DatagramSocket {
        require(profile.host.isNotBlank()) { "Host server kosong" }
        val s = DatagramSocket()
        protectDatagram(s)
        s.connect(InetSocketAddress(profile.host, profile.port))
        return s
    }

    private fun connectPlain(host: String, port: Int, timeoutMs: Int): Socket {
        // Host kosong akan ter-resolve ke loopback oleh Java — gagalkan terus terang.
        require(host.isNotBlank()) { "Host server kosong" }
        val addresses = InetAddress.getAllByName(host).toList().take(6)
        require(addresses.isNotEmpty()) { "DNS gagal untuk $host" }
        var lastErr: Exception? = null
        for (addr in addresses) {
            val socket = Socket()
            try {
                protectSocket(socket)
                socket.tcpNoDelay = true
                socket.keepAlive = true
                socket.connect(InetSocketAddress(addr, port), timeoutMs.coerceIn(2500, 20000))
                log("TCP -> ${addr.hostAddress}:$port")
                return socket
            } catch (e: Exception) {
                lastErr = e
                try { socket.close() } catch (e2: Exception) { /* abaikan */ }
            }
        }
        throw lastErr ?: IOException("Koneksi ke $host:$port gagal")
    }

    private fun tlsFactory(): javax.net.ssl.SSLSocketFactory {
        if (!profile.xrayInsecure) return SSLContext.getDefault().socketFactory
        val tm = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, tm, SecureRandom())
        return ctx.socketFactory
    }

    private fun wsHost(): String =
        profile.xrayWsHost.split(',').firstOrNull()?.trim() ?: ""

    private fun wsPath(): String {
        val p = profile.xrayWsPath.ifBlank { "/" }
        return if (p.startsWith("/")) p else "/$p"
    }

    private fun resolveSni(): String {
        val fallback = wsHost().ifBlank { profile.host }
        val raw = profile.xraySni
        if (raw.isBlank()) return fallback
        return raw.replace("[host]", fallback, ignoreCase = true)
    }

    private fun payloadVars(wsKey: String): PayloadVars = PayloadVars(
        host = profile.host,
        port = profile.port,
        sni = resolveSni(),
        wsHost = wsHost(),
        path = wsPath(),
        wsKey = wsKey,
    )

    private fun countCrlfPairs(s: String): Int {
        var c = 0
        var i = 0
        while (true) {
            val j = s.indexOf("\r\n\r\n", i)
            if (j < 0) break
            c++
            i = j + 4
        }
        return c
    }

    private fun httpStatusCode(status: String): Int =
        status.split(' ').getOrNull(1)?.toIntOrNull() ?: 0

    private fun checkHttpStatus(status: String?, stage: String) {
        if (status == null) {
            log("$stage: respons non-HTTP (banner) — diteruskan")
            return
        }
        val code = httpStatusCode(status)
        if (code in 400..599) throw IOException("$stage ditolak: $status")
    }

    private fun wsHandshake(
        stream: DuplexStream,
        setTimeout: (Int) -> Unit,
        timeoutMs: Int,
        payloadText: String,
        payloadConsumed: Boolean,
        onClose: () -> Unit,
    ): DuplexStream {
        val inp = stream.input
        val out = stream.output
        setTimeout(timeoutMs.coerceIn(3000, 15000))
        if (payloadText.isNotBlank() && !payloadConsumed) {
            val key = newWsKey()
            var rendered = Payloads.render(payloadText, payloadVars(key))
            if (!rendered.contains("Sec-WebSocket-Key:", ignoreCase = true)) {
                val idx = rendered.indexOf("\r\n\r\n")
                if (idx >= 0) {
                    val ins = "Sec-WebSocket-Key: $key\r\nSec-WebSocket-Version: 13\r\n"
                    rendered = rendered.substring(0, idx + 2) + ins + rendered.substring(idx + 2)
                }
            }
            Payloads.sendWithSplits(out, rendered)
            val maxResp = countCrlfPairs(rendered).coerceIn(1, 4)
            val (s2, status) = Payloads.drainHttpResponses(inp, maxResp)
            if (status == null) throw IOException("WS: handshake payload tidak dijawab HTTP")
            checkHttpStatus(status, "WS handshake")
            if (!status.contains("101") && httpStatusCode(status) !in 200..399) {
                throw IOException("WS handshake gagal: $status")
            }
            log("WS handshake (payload kustom) diterima: $status")
            return WsClientStream(simpleStream(s2, out, onClose), preHandshaked = true)
        }
        val key = newWsKey()
        val req = "GET ${wsPath()} HTTP/1.1\r\n" +
            "Host: ${wsHost().ifBlank { profile.host }}\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            "Sec-WebSocket-Key: $key\r\n" +
            "Sec-WebSocket-Version: 13\r\n" +
            "User-Agent: ${PayloadVars().ua}\r\n\r\n"
        out.write(req.toByteArray(Charsets.US_ASCII))
        out.flush()
        val (s2, status) = Payloads.drainHttpResponses(inp, 1)
        if (status == null || !status.contains("101")) {
            throw IOException("WS handshake gagal: ${status ?: "tanpa respons"}")
        }
        return WsClientStream(simpleStream(s2, out, onClose), preHandshaked = true)
    }

    private fun newWsKey(): String {
        val key = ByteArray(16)
        SecureRandom().nextBytes(key)
        return java.util.Base64.getEncoder().encodeToString(key)
    }

    private fun socks5Handshake(socket: Socket, host: String, port: Int) {
        val out = socket.getOutputStream()
        val inp = socket.getInputStream()
        out.write(byteArrayOf(0x05, 0x01, 0x00)); out.flush()
        val greeting = ByteArray(2)
        readFully(inp, greeting)
        require(greeting[0].toInt() == 5 && greeting[1].toInt() == 0) { "Proxy SOCKS5 menolak (tanpa autentikasi wajib)" }
        val hostBytes = host.toByteArray(Charsets.UTF_8)
        val req = ByteArray(4 + 1 + hostBytes.size + 2)
        req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03
        req[4] = hostBytes.size.toByte()
        System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
        req[req.size - 2] = (port shr 8).toByte()
        req[req.size - 1] = (port and 0xFF).toByte()
        out.write(req); out.flush()
        val head = ByteArray(4)
        readFully(inp, head)
        require(head[1].toInt() == 0) { "Proxy SOCKS5 gagal: kode ${head[1]}" }
        val restLen = when (head[3].toInt()) {
            1 -> 4 + 2
            3 -> { val l = inp.read(); l + 2 }
            4 -> 16 + 2
            else -> 0
        }
        if (restLen > 0) readFully(inp, ByteArray(restLen))
    }

    private fun readFully(inp: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = inp.read(buf, off, buf.size - off)
            if (n < 0) throw IOException("Koneksi ditutup di tengah handshake")
            off += n
        }
    }
}

/** Klien WebSocket minimal (RFC 6455): frame biner ter-mask, rakit fragment, balas ping. */
class WsClientStream(
    private val base: DuplexStream,
    hostHeader: String = "",
    path: String = "/",
    preHandshaked: Boolean = false,
) : DuplexStream {
    private val inp = base.input
    private val out = base.output
    private val random = SecureRandom()
    @Volatile private var closed = false

    init {
        if (!preHandshaked) {
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
        req.append("User-Agent: ${PayloadVars().ua}\r\n")
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
