package id.tunnelku.vpn

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.jcraft.jsch.SocketFactory
import id.tunnelku.model.SshProfile
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Base64
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Jalur koneksi SSH TunnelKu:
 *   socket mentah -> (proxy HTTP/SOCKS5) -> (TLS + SNI) -> (payload kustom) -> SSH (JSch)
 * Semua socket dibuat lewat [protect] agar tidak berputar lewat TUN sendiri.
 */
class SshTunnel(
    private val profile: SshProfile,
    private val protect: (Socket) -> Boolean,
    private val log: (String) -> Unit,
) {
    private var session: Session? = null
    @Volatile var rawSocket: Socket? = null
        private set

    val isConnected: Boolean get() = session?.isConnected == true

    /** Bangun socket TCP yang sudah menembus proxy/TLS/payload, siap dibungkus SSH. */
    private fun buildRawSocket(): Socket {
        val targetHost: String
        val targetPort: Int
        if (profile.proxyEnabled) {
            targetHost = profile.proxyHost
            targetPort = profile.proxyPort
        } else {
            targetHost = profile.host
            targetPort = profile.port
        }
        require(targetHost.isNotBlank()) { "Host tujuan kosong" }

        val socket = Socket()
        protect(socket)
        socket.soTimeout = 20_000
        socket.tcpNoDelay = true
        log("TCP -> $targetHost:$targetPort ...")
        socket.connect(InetSocketAddress(targetHost, targetPort), 15_000)
        log("TCP terhubung ke $targetHost:$targetPort")

        var current: Socket = socket

        if (profile.proxyEnabled && profile.proxyType.equals("SOCKS5", true)) {
            socks5Handshake(current, profile.host, profile.port)
            log("Proxy SOCKS5: tunnel ke ${profile.host}:${profile.port} dibuka")
        } else if (profile.proxyEnabled && !profile.payloadEnabled) {
            httpConnect(current, profile.host, profile.port)
            log("Proxy HTTP: CONNECT ${profile.host}:${profile.port} diterima")
        }

        if (profile.sniEnabled) {
            val sni = profile.sniHost.ifBlank { profile.host }
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            val ssl = factory.createSocket(current, sni, current.port, true) as SSLSocket
            val params = ssl.sslParameters
            params.serverNames = listOf(SNIHostName(sni))
            ssl.sslParameters = params
            ssl.startHandshake()
            current = ssl
            log("TLS aktif, SNI = $sni")
        }

        if (profile.payloadEnabled) {
            val payload = renderPayload(profile.payload, profile.host, profile.port)
            require(payload.isNotBlank()) { "Payload aktif tapi kosong" }
            current.getOutputStream().apply {
                write(payload.toByteArray(Charsets.ISO_8859_1))
                flush()
            }
            log("Payload terkirim (${payload.length} byte)")
            // Respons HTTP hanya dibaca bila memang lewat proxy / payload berbentuk HTTP;
            // payload non-HTTP langsung ke server SSH tidak dibaca agar banner SSH utuh untuk JSch.
            if (profile.proxyEnabled || payload.contains("HTTP/")) {
                try { current.soTimeout = 8_000 } catch (e: Exception) { /* abaikan */ }
                val resp = readHttpResponseHead(current.getInputStream())
                log("Respons: ${resp.lineSequence().firstOrNull() ?: "(kosong)"}")
                if (resp.startsWith("HTTP") && !resp.contains("200") && !resp.contains("101")) {
                    throw IllegalStateException("Proxy/payload menolak koneksi: ${resp.lineSequence().firstOrNull() ?: resp.take(80)}")
                }
            }
        }

        current.soTimeout = 0
        rawSocket = current
        return current
    }

    private fun httpConnect(socket: Socket, host: String, port: Int) {
        val req = "CONNECT $host:$port HTTP/1.1\r\nHost: $host:$port\r\nProxy-Connection: Keep-Alive\r\n\r\n"
        socket.getOutputStream().apply { write(req.toByteArray(Charsets.ISO_8859_1)); flush() }
        val resp = readHttpResponseHead(socket.getInputStream())
        if (!resp.contains(" 200")) {
            throw IllegalStateException("Proxy HTTP menolak CONNECT: ${resp.lineSequence().firstOrNull() ?: "?"}")
        }
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
            if (n < 0) throw IllegalStateException("Koneksi ditutup di tengah handshake")
            off += n
        }
    }

    /** Baca kepala respons HTTP sampai CRLFCRLF (maks ±4 KB), tanpa menelan byte SSH sesudahnya. */
    private fun readHttpResponseHead(inp: InputStream): String {
        val sb = StringBuilder()
        var state = 0
        var count = 0
        while (count < 4096) {
            val b = inp.read()
            if (b < 0) break
            count++
            sb.append(b.toChar())
            state = when {
                state == 0 && b == '\r'.code -> 1
                state == 1 && b == '\n'.code -> 2
                state == 2 && b == '\r'.code -> 3
                state == 3 && b == '\n'.code -> 4
                else -> 0
            }
            if (state == 4) break
        }
        return sb.toString()
    }

    private fun renderPayload(template: String, host: String, port: Int): String {
        var p = template
            .replace("[host_port]", "$host:$port")
            .replace("[host]", host)
            .replace("[port]", port.toString())
            .replace("[protocol]", "SSH")
        p = p.replace("\\r\\n", "\r\n").replace("[crlf]", "\r\n").replace("[cr]", "\r").replace("[lf]", "\n")
        if (!p.endsWith("\r\n\r\n") && p.contains("HTTP/")) p += "\r\n\r\n"
        return p
    }

    fun connect(timeoutMs: Int = 20_000) {
        val raw = buildRawSocket()
        val jsch = JSch()
        if (profile.usePrivateKey && profile.privateKey.isNotBlank()) {
            val keyBytes = profile.privateKey.trim().toByteArray(Charsets.UTF_8)
            val pass = profile.privateKeyPassphrase.ifBlank { null }?.toByteArray(Charsets.UTF_8)
            jsch.addIdentity("tunnelku-key", keyBytes, null, pass)
            log("SSH: autentikasi private key")
        }
        val sess = jsch.getSession(profile.username, profile.host, profile.port)
        if (!profile.usePrivateKey) sess.setPassword(profile.password)
        sess.setConfig("StrictHostKeyChecking", "no")
        sess.setConfig("PreferredAuthentications", "password,publickey,keyboard-interactive")
        sess.setServerAliveInterval(15_000)
        sess.setServerAliveCountMax(3)
        sess.setSocketFactory(object : SocketFactory {
            override fun createSocket(host: String, port: Int): Socket = raw
            override fun getInputStream(socket: Socket): InputStream = socket.getInputStream()
            override fun getOutputStream(socket: Socket): OutputStream = socket.getOutputStream()
        })
        // Daemon thread agar channel reader tidak menahan proses.
        sess.isDaemonThread = true
        sess.connect(timeoutMs)
        session = sess
        val fp = try {
            val info = sess.hostKey
            if (info != null) Base64.getEncoder().encodeToString(info.key).take(24) + "…" else "?"
        } catch (e: Exception) { "?" }
        log("SSH terhubung & terautentikasi (${profile.username}@${profile.host}:${profile.port}), hostkey $fp")
    }

    /** Buka satu aliran TCP ke [host]:[port] lewat channel direct-tcpip SSH. */
    fun openStream(host: String, port: Int): ChannelDirectTCPIP {
        val sess = session ?: throw IllegalStateException("SSH belum terhubung")
        val channel = sess.openChannel("direct-tcpip") as ChannelDirectTCPIP
        channel.setHost(host)
        channel.setPort(port)
        channel.setOriginatorIPAddress("127.0.0.1")
        channel.setOriginatorPort(0)
        channel.connect(10_000)
        return channel
    }

    fun disconnect() {
        try { session?.disconnect() } catch (e: Exception) { /* abaikan */ }
        session = null
        try { rawSocket?.close() } catch (e: Exception) { /* abaikan */ }
        rawSocket = null
    }
}
