package id.tunnelku.vpn

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.jcraft.jsch.SocketFactory
import id.tunnelku.model.SshProfile
import java.io.FilterOutputStream
import java.io.InputStream
import java.io.OutputStream
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

/**
 * Jalur koneksi SSH TunnelKu — port rantai `z` XVEON (JSch Proxy):
 *   socket (protect) -> (SOCKS5) -> (TLS+SNI, tangga retry + fragmentasi ClientHello)
 *   -> (payload [split]/[rotate] ATAU CONNECT) -> kuras respons -> SSH (JSch)
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
    @Volatile private var connInput: InputStream? = null
    @Volatile private var connOutput: OutputStream? = null
    private val channelLock = Object()

    val isConnected: Boolean get() = session?.isConnected == true

    private class Conn(val socket: Socket, val input: InputStream, val output: OutputStream)

    private fun trustAllFactory(): javax.net.ssl.SSLSocketFactory {
        val tm = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, tm, SecureRandom())
        return ctx.socketFactory
    }

    private fun resolveSni(): String {
        val raw = profile.sniHost
        if (raw.isBlank()) return profile.host
        return raw.replace("[host]", profile.host, ignoreCase = true)
    }

    /** Bangun koneksi sampai selesai tahap TLS (tangga retry ala XVEON). */
    private fun buildTransport(): Conn {
        val useProxy = profile.proxyEnabled && profile.proxyHost.isNotBlank()
        val targetHost = if (useProxy) profile.proxyHost else profile.host
        val targetPort = if (useProxy) profile.proxyPort else profile.port
        require(targetHost.isNotBlank()) { "Host tujuan kosong" }
        val addresses = InetAddress.getAllByName(targetHost).toList().take(6)
        require(addresses.isNotEmpty()) { "DNS gagal untuk $targetHost" }
        val tlsOn = profile.sniEnabled

        data class Attempt(val addr: InetAddress, val frag: Boolean, val forceTls12: Boolean)
        val attempts = mutableListOf(Attempt(addresses[0], frag = false, forceTls12 = false))
        if (tlsOn) {
            attempts += Attempt(addresses[0], frag = true, forceTls12 = false)
            if (addresses.size > 1) attempts += Attempt(addresses[1], frag = true, forceTls12 = true)
        }
        var lastErr: Exception? = null
        for ((i, att) in attempts.withIndex()) {
            var plain: Socket? = null
            try {
                val socket = Socket()
                protect(socket)
                socket.tcpNoDelay = true
                socket.keepAlive = true
                plain = socket
                log("TCP -> ${att.addr.hostAddress}:$targetPort ...")
                socket.connect(InetSocketAddress(att.addr, targetPort), 15_000)
                socket.soTimeout = 0
                log("TCP terhubung (${att.addr.hostAddress}:$targetPort)")
                var conn = Conn(socket, socket.getInputStream(), socket.getOutputStream())
                if (useProxy && profile.proxyType.equals("SOCKS5", true)) {
                    socks5Handshake(socket, profile.host, profile.port)
                    log("Proxy SOCKS5: tunnel ke ${profile.host}:${profile.port} dibuka")
                }
                if (tlsOn) {
                    conn = wrapTls(socket, att.frag, att.forceTls12)
                    if (i > 0) log("TLS aktif (percobaan ${i + 1})")
                }
                return conn
            } catch (e: Exception) {
                lastErr = e
                try { plain?.close() } catch (e2: Exception) { /* abaikan */ }
                if (!tlsOn || i == attempts.size - 1) throw e
                log("Koneksi/TLS gagal (${e.message}) — coba varian berikutnya")
            }
        }
        throw lastErr ?: IllegalStateException("Koneksi gagal")
    }

    private fun wrapTls(plain: Socket, frag: Boolean, forceTls12: Boolean): Conn {
        val sni = resolveSni()
        val factory = trustAllFactory()
        val base: Socket = if (frag) FragmentingSocket(plain, sni) else plain
        val ssl = factory.createSocket(base, sni, plain.port, true) as SSLSocket
        try {
            val params = ssl.sslParameters
            if (!sni.matches(Regex("""\d+\.\d+\.\d+\.\d+"""))) {
                params.serverNames = listOf(SNIHostName(sni))
            }
            if (forceTls12) {
                params.protocols = arrayOf("TLSv1.2")
            }
            ssl.sslParameters = params
        } catch (e: Exception) {
            log("Parameter TLS diabaikan: ${e.message}")
        }
        plain.soTimeout = 12_000
        ssl.startHandshake()
        plain.soTimeout = 0
        ssl.soTimeout = 0
        log("TLS aktif, SNI = $sni" + if (frag) " (fragmentasi ClientHello)" else "")
        return Conn(ssl, ssl.inputStream, ssl.outputStream)
    }

    /** Tahap payload / CONNECT setelah transport siap (di dalam TLS bila aktif). */
    private fun frontingStage(conn: Conn): Conn {
        val useProxy = profile.proxyEnabled && profile.proxyHost.isNotBlank() &&
            !profile.proxyType.equals("SOCKS5", true)
        var input = conn.input
        if (profile.payloadEnabled && profile.payload.isNotBlank()) {
            val vars = PayloadVars(
                host = profile.host,
                port = profile.port,
                sni = resolveSni(),
            )
            val rendered = Payloads.render(profile.payload, vars)
            Payloads.sendWithSplits(conn.output, rendered)
            log("Payload terkirim (${rendered.length} byte)")
            conn.socket.soTimeout = 10_000
            val (stream, status) = Payloads.drainHttpResponses(input, 4)
            input = stream
            log("Respons: ${status ?: "(banner/non-HTTP)"}")
            if (status != null && status.startsWith("HTTP")) {
                val code = status.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
                if (code in 400..599) {
                    throw IllegalStateException("Proxy/payload menolak koneksi: $status")
                }
            }
        } else if (useProxy) {
            val req = "CONNECT ${profile.host}:${profile.port} HTTP/1.1\r\n" +
                "Host: ${profile.host}:${profile.port}\r\n" +
                "Connection: keep-alive\r\n\r\n"
            conn.output.write(req.toByteArray(Charsets.ISO_8859_1))
            conn.output.flush()
            conn.socket.soTimeout = 10_000
            val (stream, status) = Payloads.drainHttpResponses(input, 4)
            input = stream
            if (status == null || !status.contains("200")) {
                throw IllegalStateException("Proxy HTTP menolak CONNECT: ${status ?: "(tanpa respons)"}")
            }
            log("Proxy HTTP: CONNECT ${profile.host}:${profile.port} diterima")
        }
        conn.socket.soTimeout = 0
        return Conn(conn.socket, input, conn.output)
    }

    private fun buildConnection(): Conn {
        val conn = frontingStage(buildTransport())
        rawSocket = conn.socket
        connInput = conn.input
        connOutput = conn.output
        return conn
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

    fun connect(timeoutMs: Int = 30_000) {
        buildConnection()
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
        sess.setConfig(
            "PreferredAuthentications",
            if (profile.usePrivateKey) "publickey,password,keyboard-interactive"
            else "password,keyboard-interactive,publickey",
        )
        val ciphers = "aes128-gcm@openssh.com,aes128-ctr,aes256-gcm@openssh.com,aes256-ctr," +
            "aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc"
        sess.setConfig("cipher.s2c", ciphers)
        sess.setConfig("cipher.c2s", ciphers)
        sess.setServerAliveInterval(30_000)
        sess.setServerAliveCountMax(3)
        sess.setSocketFactory(object : SocketFactory {
            override fun createSocket(host: String, port: Int): Socket = rawSocket!!
            override fun getInputStream(socket: Socket): InputStream = connInput!!
            override fun getOutputStream(socket: Socket): OutputStream = connOutput!!
        })
        sess.setDaemonThread(true)
        sess.connect(timeoutMs)
        session = sess
        log("SSH terhubung & terautentikasi (${profile.username}@${profile.host}:${profile.port})")
    }

    /** Handle stream di atas satu channel direct-tcpip (untuk adapter stack). */
    class ChannelHandle(private val channel: ChannelDirectTCPIP) : id.tunnelku.vpn.stack.TcpHandle {
        override val input: InputStream = channel.inputStream
        override val output: OutputStream = channel.outputStream
        override fun isConnected(): Boolean = channel.isConnected
        override fun setTimeout(ms: Int) { /* channel JSch tidak punya read timeout */ }
        override fun close() {
            try { channel.disconnect() } catch (e: Exception) { /* abaikan */ }
        }
    }

    /**
     * Buka satu aliran TCP ke [host]:[port] lewat channel direct-tcpip SSH
     * (port `p6.o` XVEON: open di-synchronized, stream diambil sebelum connect).
     */
    fun openStream(host: String, port: Int, orgIp: String, orgPort: Int, timeoutMs: Int): ChannelHandle {
        val sess = session ?: throw IllegalStateException("SSH belum terhubung")
        synchronized(channelLock) {
            val channel = sess.openChannel("direct-tcpip") as ChannelDirectTCPIP
            channel.setHost(host)
            channel.setPort(port)
            channel.setOrgIPAddress(orgIp)
            channel.setOrgPort(orgPort)
            val handle = ChannelHandle(channel)
            channel.connect(timeoutMs.coerceIn(2000, 60000))
            return handle
        }
    }

    fun disconnect() {
        try { session?.disconnect() } catch (e: Exception) { /* abaikan */ }
        session = null
        try { rawSocket?.close() } catch (e: Exception) { /* abaikan */ }
        rawSocket = null
        connInput = null
        connOutput = null
    }
}
