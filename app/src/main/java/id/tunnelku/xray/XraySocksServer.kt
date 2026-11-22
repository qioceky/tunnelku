package id.tunnelku.xray

import id.tunnelku.model.SshProfile
import id.tunnelku.vpn.DuplexStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

/**
 * Server SOCKS5 lokal (127.0.0.1:11082) yang meneruskan ke klien protokol
 * Xray Kotlin — pengganti peran mesin Go. Mendukung CONNECT (TCP) dan
 * UDP ASSOCIATE. Dipakai TunnelVpnService lewat SocksStreamTransport &
 * SocksUdpRelay yang sudah ada.
 */
class XraySocksServer(
    private val profile: SshProfile,
    protectSocket: (Socket) -> Boolean,
    protectDatagram: (DatagramSocket) -> Boolean,
    private val log: (String) -> Unit,
) {
    @Volatile var alive = false
        private set

    private val dialer = XrayDialer(profile, protectSocket, protectDatagram, log)
    private val proto: XrayProto = when (profile.xrayProtocol.lowercase()) {
        "vless" -> VlessProto(profile, dialer)
        "vmess" -> VmessProto(profile, dialer)
        "trojan" -> TrojanProto(profile, dialer)
        "ss" -> SsProto(profile, dialer)
        else -> throw IllegalStateException("Protokol Xray tidak dikenal: ${profile.xrayProtocol}")
    }

    private var serverSocket: ServerSocket? = null
    private var udpSocket: DatagramSocket? = null
    private val udpSessions = ConcurrentHashMap<String, UdpSession>()
    private val activeStreams = ConcurrentHashMap.newKeySet<DuplexStream>()
    @Volatile private var udpClientAddr: InetSocketAddress? = null

    fun start() {
        val ss = ServerSocket()
        ss.reuseAddress = true
        ss.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), PORT))
        serverSocket = ss
        alive = true
        thread(name = "tk-xray-socks", isDaemon = true) {
            while (alive) {
                val client = try {
                    ss.accept()
                } catch (e: Exception) {
                    break
                }
                thread(name = "tk-xray-conn", isDaemon = true) { handle(client) }
            }
        }
        log("SOCKS5 lokal Xray aktif di 127.0.0.1:$PORT (${profile.xrayProtocol})")
    }

    fun stop() {
        alive = false
        try { serverSocket?.close() } catch (e: Exception) { /* abaikan */ }
        try { udpSocket?.close() } catch (e: Exception) { /* abaikan */ }
        udpSessions.values.forEach { try { it.close() } catch (e: Exception) { /* abaikan */ } }
        udpSessions.clear()
        activeStreams.forEach { try { it.close() } catch (e: Exception) { /* abaikan */ } }
        activeStreams.clear()
    }

    private fun handle(client: Socket) {
        try {
            client.tcpNoDelay = true
            val inp = client.getInputStream()
            val out = client.getOutputStream()
            // greeting
            val g = Addr.readN(inp, 2)
            if (g[0].toInt() != 5) throw IllegalStateException("bukan SOCKS5")
            val nMethods = g[1].toInt() and 0xFF
            if (nMethods > 0) Addr.readN(inp, nMethods)
            out.write(byteArrayOf(5, 0)); out.flush()
            val req = Addr.readN(inp, 4)
            if (req[0].toInt() != 5) throw IllegalStateException("permintaan SOCKS5 rusak")
            val cmd = req[1].toInt() and 0xFF
            val (host, port) = readTarget(inp, req[3].toInt() and 0xFF)
            when (cmd) {
                1 -> handleConnect(client, inp, out, host, port)
                3 -> handleUdpAssociate(client, inp, out)
                else -> {
                    reply(out, 0x07, "0.0.0.0", 0)
                    client.close()
                }
            }
        } catch (e: Exception) {
            try { client.close() } catch (ignored: Exception) { /* abaikan */ }
        }
    }

    private fun readTarget(inp: InputStream, atyp: Int): Pair<String, Int> = when (atyp) {
        1 -> {
            val b = Addr.readN(inp, 4)
            val pb = Addr.readN(inp, 2)
            b.joinToString(".") { (it.toInt() and 0xFF).toString() } to (((pb[0].toInt() and 0xFF) shl 8) or (pb[1].toInt() and 0xFF))
        }
        3 -> {
            val l = inp.read()
            if (l < 0) throw IllegalStateException("EOF domain")
            val name = String(Addr.readN(inp, l), Charsets.UTF_8)
            val pb = Addr.readN(inp, 2)
            name to (((pb[0].toInt() and 0xFF) shl 8) or (pb[1].toInt() and 0xFF))
        }
        4 -> {
            val b = Addr.readN(inp, 16)
            val pb = Addr.readN(inp, 2)
            Addr.formatIpv6(b) to (((pb[0].toInt() and 0xFF) shl 8) or (pb[1].toInt() and 0xFF))
        }
        else -> throw IllegalStateException("ATYP tidak dikenal: $atyp")
    }

    private fun reply(out: OutputStream, code: Int, ip: String, port: Int) {
        val ipB = Addr.parseIpv4(ip) ?: byteArrayOf(0, 0, 0, 0)
        out.write(byteArrayOf(5, code.toByte(), 0, 1))
        out.write(ipB)
        out.write(byteArrayOf((port shr 8).toByte(), (port and 0xFF).toByte()))
        out.flush()
    }

    private fun handleConnect(client: Socket, inp: InputStream, out: OutputStream, host: String, port: Int) {
        val upstream: DuplexStream = try {
            proto.openTcp(host, port)
        } catch (e: Exception) {
            log("Xray CONNECT $host:$port gagal: ${e.message}")
            reply(out, 0x05, "0.0.0.0", 0)
            client.close()
            return
        }
        activeStreams.add(upstream)
        reply(out, 0x00, "0.0.0.0", 0)
        val done = java.util.concurrent.atomic.AtomicBoolean(false)
        fun finish() {
            if (done.compareAndSet(false, true)) {
                activeStreams.remove(upstream)
                try { upstream.close() } catch (e: Exception) { /* abaikan */ }
                try { client.close() } catch (e: Exception) { /* abaikan */ }
            }
        }
        thread(name = "tk-xray-up", isDaemon = true) {
            try {
                copy(inp, upstream.output)
            } catch (e: Exception) { /* abaikan */ } finally { finish() }
        }
        thread(name = "tk-xray-down", isDaemon = true) {
            try {
                copy(upstream.input, out)
            } catch (e: Exception) { /* abaikan */ } finally { finish() }
        }
    }

    private fun copy(inp: InputStream, out: OutputStream) {
        val buf = ByteArray(16384)
        while (true) {
            val n = inp.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
            out.flush()
        }
    }

    private fun handleUdpAssociate(client: Socket, inp: InputStream, out: OutputStream) {
        ensureUdpSocket()
        val udp = udpSocket!!
        reply(out, 0x00, "127.0.0.1", udp.localPort)
        // Koneksi kontrol TCP menahan asosiasi; blokir sampai klien menutup.
        try {
            val buf = ByteArray(64)
            while (inp.read(buf) >= 0) { /* buang */ }
        } catch (e: Exception) { /* abaikan */ }
        try { client.close() } catch (e: Exception) { /* abaikan */ }
    }

    @Synchronized
    private fun ensureUdpSocket() {
        if (udpSocket != null) return
        val udp = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        udpSocket = udp
        thread(name = "tk-xray-udp", isDaemon = true) {
            val buf = ByteArray(65535)
            while (alive) {
                val packet = DatagramPacket(buf, buf.size)
                try {
                    udp.receive(packet)
                } catch (e: Exception) {
                    break
                }
                try {
                    handleUdpPacket(udp, packet)
                } catch (e: Exception) {
                    // paket rusak diabaikan
                }
            }
        }
    }

    private fun handleUdpPacket(udp: DatagramSocket, packet: DatagramPacket) {
        val data = packet.data
        val len = packet.length
        if (len < 4 || data[0].toInt() != 0 || data[1].toInt() != 0 || data[2].toInt() != 0) return
        udpClientAddr = InetSocketAddress(packet.address, packet.port)
        var off = 3
        val atyp = data[off++].toInt() and 0xFF
        val host: String
        when (atyp) {
            1 -> {
                host = (0..3).joinToString(".") { (data[off + it].toInt() and 0xFF).toString() }
                off += 4
            }
            3 -> {
                val l = data[off++].toInt() and 0xFF
                host = String(data, off, l, Charsets.UTF_8)
                off += l
            }
            4 -> {
                host = Addr.formatIpv6(data.copyOfRange(off, off + 16))
                off += 16
            }
            else -> return
        }
        if (len < off + 2) return
        val port = ((data[off].toInt() and 0xFF) shl 8) or (data[off + 1].toInt() and 0xFF)
        off += 2
        val payload = data.copyOfRange(off, len)
        val key = "$host:$port"
        val session = udpSessions.getOrPut(key) {
            proto.openUdp(host, port) { replyPayload ->
                sendUdpReply(host, port, replyPayload)
            }
        }
        session.send(payload)
    }

    private fun sendUdpReply(srcHost: String, srcPort: Int, payload: ByteArray) {
        val udp = udpSocket ?: return
        val clientAddr = udpClientAddr ?: return
        val srcIp = Addr.parseIpv4(srcHost) ?: return // balasan hanya untuk tujuan IPv4 (jalur TUN IPv4)
        val head = ByteArray(10)
        head[3] = 1
        System.arraycopy(srcIp, 0, head, 4, 4)
        head[8] = (srcPort shr 8).toByte()
        head[9] = (srcPort and 0xFF).toByte()
        val pkt = head + payload
        try {
            udp.send(DatagramPacket(pkt, pkt.size, clientAddr))
        } catch (e: Exception) { /* abaikan */ }
    }

    companion object {
        const val PORT = 11082
    }
}
