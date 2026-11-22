package id.tunnelku.vpn

import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

/** Satu aliran dupleks (TCP) yang dibuka lewat transport aktif. */
interface DuplexStream {
    val input: InputStream
    val output: OutputStream
    fun close()
}

/** Pembuka aliran TCP menuju (host, port) lewat jalur tunnel aktif. */
interface StreamTransport {
    fun openStream(host: String, port: Int): DuplexStream
}

/** Relay UDP: meneruskan datagram klien TUN ke tujuan dan memanggil balik onPacket untuk balasan. */
interface UdpRelay {
    val alive: Boolean
    fun send(clientIp: Int, clientPort: Int, dstIp: Int, dstPort: Int, payload: ByteArray, isDns: Boolean)
    fun close()
}

/** Transport lewat channel SSH (mode SSH & SlowDNS). */
class SshStreamTransport(private val ssh: SshTunnel) : StreamTransport {
    override fun openStream(host: String, port: Int): DuplexStream {
        val channel = ssh.openStream(host, port)
        return object : DuplexStream {
            override val input: InputStream get() = channel.inputStream
            override val output: OutputStream get() = channel.outputStream
            override fun close() {
                try { channel.disconnect() } catch (e: Exception) { /* abaikan */ }
            }
        }
    }
}

/** Transport lewat SOCKS5 lokal (mode UDP Custom — SOCKS5 disajikan mesin Go Hysteria). */
class SocksStreamTransport(private val socksPort: Int) : StreamTransport {
    override fun openStream(host: String, port: Int): DuplexStream {
        val socket = Socket()
        socket.soTimeout = 20_000
        socket.tcpNoDelay = true
        socket.connect(InetSocketAddress("127.0.0.1", socksPort), 10_000)
        try {
            socks5Connect(socket, host, port)
        } catch (e: Exception) {
            try { socket.close() } catch (ignored: Exception) { /* abaikan */ }
            throw e
        }
        socket.soTimeout = 0
        return object : DuplexStream {
            override val input: InputStream get() = socket.inputStream
            override val output: OutputStream get() = socket.outputStream
            override fun close() {
                try { socket.close() } catch (e: Exception) { /* abaikan */ }
            }
        }
    }

    companion object {
        /** Handshake SOCKS5 tanpa autentikasi + perintah CONNECT ke (host, port). */
        fun socks5Connect(socket: Socket, host: String, port: Int) {
            val out = socket.getOutputStream()
            val inp = socket.getInputStream()
            out.write(byteArrayOf(0x05, 0x01, 0x00)); out.flush()
            val greeting = ByteArray(2)
            readFully(inp, greeting)
            require(greeting[0].toInt() == 5 && greeting[1].toInt() == 0) { "SOCKS5 menolak (autentikasi)" }
            val ip = parseIpv4(host)
            val req: ByteArray
            if (ip != null) {
                req = ByteArray(4 + 4 + 2)
                req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x01
                System.arraycopy(ip, 0, req, 4, 4)
                req[8] = (port shr 8).toByte(); req[9] = (port and 0xFF).toByte()
            } else {
                val hb = host.toByteArray(Charsets.UTF_8)
                require(hb.size <= 255) { "Nama host terlalu panjang untuk SOCKS5" }
                req = ByteArray(4 + 1 + hb.size + 2)
                req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03
                req[4] = hb.size.toByte()
                System.arraycopy(hb, 0, req, 5, hb.size)
                req[5 + hb.size] = (port shr 8).toByte()
                req[6 + hb.size] = (port and 0xFF).toByte()
            }
            out.write(req); out.flush()
            val head = ByteArray(4)
            readFully(inp, head)
            require(head[0].toInt() == 5 && head[1].toInt() == 0) {
                "SOCKS5 CONNECT gagal (kode ${head[1]})"
            }
            val addrLen = when (head[3].toInt()) {
                0x01 -> 4
                0x04 -> 16
                0x03 -> {
                    val l = ByteArray(1); readFully(inp, l); l[0].toInt() and 0xFF
                }
                else -> 0
            }
            if (addrLen > 0) readFully(inp, ByteArray(addrLen))
            readFully(inp, ByteArray(2))
        }

        fun readFully(inp: InputStream, buf: ByteArray) {
            var off = 0
            while (off < buf.size) {
                val n = inp.read(buf, off, buf.size - off)
                if (n < 0) throw IllegalStateException("EOF dari SOCKS5")
                off += n
            }
        }

        fun parseIpv4(host: String): ByteArray? {
            val parts = host.split(".")
            if (parts.size != 4) return null
            val out = ByteArray(4)
            for (i in 0..3) {
                val v = parts[i].toIntOrNull() ?: return null
                if (v !in 0..255) return null
                out[i] = v.toByte()
            }
            return out
        }
    }
}

/**
 * Relay UDP lewat SOCKS5 UDP ASSOCIATE (mode UDP Custom).
 * Satu DatagramSocket ke relay; demux balasan memakai peta tujuan->klien
 * (klien terakhir yang mengirim ke tujuan itu), pola relay sederhana.
 */
class SocksUdpRelay(
    private val socksPort: Int,
    private val protect: (DatagramSocket) -> Boolean,
    private val onPacket: (srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int, payload: ByteArray) -> Unit,
    private val log: (String) -> Unit,
) : UdpRelay {
    @Volatile override var alive = true
        private set

    private var controlSocket: Socket? = null
    private var udpSocket: DatagramSocket? = null
    private var relayAddr: InetSocketAddress? = null
    private val dstToClient = ConcurrentHashMap<String, Pair<Int, Int>>()
    @Volatile private var started = false

    @Synchronized
    private fun ensureStarted(): Boolean {
        if (started) return alive
        started = true
        return try {
            val ctrl = Socket()
            ctrl.soTimeout = 15_000
            ctrl.connect(InetSocketAddress("127.0.0.1", socksPort), 10_000)
            val out = ctrl.getOutputStream()
            val inp = ctrl.getInputStream()
            out.write(byteArrayOf(0x05, 0x01, 0x00)); out.flush()
            val g = ByteArray(2)
            SocksStreamTransport.readFully(inp, g)
            require(g[0].toInt() == 5 && g[1].toInt() == 0) { "SOCKS5 menolak" }
            // UDP ASSOCIATE ke 0.0.0.0:0
            out.write(byteArrayOf(0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0)); out.flush()
            val head = ByteArray(4)
            SocksStreamTransport.readFully(inp, head)
            require(head[0].toInt() == 5 && head[1].toInt() == 0) { "UDP ASSOCIATE gagal (${head[1]})" }
            require(head[3].toInt() == 0x01) { "Alamat relay SOCKS bukan IPv4" }
            val ipB = ByteArray(4); SocksStreamTransport.readFully(inp, ipB)
            val portB = ByteArray(2); SocksStreamTransport.readFully(inp, portB)
            val relayIp = if (ipB.all { it.toInt() == 0 }) "127.0.0.1"
                else InetAddress.getByAddress(ipB).hostAddress
            val relayPort = ((portB[0].toInt() and 0xFF) shl 8) or (portB[1].toInt() and 0xFF)
            relayAddr = InetSocketAddress(relayIp, relayPort)
            controlSocket = ctrl
            val udp = DatagramSocket()
            protect(udp)
            udpSocket = udp
            thread(name = "tk-socksudp-r", isDaemon = true) { readLoop() }
            log("Relay UDP SOCKS5 aktif ($relayIp:$relayPort)")
            true
        } catch (e: Exception) {
            alive = false
            log("Relay UDP SOCKS5 gagal: ${e.message}")
            false
        }
    }

    override fun send(clientIp: Int, clientPort: Int, dstIp: Int, dstPort: Int, payload: ByteArray, isDns: Boolean) {
        if (!ensureStarted()) return
        val udp = udpSocket ?: return
        val relay = relayAddr ?: return
        dstToClient["$dstIp:$dstPort"] = clientIp to clientPort
        val pkt = ByteArray(10 + payload.size)
        pkt[0] = 0; pkt[1] = 0; pkt[2] = 0; pkt[3] = 0x01
        pkt[4] = (dstIp shr 24).toByte(); pkt[5] = (dstIp shr 16).toByte()
        pkt[6] = (dstIp shr 8).toByte(); pkt[7] = dstIp.toByte()
        pkt[8] = (dstPort shr 8).toByte(); pkt[9] = (dstPort and 0xFF).toByte()
        System.arraycopy(payload, 0, pkt, 10, payload.size)
        try {
            udp.send(DatagramPacket(pkt, pkt.size, relay))
        } catch (e: Exception) {
            alive = false
        }
    }

    private fun readLoop() {
        val udp = udpSocket ?: return
        val buf = ByteArray(65535)
        while (alive) {
            val packet = DatagramPacket(buf, buf.size)
            try {
                udp.receive(packet)
            } catch (e: Exception) {
                break
            }
            val data = packet.data
            val len = packet.length
            if (len < 10 || data[0].toInt() != 0 || data[3].toInt() != 0x01) continue
            val srcIp = ((data[4].toInt() and 0xFF) shl 24) or ((data[5].toInt() and 0xFF) shl 16) or
                ((data[6].toInt() and 0xFF) shl 8) or (data[7].toInt() and 0xFF)
            val srcPort = ((data[8].toInt() and 0xFF) shl 8) or (data[9].toInt() and 0xFF)
            val client = dstToClient["$srcIp:$srcPort"] ?: continue
            val payload = data.copyOfRange(10, len)
            onPacket(srcIp, srcPort, client.first, client.second, payload)
        }
    }

    override fun close() {
        alive = false
        try { udpSocket?.close() } catch (e: Exception) { /* abaikan */ }
        try { controlSocket?.close() } catch (e: Exception) { /* abaikan */ }
    }
}

/** Penyedia relay UDPGW malas (lazy) dengan jeda coba-ulang 30 detik. */
class UdpGwRelayProvider(
    private val ssh: SshTunnel,
    private val host: String,
    private val port: Int,
    private val emit: (srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int, payload: ByteArray) -> Unit,
    private val log: (String) -> Unit,
) {
    @Volatile private var client: UdpGwClient? = null
    @Volatile private var nextTry = 0L

    fun get(): UdpRelay? {
        client?.let { if (it.alive) return Relay(it) }
        val now = System.currentTimeMillis()
        if (now < nextTry) return null
        nextTry = now + 30_000
        return try {
            val channel = ssh.openStream(host, port)
            val c = UdpGwClient(
                channel.outputStream, channel.inputStream,
                onPacket = emit,
                onDead = { reason ->
                    log("UDPGW putus: $reason — UDP jatuh ke mode DNS-saja")
                    client = null
                },
                log = log,
            )
            c.start()
            client = c
            Relay(c)
        } catch (e: Exception) {
            log("UDPGW tidak tersedia ($host:$port): ${e.message} — UDP mode DNS-saja")
            null
        }
    }

    fun close() {
        try { client?.close() } catch (e: Exception) { /* abaikan */ }
        client = null
    }

    private class Relay(private val c: UdpGwClient) : UdpRelay {
        override val alive: Boolean get() = c.alive
        override fun send(clientIp: Int, clientPort: Int, dstIp: Int, dstPort: Int, payload: ByteArray, isDns: Boolean) =
            c.send(clientIp, clientPort, dstIp, dstPort, payload, isDns)
        override fun close() = c.close()
    }
}
