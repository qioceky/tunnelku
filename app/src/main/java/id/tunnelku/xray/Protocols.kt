package id.tunnelku.xray

import id.tunnelku.model.SshProfile
import id.tunnelku.vpn.DuplexStream
import java.io.InputStream
import java.io.OutputStream
import kotlin.concurrent.thread

/** Sesi UDP satu tujuan lewat protokol Xray. */
interface UdpSession {
    fun send(payload: ByteArray)
    fun close()
}

/** Klien protokol Xray (di atas transport yang sudah terhubung ke server). */
interface XrayProto {
    fun openTcp(host: String, port: Int): DuplexStream
    fun openUdp(host: String, port: Int, onReply: (srcHost: String, srcPort: Int, payload: ByteArray) -> Unit): UdpSession
}

/** InputStream yang menjalankan [onFirstRead] sekali sebelum bacaan pertama (header respons malas). */
class LazyHeaderInputStream(
    private val base: InputStream,
    private val onFirstRead: () -> Unit,
) : InputStream() {
    @Volatile private var done = false
    private fun ensure() {
        if (!done) {
            synchronized(this) {
                if (!done) {
                    onFirstRead()
                    done = true
                }
            }
        }
    }

    override fun read(): Int {
        ensure()
        return base.read()
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        ensure()
        return base.read(b, off, len)
    }

    override fun available(): Int = base.available()
    override fun close() = base.close()
}

fun simpleStream(input: InputStream, output: OutputStream, onClose: () -> Unit): DuplexStream =
    object : DuplexStream {
        override val input: InputStream = input
        override val output: OutputStream = output
        override fun close() = onClose()
    }

/** VLESS (xray-core v1.8.3 encoding): header + addons, UDP = paket berprefiks panjang 2 byte. */
class VlessProto(
    private val profile: SshProfile,
    private val dialer: XrayDialer,
) : XrayProto {
    private val uuid: ByteArray = Crypto.parseUuid(profile.xrayUuid)

    private fun header(command: Int, host: String, port: Int): ByteArray {
        // Flow (termasuk xtls-rprx-vision) diabaikan diam-diam seperti XVEON:
        // addons selalu kosong, koneksi berjalan sebagai VLESS polos.
        val out = ArrayList<Byte>()
        out.add(0) // versi
        uuid.forEach { out.add(it) }
        out.add(0) // addons: hanya XRV yang membawa addons protobuf; selain itu panjang 0
        out.add(command.toByte())
        Addr.writePortFirst(host, port).forEach { out.add(it) }
        return out.toByteArray()
    }

    private fun readResponseHeader(inp: InputStream) {
        val v = inp.read()
        if (v != 0) throw IllegalStateException("VLESS: versi respons tak terduga: $v")
        val len = inp.read()
        if (len < 0) throw IllegalStateException("VLESS: EOF header respons")
        if (len > 0) Addr.readN(inp, len)
    }

    override fun openTcp(host: String, port: Int): DuplexStream {
        val s = dialer.dialServer()
        try {
            s.output.write(header(1, host, port))
            s.output.flush()
        } catch (e: Exception) {
            s.close()
            throw e
        }
        val lazyIn = LazyHeaderInputStream(s.input) { readResponseHeader(s.input) }
        return simpleStream(lazyIn, s.output) { s.close() }
    }

    override fun openUdp(host: String, port: Int, onReply: (srcHost: String, srcPort: Int, payload: ByteArray) -> Unit): UdpSession {
        val s = dialer.dialServer()
        s.output.write(header(2, host, port))
        s.output.flush()
        val alive = java.util.concurrent.atomic.AtomicBoolean(true)
        thread(name = "tk-vless-udp", isDaemon = true) {
            try {
                readResponseHeader(s.input)
                while (alive.get()) {
                    val lb = Addr.readN(s.input, 2)
                    val len = ((lb[0].toInt() and 0xFF) shl 8) or (lb[1].toInt() and 0xFF)
                    if (len == 0) continue
                    onReply(host, port, Addr.readN(s.input, len))
                }
            } catch (e: Exception) {
                // sesi selesai
            }
        }
        return object : UdpSession {
            override fun send(payload: ByteArray) {
                synchronized(s.output) {
                    s.output.write(byteArrayOf((payload.size shr 8).toByte(), (payload.size and 0xFF).toByte()))
                    s.output.write(payload)
                    s.output.flush()
                }
            }

            override fun close() {
                alive.set(false)
                s.close()
            }
        }
    }
}

/** Trojan: kata sandi = hex(SHA-224(password)); UDP berbingkai alamat per paket. */
class TrojanProto(
    private val profile: SshProfile,
    private val dialer: XrayDialer,
) : XrayProto {
    private val keyHex: ByteArray =
        Crypto.bytesToHex(Crypto.sha224(profile.xrayPassword.toByteArray(Charsets.UTF_8)))
            .toByteArray(Charsets.US_ASCII)
    private val crlf = byteArrayOf(0x0D, 0x0A)

    private fun header(command: Int, host: String, port: Int): ByteArray =
        keyHex + crlf + byteArrayOf(command.toByte()) + Addr.writeAddrFirst(host, port) + crlf

    override fun openTcp(host: String, port: Int): DuplexStream {
        val s = dialer.dialServer()
        try {
            s.output.write(header(0x01, host, port))
            s.output.flush()
        } catch (e: Exception) {
            s.close()
            throw e
        }
        return s
    }

    override fun openUdp(host: String, port: Int, onReply: (srcHost: String, srcPort: Int, payload: ByteArray) -> Unit): UdpSession {
        val s = dialer.dialServer()
        s.output.write(header(0x03, host, port))
        s.output.flush()
        val alive = java.util.concurrent.atomic.AtomicBoolean(true)
        thread(name = "tk-trojan-udp", isDaemon = true) {
            try {
                while (alive.get()) {
                    val (rHost, rPort) = Addr.readAddrFirst(s.input, domainType = 3, ipv6Type = 4)
                    val lb = Addr.readN(s.input, 2)
                    val len = ((lb[0].toInt() and 0xFF) shl 8) or (lb[1].toInt() and 0xFF)
                    Addr.readN(s.input, 2) // CRLF
                    onReply(rHost, rPort, Addr.readN(s.input, len))
                }
            } catch (e: Exception) {
                // sesi selesai
            }
        }
        return object : UdpSession {
            override fun send(payload: ByteArray) {
                synchronized(s.output) {
                    s.output.write(Addr.writeAddrFirst(host, port))
                    s.output.write(byteArrayOf((payload.size shr 8).toByte(), (payload.size and 0xFF).toByte()))
                    s.output.write(crlf)
                    s.output.write(payload)
                    s.output.flush()
                }
            }

            override fun close() {
                alive.set(false)
                s.close()
            }
        }
    }
}
