package id.tunnelku.xray

import id.tunnelku.model.SshProfile
import id.tunnelku.vpn.DuplexStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.security.SecureRandom
import kotlin.concurrent.thread

/**
 * Shadowsocks AEAD (SIP004): kunci master EVP_BytesToKey(MD5), subkunci
 * HKDF-SHA1("ss-subkey"), stream = [salt][chunk AEAD], UDP = [salt][paket AEAD].
 * Cipher: aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305, none.
 */
class SsProto(
    private val profile: SshProfile,
    private val dialer: XrayDialer,
    private val random: SecureRandom = SecureRandom(),
) : XrayProto {

    enum class CipherKind { AES_GCM, CHACHA_IETF, XCHACHA, NONE }

    private val kind: CipherKind
    private val keyLen: Int
    private val saltLen: Int

    init {
        when (profile.xrayMethod.lowercase()) {
            "aes-128-gcm" -> { kind = CipherKind.AES_GCM; keyLen = 16; saltLen = 16 }
            "aes-256-gcm" -> { kind = CipherKind.AES_GCM; keyLen = 32; saltLen = 32 }
            "chacha20-ietf-poly1305", "chacha20-poly1305" -> { kind = CipherKind.CHACHA_IETF; keyLen = 32; saltLen = 32 }
            "xchacha20-ietf-poly1305" -> { kind = CipherKind.XCHACHA; keyLen = 32; saltLen = 32 }
            "none" -> { kind = CipherKind.NONE; keyLen = 0; saltLen = 0 }
            else -> throw IllegalStateException(
                "Method Shadowsocks tidak didukung klien Kotlin: ${profile.xrayMethod} " +
                    "(pakai aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305 / xchacha20-ietf-poly1305)",
            )
        }
    }

    private val masterKey: ByteArray =
        if (keyLen > 0) Crypto.evpBytesToKey(profile.xrayPassword.toByteArray(Charsets.UTF_8), keyLen) else ByteArray(0)

    private fun subkey(salt: ByteArray): ByteArray =
        Crypto.hkdfSha1(masterKey, salt, "ss-subkey".toByteArray(Charsets.US_ASCII), keyLen)

    /** AEAD satu arah dengan nonce penghitung little-endian (dimulai 0). */
    private inner class AeadStream(private val subkey: ByteArray) {
        private val nonce = ByteArray(if (kind == CipherKind.XCHACHA) 24 else 12)

        private fun nextNonce(): ByteArray {
            val n = nonce.copyOf()
            var i = 0
            while (true) {
                nonce[i] = (nonce[i] + 1).toByte()
                if (nonce[i].toInt() != 0) break
                i++
            }
            return n
        }

        fun seal(data: ByteArray): ByteArray {
            val n = nextNonce()
            return when (kind) {
                CipherKind.AES_GCM -> Crypto.aesGcmSeal(subkey, n, data)
                CipherKind.CHACHA_IETF -> ChaCha.sealIetf(subkey, n, data)
                CipherKind.XCHACHA -> ChaCha.sealX(subkey, n, data)
                CipherKind.NONE -> data
            }
        }

        fun open(data: ByteArray): ByteArray {
            val n = nextNonce()
            return when (kind) {
                CipherKind.AES_GCM -> Crypto.aesGcmOpen(subkey, n, data)
                CipherKind.CHACHA_IETF -> ChaCha.openIetf(subkey, n, data)
                CipherKind.XCHACHA -> ChaCha.openX(subkey, n, data)
                CipherKind.NONE -> data
            }
        }
    }

    override fun openTcp(host: String, port: Int): DuplexStream {
        val s = dialer.dialServer()
        val outCipher: AeadStream
        val header = Addr.writeAddrFirst(host, port)
        try {
            if (kind == CipherKind.NONE) {
                s.output.write(header)
                outCipher = AeadStream(ByteArray(0))
            } else {
                val salt = ByteArray(saltLen)
                random.nextBytes(salt)
                outCipher = AeadStream(subkey(salt))
                s.output.write(salt)
                // header tujuan = potongan data pertama (ikut terenkripsi sebagai chunk)
                writeChunk(s.output, outCipher, header)
            }
            s.output.flush()
        } catch (e: Exception) {
            s.close()
            throw e
        }
        val inStream = object : InputStream() {
            private var inCipher: AeadStream? = null
            private var cur: ByteArray = ByteArray(0)
            private var pos = 0
            private var eof = false

            private fun ensureCipher() {
                if (inCipher == null) {
                    if (kind == CipherKind.NONE) {
                        inCipher = AeadStream(ByteArray(0))
                    } else {
                        val salt = Addr.readN(s.input, saltLen)
                        inCipher = AeadStream(subkey(salt))
                    }
                }
            }

            override fun read(): Int {
                val b = ByteArray(1)
                val n = read(b, 0, 1)
                return if (n < 0) -1 else b[0].toInt() and 0xFF
            }

            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (len == 0) return 0
                while (pos >= cur.size) {
                    if (eof) return -1
                    ensureCipher()
                    val chunk = readChunk(s.input, inCipher!!) ?: run {
                        eof = true
                        return -1
                    }
                    cur = chunk
                    pos = 0
                }
                val take = minOf(len, cur.size - pos)
                System.arraycopy(cur, pos, b, off, take)
                pos += take
                return take
            }

            override fun close() = s.close()
        }
        val outStream = object : OutputStream() {
            override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)
            override fun write(b: ByteArray, off: Int, len: Int) {
                if (kind == CipherKind.NONE) {
                    s.output.write(b, off, len)
                    return
                }
                var i = off
                var remaining = len
                while (remaining > 0) {
                    val take = minOf(8192, remaining)
                    writeChunk(s.output, outCipher, b.copyOfRange(i, i + take))
                    i += take; remaining -= take
                }
            }

            override fun flush() = s.output.flush()
            override fun close() {
                try { s.output.flush() } catch (e: Exception) { /* abaikan */ }
            }
        }
        return simpleStream(inStream, outStream) { s.close() }
    }

    private fun writeChunk(out: OutputStream, cipher: AeadStream, payload: ByteArray) {
        val lenSealed = cipher.seal(byteArrayOf((payload.size shr 8).toByte(), (payload.size and 0xFF).toByte()))
        val paySealed = cipher.seal(payload)
        synchronized(out) {
            out.write(lenSealed)
            out.write(paySealed)
        }
    }

    private fun readChunk(inp: InputStream, cipher: AeadStream): ByteArray? {
        val lenSealed = try {
            Addr.readN(inp, 2 + 16)
        } catch (e: Exception) {
            return null
        }
        val lenBytes = cipher.open(lenSealed)
        val len = ((lenBytes[0].toInt() and 0xFF) shl 8) or (lenBytes[1].toInt() and 0xFF)
        if (len > 0xFFFF) return null
        val paySealed = Addr.readN(inp, len + 16)
        return cipher.open(paySealed)
    }

    override fun openUdp(host: String, port: Int, onReply: (ByteArray) -> Unit): UdpSession {
        val udp = dialer.dialUdpSocket()
        val alive = java.util.concurrent.atomic.AtomicBoolean(true)
        thread(name = "tk-ss-udp", isDaemon = true) {
            val buf = ByteArray(65535)
            while (alive.get()) {
                val packet = DatagramPacket(buf, buf.size)
                try {
                    udp.receive(packet)
                } catch (e: Exception) {
                    break
                }
                try {
                    val data = buf.copyOf(packet.length)
                    val payload = decodeUdpPacket(data) ?: continue
                    onReply(payload)
                } catch (e: Exception) {
                    // paket rusak diabaikan
                }
            }
        }
        return object : UdpSession {
            override fun send(payload: ByteArray) {
                val packet = encodeUdpPacket(host, port, payload)
                try {
                    udp.send(DatagramPacket(packet, packet.size))
                } catch (e: Exception) {
                    // abaikan
                }
            }

            override fun close() {
                alive.set(false)
                try { udp.close() } catch (e: Exception) { /* abaikan */ }
            }
        }
    }

    fun encodeUdpPacket(host: String, port: Int, payload: ByteArray): ByteArray {
        val plain = Addr.writeAddrFirst(host, port) + payload
        if (kind == CipherKind.NONE) return plain
        val salt = ByteArray(saltLen)
        random.nextBytes(salt)
        val cipher = AeadStream(subkey(salt))
        return salt + cipher.seal(plain)
    }

    fun decodeUdpPacket(data: ByteArray): ByteArray? {
        if (kind == CipherKind.NONE) {
            return stripAddr(data)
        }
        if (data.size <= saltLen) return null
        val salt = data.copyOfRange(0, saltLen)
        val cipher = AeadStream(subkey(salt))
        val plain = cipher.open(data.copyOfRange(saltLen, data.size))
        return stripAddr(plain)
    }

    private fun stripAddr(plain: ByteArray): ByteArray? {
        if (plain.isEmpty()) return null
        var off = 1
        when (plain[0].toInt() and 0x0F) {
            1 -> off += 4
            3 -> {
                if (plain.size < 2) return null
                off += 1 + (plain[1].toInt() and 0xFF)
            }
            4 -> off += 16
            else -> return null
        }
        off += 2 // port
        if (plain.size < off) return null
        return plain.copyOfRange(off, plain.size)
    }
}
