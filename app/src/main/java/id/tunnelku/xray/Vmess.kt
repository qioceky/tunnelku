package id.tunnelku.xray

import id.tunnelku.model.SshProfile
import id.tunnelku.vpn.DuplexStream
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import java.util.zip.CRC32
import kotlin.concurrent.thread

/**
 * VMess AEAD (alterId 0) — port setia dari xray-core v1.8.3
 * (proxy/vmess/aead + proxy/vmess/encoding): header ter-seal AES-GCM dengan
 * KDF khas VMess, badan = chunk terenkripsi dengan ukuran ter-masking SHAKE128.
 */
class VmessProto(
    private val profile: SshProfile,
    private val dialer: XrayDialer,
    private val random: SecureRandom = SecureRandom(),
    private val timeSec: () -> Long = { System.currentTimeMillis() / 1000 },
    /** Mode legacy (alterId > 0): header HmacMD5 + AES-CFB ala VMess lama XVEON. */
    private val legacy: Boolean = false,
) : XrayProto {

    private val uuid: ByteArray = Crypto.parseUuid(profile.xrayUuid)
    private val cmdKey: ByteArray = Crypto.md5(uuid + CMD_KEY_SALT)

    val securityType: Int = when (profile.xrayVmessSecurity.lowercase()) {
        "aes-128-gcm" -> 3
        "chacha20-poly1305" -> 4
        "none", "zero" -> 5
        else -> 3 // auto → AES-128-GCM
    }

    private inner class Session(
        val reqKey: ByteArray,
        val reqIV: ByteArray,
        val respV: Byte,
    ) {
        val respKey: ByteArray = if (legacy) Crypto.md5(reqKey) else Crypto.sha256(reqKey).copyOf(16)
        val respIV: ByteArray = if (legacy) Crypto.md5(reqIV) else Crypto.sha256(reqIV).copyOf(16)

        fun headerBytes(command: Int, host: String, port: Int): ByteArray {
            if (legacy) return legacyHeaderBytes(command, host, port)
            return sealHeader(cmdKey, plainHeader(command, host, port), timeSec(), random)
        }

        /** Header legacy: [auth HmacMD5 16B][plaintext header terenkripsi AES-CFB]. */
        private fun legacyHeaderBytes(command: Int, host: String, port: Int): ByteArray {
            val ts = timeSec()
            val tsBytes = ByteArray(8) { i -> (ts shr (56 - 8 * i)).toByte() }
            val auth = Crypto.hmac("HmacMD5", uuid, tsBytes)
            val key = Crypto.md5(uuid + CMD_KEY_SALT)
            val ivSeed = ByteArray(32) { i -> tsBytes[i % 8] }
            val iv = Crypto.md5(ivSeed)
            val enc = Crypto.aesCfb(key, iv, plainHeader(command, host, port), encrypt = true)
            return auth + enc
        }

        fun plainHeader(command: Int, host: String, port: Int): ByteArray {
            val paddingLen = random.nextInt(16)
            val plain = ArrayList<Byte>()
            plain.add(1) // versi
            reqIV.forEach { plain.add(it) }
            reqKey.forEach { plain.add(it) }
            plain.add(respV)
            plain.add(OPTION_BYTE)
            plain.add(((paddingLen shl 4) or securityType).toByte())
            plain.add(0)
            plain.add(command.toByte())
            Addr.writePortFirst(host, port).forEach { plain.add(it) }
            val padding = ByteArray(paddingLen)
            random.nextBytes(padding)
            padding.forEach { plain.add(it) }
            val body = plain.toByteArray()
            val fnv = Crypto.fnv1a32(body)
            val full = body + byteArrayOf(
                (fnv ushr 24).toByte(), (fnv ushr 16).toByte(), (fnv ushr 8).toByte(), fnv.toByte(),
            )
            return full
        }

        fun readResponseHeader(inp: InputStream) {
            if (legacy) {
                // Blok 4 byte AES-CFB: byte0 = respV, byte3 = jumlah byte ekstra yang dilewati.
                val block = Addr.readN(inp, 4)
                val plain = Crypto.aesCfb(respKey, respIV, block, encrypt = false)
                if (plain[0] != respV) {
                    throw IllegalStateException("VMess legacy: byte verifikasi respons tidak cocok")
                }
                val skip = plain[3].toInt() and 0xFF
                if (skip > 0) Addr.readN(inp, skip)
                return
            }
            val lenBlock = Addr.readN(inp, 18)
            val lenKey = VmessKdf.kdf16Str(respKey, SALT_RESP_LEN_KEY)
            val lenIV = VmessKdf.kdfStr(respIV, SALT_RESP_LEN_IV).copyOf(12)
            val lenBytes = Crypto.aesGcmOpen(lenKey, lenIV, lenBlock)
            val respLen = ((lenBytes[0].toInt() and 0xFF) shl 8) or (lenBytes[1].toInt() and 0xFF)
            val payloadBlock = Addr.readN(inp, respLen + 16)
            val payKey = VmessKdf.kdf16Str(respKey, SALT_RESP_PAY_KEY)
            val payIV = VmessKdf.kdfStr(respIV, SALT_RESP_PAY_IV).copyOf(12)
            val payload = Crypto.aesGcmOpen(payKey, payIV, payloadBlock)
            if (payload.isEmpty() || payload[0] != respV) {
                throw IllegalStateException("VMess: byte verifikasi respons tidak cocok")
            }
        }

        fun writer(out: OutputStream) = ChunkWriter(out, reqKey, reqIV, securityType)
        fun reader(inp: InputStream) = ChunkReader(inp, respKey, respIV, securityType)
    }

    private fun newSession(): Session {
        val reqKey = ByteArray(16); random.nextBytes(reqKey)
        val reqIV = ByteArray(16); random.nextBytes(reqIV)
        val v = ByteArray(1); random.nextBytes(v)
        return Session(reqKey, reqIV, v[0])
    }

    override fun openTcp(host: String, port: Int): DuplexStream {
        val s = dialer.dialServer()
        val session = newSession()
        try {
            s.output.write(session.headerBytes(1, host, port))
            s.output.flush()
        } catch (e: Exception) {
            s.close()
            throw e
        }
        val chunkWriter = session.writer(s.output)
        val outStream = object : OutputStream() {
            private val buf = ByteArray(8192)
            private var n = 0
            override fun write(b: Int) {
                buf[n++] = b.toByte()
                if (n == buf.size) flushFull()
            }

            override fun write(b: ByteArray, off: Int, len: Int) {
                var i = off
                var remaining = len
                while (remaining > 0) {
                    val take = minOf(buf.size - n, remaining)
                    System.arraycopy(b, i, buf, n, take)
                    n += take; i += take; remaining -= take
                    if (n == buf.size) flushFull()
                }
            }

            private fun flushFull() {
                if (n > 0) {
                    chunkWriter.writeChunk(buf, 0, n)
                    n = 0
                }
            }

            override fun flush() {
                flushFull()
                s.output.flush()
            }

            override fun close() {
                try { flushFull(); chunkWriter.writeTermination() } catch (e: Exception) { /* abaikan */ }
                try { s.output.flush() } catch (e: Exception) { /* abaikan */ }
            }
        }
        val lazyIn = LazyHeaderInputStream(s.input) { session.readResponseHeader(s.input) }
        val inStream = ChunkInputStream({ session.reader(lazyIn) }, lazyIn)
        return simpleStream(inStream, outStream) {
            try { outStream.close() } catch (e: Exception) { /* abaikan */ }
            s.close()
        }
    }

    override fun openUdp(host: String, port: Int, onReply: (String, Int, ByteArray) -> Unit): UdpSession {
        val s = dialer.dialServer()
        val session = newSession()
        s.output.write(session.headerBytes(2, host, port))
        s.output.flush()
        val writer = session.writer(s.output)
        val alive = java.util.concurrent.atomic.AtomicBoolean(true)
        thread(name = "tk-vmess-udp", isDaemon = true) {
            try {
                session.readResponseHeader(s.input)
                val reader = session.reader(s.input)
                while (alive.get()) {
                    val chunk = reader.readChunk() ?: break
                    if (chunk.isNotEmpty()) onReply(host, port, chunk)
                }
            } catch (e: Exception) {
                // sesi selesai
            }
        }
        return object : UdpSession {
            override fun send(payload: ByteArray) {
                synchronized(writer) { writer.writePacket(payload) }
                s.output.flush()
            }

            override fun close() {
                alive.set(false)
                s.close()
            }
        }
    }

    /** Penulis chunk badan VMess: [ukuran ter-masking 2B][payload ter-seal]. */
    class ChunkWriter(
        private val out: OutputStream,
        key: ByteArray,
        iv: ByteArray,
        private val security: Int,
    ) {
        private val key = key.copyOf()
        private val iv = iv.copyOf()
        private val shake = Shake128().apply { write(iv) }
        private var counter = 0

        private fun nextNonce(): ByteArray {
            val nonce = iv.copyOf(12)
            nonce[0] = (counter shr 8).toByte()
            nonce[1] = (counter and 0xFF).toByte()
            counter++
            return nonce
        }

        private fun seal(payload: ByteArray, off: Int, len: Int): ByteArray {
            val data = payload.copyOfRange(off, off + len)
            return when (security) {
                3 -> Crypto.aesGcmSeal(key, nextNonce(), data)
                4 -> ChaCha.sealIetf(chachaKey(key), nextNonce(), data)
                else -> data // NONE
            }
        }

        @Synchronized
        fun writeChunk(data: ByteArray, off: Int, len: Int) {
            var i = off
            var remaining = len
            while (remaining > 0) {
                val take = minOf(8192, remaining)
                writeOneChunk(data, i, take)
                i += take; remaining -= take
            }
        }

        private fun writeOneChunk(data: ByteArray, off: Int, len: Int) {
            val sealed = seal(data, off, len)
            val mask = shake.readBytes(2)
            val maskedSize = sealed.size xor (((mask[0].toInt() and 0xFF) shl 8) or (mask[1].toInt() and 0xFF))
            synchronized(out) {
                out.write(byteArrayOf((maskedSize shr 8).toByte(), (maskedSize and 0xFF).toByte()))
                out.write(sealed)
                out.flush()
            }
        }

        /** Satu datagram = satu chunk utuh (mode paket UDP, tanpa pemecahan). */
        @Synchronized
        fun writePacket(data: ByteArray) {
            writeOneChunk(data, 0, data.size)
        }

        @Synchronized
        fun writeTermination() {
            writeOneChunk(ByteArray(0), 0, 0)
        }
    }

    /** Pembaca chunk badan VMess; null = chunk terminasi / EOF. */
    class ChunkReader(
        private val inp: InputStream,
        key: ByteArray,
        iv: ByteArray,
        private val security: Int,
    ) {
        private val key = key.copyOf()
        private val iv = iv.copyOf()
        private val shake = Shake128().apply { write(iv) }
        private var counter = 0

        private fun nextNonce(): ByteArray {
            val nonce = iv.copyOf(12)
            nonce[0] = (counter shr 8).toByte()
            nonce[1] = (counter and 0xFF).toByte()
            counter++
            return nonce
        }

        private val overhead: Int get() = if (security == 5) 0 else 16

        fun readChunk(): ByteArray? {
            val sizeBytes = try {
                Addr.readN(inp, 2)
            } catch (e: Exception) {
                return null
            }
            val mask = shake.readBytes(2)
            val masked = ((sizeBytes[0].toInt() and 0xFF) shl 8) or (sizeBytes[1].toInt() and 0xFF)
            val sealedLen = masked xor (((mask[0].toInt() and 0xFF) shl 8) or (mask[1].toInt() and 0xFF))
            if (sealedLen < overhead) return null
            val sealed = Addr.readN(inp, sealedLen)
            val plain = when (security) {
                3 -> Crypto.aesGcmOpen(key, nextNonce(), sealed)
                4 -> ChaCha.openIetf(chachaKey(key), nextNonce(), sealed)
                else -> sealed
            }
            if (plain.isEmpty()) return null // chunk terminasi
            return plain
        }
    }

    /** InputStream di atas ChunkReader (mode stream/TCP). */
    class ChunkInputStream(
        private val readerFactory: () -> ChunkReader,
        private val headerStream: InputStream,
    ) : InputStream() {
        private var reader: ChunkReader? = null
        private var cur: ByteArray = ByteArray(0)
        private var pos = 0
        private var eof = false

        private fun ensureReader(): ChunkReader {
            if (reader == null) {
                // Sentuh headerStream agar header respons terbaca lebih dulu.
                reader = readerFactory()
            }
            return reader!!
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
                val chunk = ensureReader().readChunk()
                if (chunk == null) {
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

        override fun close() {
            try { headerStream.close() } catch (e: Exception) { /* abaikan */ }
        }
    }

    companion object {
        private val CMD_KEY_SALT = "c48619fe-8f02-49e0-b9e9-edf763e17e21".toByteArray(Charsets.US_ASCII)
        private const val OPTION_BYTE: Byte = 0x05 // ChunkStream | ChunkMasking
        private const val SALT_RESP_LEN_KEY = "AEAD Resp Header Len Key"
        private const val SALT_RESP_LEN_IV = "AEAD Resp Header Len IV"
        private const val SALT_RESP_PAY_KEY = "AEAD Resp Header Key"
        private const val SALT_RESP_PAY_IV = "AEAD Resp Header IV"

        /** Kunci ChaCha VMess: MD5(k) || MD5(MD5(k)) (GenerateChacha20Poly1305Key). */
        fun chachaKey(key16: ByteArray): ByteArray {
            val first = Crypto.md5(key16)
            val second = Crypto.md5(first)
            return first + second
        }

        /** AuthID VMess: AES-ECB( KDF16(cmdKey,"AES Auth ID Encryption"), time||rand4||crc32 ). */
        fun createAuthId(cmdKey: ByteArray, time: Long, rand4: ByteArray): ByteArray {
            val plain = ByteArray(16)
            for (i in 0..7) plain[i] = (time ushr (8 * (7 - i))).toByte()
            System.arraycopy(rand4, 0, plain, 8, 4)
            val crc = CRC32()
            crc.update(plain, 0, 12)
            val v = crc.value
            plain[12] = (v ushr 24).toByte(); plain[13] = (v ushr 16).toByte()
            plain[14] = (v ushr 8).toByte(); plain[15] = v.toByte()
            val key = VmessKdf.kdf16Str(cmdKey, "AES Auth ID Encryption")
            return Crypto.aesEcbEncryptBlock(key, plain)
        }

        /** Seal header VMess AEAD persis SealVMessAEADHeader xray (authID & nonce bisa disuntik untuk uji). */
        fun sealHeader(cmdKey: ByteArray, data: ByteArray, time: Long, random: SecureRandom): ByteArray {
            val rand4 = ByteArray(4); random.nextBytes(rand4)
            val authId = createAuthId(cmdKey, time, rand4)
            val connNonce = ByteArray(8); random.nextBytes(connNonce)
            return sealHeaderWith(cmdKey, data, authId, connNonce)
        }

        fun sealHeaderWith(cmdKey: ByteArray, data: ByteArray, authId: ByteArray, connNonce: ByteArray): ByteArray {
            val lenKey = VmessKdf.kdf16(cmdKey, "VMess Header AEAD Key_Length".toByteArray(), authId, connNonce)
            val lenIV = VmessKdf.kdf(cmdKey, "VMess Header AEAD Nonce_Length".toByteArray(), authId, connNonce).copyOf(12)
            val lenPlain = byteArrayOf((data.size shr 8).toByte(), (data.size and 0xFF).toByte())
            val lenSealed = Crypto.aesGcmSeal(lenKey, lenIV, lenPlain, authId)
            val payKey = VmessKdf.kdf16(cmdKey, "VMess Header AEAD Key".toByteArray(), authId, connNonce)
            val payIV = VmessKdf.kdf(cmdKey, "VMess Header AEAD Nonce".toByteArray(), authId, connNonce).copyOf(12)
            val paySealed = Crypto.aesGcmSeal(payKey, payIV, data, authId)
            return authId + lenSealed + connNonce + paySealed
        }
    }
}
