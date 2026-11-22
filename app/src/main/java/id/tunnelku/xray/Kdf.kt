package id.tunnelku.xray

/**
 * Simulasi persis crypto/hmac Go untuk KDF VMess AEAD.
 *
 * KDF xray-core dibangun dari HMAC yang inner & outer-nya BERBAGI objek hash
 * level sebelumnya (trik hash2 di proxy/vmess/aead/kdf.go), jadi hasilnya
 * BUKAN HMAC bersarang biasa. Kelas-kelas di sini meniru semantik Go
 * (New/Write/Sum/Reset + marshaling state) satu-satu; sudah dicocokkan
 * byte-for-byte dengan keluaran aead.KDF asli untuk path 0..3 elemen.
 */
private interface GoHash {
    fun write(b: ByteArray)
    fun sum(prefix: ByteArray): ByteArray
    fun reset()
    fun marshalable(): Boolean
    fun snapshot(): GoHash
    fun restoreFrom(snap: GoHash)
}

private class ShaHash(private var state: Sha256Pure = Sha256Pure()) : GoHash {
    override fun write(b: ByteArray) = state.write(b)
    override fun sum(prefix: ByteArray): ByteArray = prefix + state.digest()
    override fun reset() = state.reset()
    override fun marshalable() = true
    override fun snapshot(): GoHash = ShaHash(state.copy())
    override fun restoreFrom(snap: GoHash) {
        state = (snap as ShaHash).state.copy()
    }
}

/** Pembungkus hash2 Go: semua operasi diteruskan ke objek yang dibungkus. */
private class Hash2(private val inner: GoHash) : GoHash {
    override fun write(b: ByteArray) = inner.write(b)
    override fun sum(prefix: ByteArray): ByteArray = inner.sum(prefix)
    override fun reset() = inner.reset()
    override fun marshalable() = inner.marshalable()
    override fun snapshot(): GoHash = inner.snapshot()
    override fun restoreFrom(snap: GoHash) = inner.restoreFrom(snap)
}

private class HmacHash(hashFn: () -> GoHash, keyIn: ByteArray) : GoHash {
    private val outer: GoHash = hashFn()
    private val inner: GoHash = hashFn()
    private var ipad: ByteArray
    private var opad: ByteArray
    private var marshaled = false
    private var ipadState: GoHash? = null
    private var opadState: GoHash? = null

    init {
        var key = keyIn
        if (key.size > BLOCK) {
            outer.write(key)
            key = outer.sum(ByteArray(0))
        }
        val padded = ByteArray(BLOCK)
        System.arraycopy(key, 0, padded, 0, key.size)
        ipad = ByteArray(BLOCK) { (padded[it].toInt() xor 0x36).toByte() }
        opad = ByteArray(BLOCK) { (padded[it].toInt() xor 0x5c).toByte() }
        inner.write(ipad)
    }

    override fun write(b: ByteArray) = inner.write(b)

    override fun sum(prefix: ByteArray): ByteArray {
        val origLen = prefix.size
        val data = inner.sum(prefix)
        if (marshaled) {
            outer.restoreFrom(opadState!!)
        } else {
            outer.reset()
            outer.write(opad)
        }
        outer.write(data.copyOfRange(origLen, data.size))
        return outer.sum(prefix)
    }

    override fun reset() {
        if (marshaled) {
            inner.restoreFrom(ipadState!!)
            return
        }
        inner.reset()
        inner.write(ipad)
        if (!(inner.marshalable() && outer.marshalable())) return
        ipadState = inner.snapshot()
        outer.reset()
        outer.write(opad)
        opadState = outer.snapshot()
        marshaled = true
    }

    override fun marshalable() = false // hmac Go tidak mengimplementasikan BinaryMarshaler
    override fun snapshot(): GoHash = throw UnsupportedOperationException("hmac tidak bisa di-snapshot")
    override fun restoreFrom(snap: GoHash) = throw UnsupportedOperationException("hmac tidak bisa di-restore")

    companion object {
        private const val BLOCK = 64
    }
}

/** KDF VMess AEAD persis xray-core: KDF(key, path...). Elemen path = byte mentah (Go string). */
object VmessKdf {
    private val SALT = "VMess AEAD KDF".toByteArray(Charsets.UTF_8)

    fun kdf(key: ByteArray, vararg path: ByteArray): ByteArray {
        var cur: GoHash = HmacHash({ ShaHash() }, SALT)
        for (v in path) {
            val prev = cur
            var first = true
            cur = HmacHash({
                if (first) {
                    first = false
                    Hash2(prev)
                } else {
                    prev
                }
            }, v)
        }
        cur.write(key)
        return cur.sum(ByteArray(0))
    }

    fun kdf16(key: ByteArray, vararg path: ByteArray): ByteArray = kdf(key, *path).copyOf(16)

    fun kdfStr(key: ByteArray, vararg path: String): ByteArray =
        kdf(key, *path.map { it.toByteArray(Charsets.UTF_8) }.toTypedArray())

    fun kdf16Str(key: ByteArray, vararg path: String): ByteArray =
        kdf16(key, *path.map { it.toByteArray(Charsets.UTF_8) }.toTypedArray())
}
