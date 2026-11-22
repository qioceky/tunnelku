package id.tunnelku.xray

/** ChaCha20-Poly1305 IETF (nonce 12 byte) + XChaCha20-Poly1305 (nonce 24 byte) murni Kotlin (RFC 8439). */
object ChaCha {
    private fun rotl(v: Int, n: Int) = Integer.rotateLeft(v, n)

    private fun quarterRound(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 16)
        x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 12)
        x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 8)
        x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 7)
    }

    private fun le32(b: ByteArray, off: Int) =
        (b[off].toInt() and 0xFF) or ((b[off + 1].toInt() and 0xFF) shl 8) or
            ((b[off + 2].toInt() and 0xFF) shl 16) or ((b[off + 3].toInt() and 0xFF) shl 24)

    private fun putLe32(out: ByteArray, off: Int, v: Int) {
        out[off] = v.toByte(); out[off + 1] = (v ushr 8).toByte()
        out[off + 2] = (v ushr 16).toByte(); out[off + 3] = (v ushr 24).toByte()
    }

    private fun chachaBlock(key: ByteArray, counter: Int, nonce: ByteArray, out: ByteArray) {
        val state = IntArray(16)
        state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574
        for (i in 0..7) state[4 + i] = le32(key, i * 4)
        state[12] = counter
        state[13] = le32(nonce, 0); state[14] = le32(nonce, 4); state[15] = le32(nonce, 8)
        val w = state.copyOf()
        repeat(10) {
            quarterRound(w, 0, 4, 8, 12); quarterRound(w, 1, 5, 9, 13)
            quarterRound(w, 2, 6, 10, 14); quarterRound(w, 3, 7, 11, 15)
            quarterRound(w, 0, 5, 10, 15); quarterRound(w, 1, 6, 11, 12)
            quarterRound(w, 2, 7, 8, 13); quarterRound(w, 3, 4, 9, 14)
        }
        for (i in 0..15) putLe32(out, i * 4, w[i] + state[i])
    }

    private fun chachaXor(key: ByteArray, nonce: ByteArray, counterStart: Int, data: ByteArray): ByteArray {
        val out = ByteArray(data.size)
        val block = ByteArray(64)
        var counter = counterStart
        var off = 0
        while (off < data.size) {
            chachaBlock(key, counter++, nonce, block)
            val take = minOf(64, data.size - off)
            for (i in 0 until take) out[off + i] = (data[off + i].toInt() xor block[i].toInt()).toByte()
            off += take
        }
        return out
    }

    fun hchacha20(key: ByteArray, nonce16: ByteArray): ByteArray {
        val state = IntArray(16)
        state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574
        for (i in 0..7) state[4 + i] = le32(key, i * 4)
        for (i in 0..3) state[12 + i] = le32(nonce16, i * 4)
        repeat(10) {
            quarterRound(state, 0, 4, 8, 12); quarterRound(state, 1, 5, 9, 13)
            quarterRound(state, 2, 6, 10, 14); quarterRound(state, 3, 7, 11, 15)
            quarterRound(state, 0, 5, 10, 15); quarterRound(state, 1, 6, 11, 12)
            quarterRound(state, 2, 7, 8, 13); quarterRound(state, 3, 4, 9, 14)
        }
        val out = ByteArray(32)
        putLe32(out, 0, state[0]); putLe32(out, 4, state[1]); putLe32(out, 8, state[2]); putLe32(out, 12, state[3])
        putLe32(out, 16, state[12]); putLe32(out, 20, state[13]); putLe32(out, 24, state[14]); putLe32(out, 28, state[15])
        return out
    }

    /** Poly1305 one-time auth (implementasi BigInteger agar ringkas & benar). */
    private fun poly1305(key: ByteArray, msg: ByteArray): ByteArray {
        val rBytes = key.copyOfRange(0, 16)
        rBytes[3] = (rBytes[3].toInt() and 15).toByte(); rBytes[7] = (rBytes[7].toInt() and 15).toByte()
        rBytes[11] = (rBytes[11].toInt() and 15).toByte(); rBytes[15] = (rBytes[15].toInt() and 15).toByte()
        rBytes[4] = (rBytes[4].toInt() and 0xFC).toByte(); rBytes[8] = (rBytes[8].toInt() and 0xFC).toByte()
        rBytes[12] = (rBytes[12].toInt() and 0xFC).toByte()
        fun leNum(b: ByteArray): java.math.BigInteger {
            val rev = ByteArray(b.size) { b[b.size - 1 - it] }
            return java.math.BigInteger(1, rev)
        }
        val r = leNum(rBytes)
        val s = leNum(key.copyOfRange(16, 32))
        val p = java.math.BigInteger.ONE.shiftLeft(130).subtract(java.math.BigInteger.valueOf(5))
        var acc = java.math.BigInteger.ZERO
        var off = 0
        while (off < msg.size) {
            val take = minOf(16, msg.size - off)
            val chunk = msg.copyOfRange(off, off + take) + byteArrayOf(1)
            acc = (acc + leNum(chunk)).multiply(r).mod(p)
            off += take
        }
        val total = acc + s
        val out = ByteArray(16)
        val bi = total.toByteArray() // big-endian, bisa 17 byte dgn leading 0
        for (i in 0..15) {
            val srcIdx = bi.size - 1 - i
            out[i] = if (srcIdx >= 0) bi[srcIdx] else 0
        }
        return out
    }

    private fun polyKey(key: ByteArray, nonce: ByteArray): ByteArray {
        val block = ByteArray(64)
        chachaBlock(key, 0, nonce, block)
        return block.copyOf(32)
    }

    private fun tagFor(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val pk = polyKey(key, nonce)
        fun pad16(b: ByteArray) = if (b.size % 16 == 0) ByteArray(0) else ByteArray(16 - b.size % 16)
        val lenBlock = ByteArray(16)
        putLe64(lenBlock, 0, aad.size.toLong())
        putLe64(lenBlock, 8, ciphertext.size.toLong())
        return poly1305(pk, aad + pad16(aad) + ciphertext + pad16(ciphertext) + lenBlock)
    }

    private fun putLe64(out: ByteArray, off: Int, v: Long) {
        for (i in 0..7) out[off + i] = (v ushr (8 * i)).toByte()
    }

    /** Seal IETF: nonce 12 byte → ciphertext||tag(16). */
    fun sealIetf(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        require(nonce.size == 12)
        val ct = chachaXor(key, nonce, 1, plaintext)
        return ct + tagFor(key, nonce, aad, ct)
    }

    fun openIetf(key: ByteArray, nonce: ByteArray, sealed: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        require(nonce.size == 12 && sealed.size >= 16)
        val ct = sealed.copyOfRange(0, sealed.size - 16)
        val tag = sealed.copyOfRange(sealed.size - 16, sealed.size)
        val expect = tagFor(key, nonce, aad, ct)
        if (!tag.contentEquals(expect)) throw IllegalStateException("ChaCha20-Poly1305: tag tidak cocok")
        return chachaXor(key, nonce, 1, ct)
    }

    /** Seal XChaCha: nonce 24 byte. */
    fun sealX(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        require(nonce.size == 24)
        val sub = hchacha20(key, nonce.copyOfRange(0, 16))
        val ietfNonce = byteArrayOf(0, 0, 0, 0) + nonce.copyOfRange(16, 24)
        return sealIetf(sub, ietfNonce, plaintext, aad)
    }

    fun openX(key: ByteArray, nonce: ByteArray, sealed: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        require(nonce.size == 24)
        val sub = hchacha20(key, nonce.copyOfRange(0, 16))
        val ietfNonce = byteArrayOf(0, 0, 0, 0) + nonce.copyOfRange(16, 24)
        return openIetf(sub, ietfNonce, sealed, aad)
    }
}
