package id.tunnelku.xray

/** SHA-256 murni Kotlin dengan kemampuan snapshot/restore state (untuk simulasi HMAC Go). */
class Sha256Pure {
    private var h = intArrayOf(
        0x6a09e667, 0xbb67ae85.toInt(), 0x3c6ef372, 0xa54ff53a.toInt(),
        0x510e527f, 0x9b05688c.toInt(), 0x1f83d9ab, 0x5be0cd19,
    )
    private val buf = ByteArray(64)
    private var bufLen = 0
    private var totalLen = 0L

    fun copy(): Sha256Pure {
        val c = Sha256Pure()
        c.h = h.copyOf()
        System.arraycopy(buf, 0, c.buf, 0, buf.size)
        c.bufLen = bufLen
        c.totalLen = totalLen
        return c
    }

    fun write(data: ByteArray, off: Int = 0, len: Int = data.size) {
        totalLen += len
        var i = off
        var remaining = len
        if (bufLen > 0) {
            val take = minOf(64 - bufLen, remaining)
            System.arraycopy(data, i, buf, bufLen, take)
            bufLen += take; i += take; remaining -= take
            if (bufLen == 64) { compress(buf, 0); bufLen = 0 }
        }
        while (remaining >= 64) {
            compress(data, i); i += 64; remaining -= 64
        }
        if (remaining > 0) {
            System.arraycopy(data, i, buf, 0, remaining)
            bufLen = remaining
        }
    }

    /** Digest tanpa mengubah state (seperti Sum pada hash Go). */
    fun digest(): ByteArray {
        val c = copy()
        val bitLen = c.totalLen * 8
        c.write(byteArrayOf(0x80.toByte()))
        while (c.bufLen != 56) c.write(byteArrayOf(0))
        val lb = ByteArray(8)
        for (i in 0..7) lb[7 - i] = (bitLen ushr (8 * i)).toByte()
        c.write(lb)
        val out = ByteArray(32)
        for (i in 0..7) {
            out[i * 4] = (c.h[i] ushr 24).toByte()
            out[i * 4 + 1] = (c.h[i] ushr 16).toByte()
            out[i * 4 + 2] = (c.h[i] ushr 8).toByte()
            out[i * 4 + 3] = c.h[i].toByte()
        }
        return out
    }

    fun reset() {
        h = intArrayOf(
            0x6a09e667, 0xbb67ae85.toInt(), 0x3c6ef372, 0xa54ff53a.toInt(),
            0x510e527f, 0x9b05688c.toInt(), 0x1f83d9ab, 0x5be0cd19,
        )
        bufLen = 0
        totalLen = 0L
    }

    private fun compress(b: ByteArray, off: Int) {
        val w = IntArray(64)
        for (i in 0..15) {
            w[i] = ((b[off + i * 4].toInt() and 0xFF) shl 24) or ((b[off + i * 4 + 1].toInt() and 0xFF) shl 16) or
                ((b[off + i * 4 + 2].toInt() and 0xFF) shl 8) or (b[off + i * 4 + 3].toInt() and 0xFF)
        }
        for (i in 16..63) {
            val s0 = Integer.rotateRight(w[i - 15], 7) xor Integer.rotateRight(w[i - 15], 18) xor (w[i - 15] ushr 3)
            val s1 = Integer.rotateRight(w[i - 2], 17) xor Integer.rotateRight(w[i - 2], 19) xor (w[i - 2] ushr 10)
            w[i] = w[i - 16] + s0 + w[i - 7] + s1
        }
        var a = h[0]; var bb = h[1]; var c = h[2]; var d = h[3]
        var e = h[4]; var f = h[5]; var g = h[6]; var hh = h[7]
        for (i in 0..63) {
            val s1 = Integer.rotateRight(e, 6) xor Integer.rotateRight(e, 11) xor Integer.rotateRight(e, 25)
            val ch = (e and f) xor (e.inv() and g)
            val t1 = hh + s1 + ch + K[i] + w[i]
            val s0 = Integer.rotateRight(a, 2) xor Integer.rotateRight(a, 13) xor Integer.rotateRight(a, 22)
            val maj = (a and bb) xor (a and c) xor (bb and c)
            val t2 = s0 + maj
            hh = g; g = f; f = e; e = d + t1; d = c; c = bb; bb = a; a = t1 + t2
        }
        h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh
    }

    companion object {
        private val K = intArrayOf(
            0x428a2f98, 0x71374491, 0xb5c0fbcf.toInt(), 0xe9b5dba5.toInt(), 0x3956c25b, 0x59f111f1, 0x923f82a4.toInt(), 0xab1c5ed5.toInt(),
            0xd807aa98.toInt(), 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe.toInt(), 0x9bdc06a7.toInt(), 0xc19bf174.toInt(),
            0xe49b69c1.toInt(), 0xefbe4786.toInt(), 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152.toInt(), 0xa831c66d.toInt(),
            0xb00327c8.toInt(), 0xbf597fc7.toInt(), 0xc6e00bf3.toInt(), 0xd5a79147.toInt(), 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e.toInt(), 0x92722c85.toInt(),
            0xa2bfe8a1.toInt(), 0xa81a664b.toInt(), 0xc24b8b70.toInt(), 0xc76c51a3.toInt(), 0xd192e819.toInt(), 0xd6990624.toInt(), 0xf40e3585.toInt(), 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814.toInt(), 0x8cc70208.toInt(),
            0x90befffa.toInt(), 0xa4506ceb.toInt(), 0xbef9a3f7.toInt(), 0xc67178f2.toInt(),
        )

        fun hash(data: ByteArray): ByteArray {
            val s = Sha256Pure()
            s.write(data)
            return s.digest()
        }
    }
}
