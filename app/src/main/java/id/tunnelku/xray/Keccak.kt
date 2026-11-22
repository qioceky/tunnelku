package id.tunnelku.xray

/** SHAKE128 (Keccak-f1600, rate 168 byte, suffix 0x1F) murni Kotlin — untuk masking ukuran chunk VMess. */
class Shake128 {
    private val st = LongArray(25)
    private var pos = 0 // posisi dalam blok rate saat menyerap
    private var squeezing = false
    private var outPos = RATE // memaksa permutasi saat squeeze pertama

    fun write(data: ByteArray, off: Int = 0, len: Int = data.size) {
        check(!squeezing) { "SHAKE sudah squeeze" }
        var i = off
        var remaining = len
        while (remaining > 0) {
            val take = minOf(RATE - pos, remaining)
            for (j in 0 until take) {
                val p = pos + j
                st[p / 8] = st[p / 8] xor ((data[i + j].toLong() and 0xFF) shl (8 * (p % 8)))
            }
            pos += take; i += take; remaining -= take
            if (pos == RATE) {
                keccakF()
                pos = 0
            }
        }
    }

    fun read(out: ByteArray, off: Int = 0, len: Int = out.size) {
        if (!squeezing) {
            // padding pad10*1 dengan suffix SHAKE 0x1F
            val p = pos
            st[p / 8] = st[p / 8] xor (0x1FL shl (8 * (p % 8)))
            st[(RATE - 1) / 8] = st[(RATE - 1) / 8] xor (0x80L shl (8 * ((RATE - 1) % 8)))
            keccakF()
            squeezing = true
            outPos = 0
        }
        var i = off
        var remaining = len
        while (remaining > 0) {
            if (outPos == RATE) {
                keccakF()
                outPos = 0
            }
            val take = minOf(RATE - outPos, remaining)
            for (j in 0 until take) {
                val p = outPos + j
                out[i + j] = (st[p / 8] ushr (8 * (p % 8))).toByte()
            }
            outPos += take; i += take; remaining -= take
        }
    }

    fun readBytes(n: Int): ByteArray {
        val b = ByteArray(n)
        read(b)
        return b
    }

    private fun keccakF() {
        val c = LongArray(5)
        val d = LongArray(5)
        val b = LongArray(25)
        for (round in 0 until 24) {
            // theta
            for (x in 0..4) c[x] = st[x] xor st[x + 5] xor st[x + 10] xor st[x + 15] xor st[x + 20]
            for (x in 0..4) d[x] = c[(x + 4) % 5] xor java.lang.Long.rotateLeft(c[(x + 1) % 5], 1)
            for (x in 0..4) for (y in 0..4) st[x + 5 * y] = st[x + 5 * y] xor d[x]
            // rho + pi
            for (x in 0..4) for (y in 0..4) {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = java.lang.Long.rotateLeft(st[x + 5 * y], ROT[x + 5 * y])
            }
            // chi
            for (x in 0..4) for (y in 0..4) {
                st[x + 5 * y] = b[x + 5 * y] xor (b[(x + 1) % 5 + 5 * y].inv() and b[(x + 2) % 5 + 5 * y])
            }
            // iota
            st[0] = st[0] xor RC[round]
        }
    }

    companion object {
        private const val RATE = 168
        private val ROT = intArrayOf(
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14,
        )
        private val RC = longArrayOf(
            0x0000000000000001uL.toLong(), 0x0000000000008082uL.toLong(), 0x800000000000808auL.toLong(), 0x8000000080008000uL.toLong(),
            0x000000000000808buL.toLong(), 0x0000000080000001uL.toLong(), 0x8000000080008081uL.toLong(), 0x8000000000008009uL.toLong(),
            0x000000000000008auL.toLong(), 0x0000000000000088uL.toLong(), 0x0000000080008009uL.toLong(), 0x000000008000000auL.toLong(),
            0x000000008000808buL.toLong(), 0x800000000000008buL.toLong(), 0x8000000000008089uL.toLong(), 0x8000000000008003uL.toLong(),
            0x8000000000008002uL.toLong(), 0x8000000000000080uL.toLong(), 0x000000000000800auL.toLong(), 0x800000008000000auL.toLong(),
            0x8000000080008081uL.toLong(), 0x8000000000008080uL.toLong(), 0x0000000080000001uL.toLong(), 0x8000000080008008uL.toLong(),
        )
    }
}
