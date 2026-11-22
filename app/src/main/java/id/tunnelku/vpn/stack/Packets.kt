package id.tunnelku.vpn.stack

/**
 * Pembangun paket IPv4/TCP/UDP — port perilaku kelas `d` XVEON:
 * header IPv4 selalu 20 byte (0x45), IP ID 0, flags DF, TTL 64;
 * window TCP selalu 65535; checksum dihitung penuh untuk paket keluar,
 * checksum paket masuk tidak pernah diverifikasi.
 */
object Packets {

    const val FLAG_FIN = 0x01
    const val FLAG_SYN = 0x02
    const val FLAG_RST = 0x04
    const val FLAG_PSH = 0x08
    const val FLAG_ACK = 0x10

    fun u16(b: ByteArray, off: Int): Int = ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    fun u32(b: ByteArray, off: Int): Long =
        ((b[off].toLong() and 0xFF) shl 24) or ((b[off + 1].toLong() and 0xFF) shl 16) or
            ((b[off + 2].toLong() and 0xFF) shl 8) or (b[off + 3].toLong() and 0xFF)

    fun put16(b: ByteArray, off: Int, v: Int) {
        b[off] = (v shr 8).toByte(); b[off + 1] = v.toByte()
    }

    fun put32(b: ByteArray, off: Int, v: Long) {
        b[off] = (v shr 24).toByte(); b[off + 1] = (v shr 16).toByte()
        b[off + 2] = (v shr 8).toByte(); b[off + 3] = v.toByte()
    }

    fun ipToInt(ip: String): Int {
        val p = ip.split('.')
        require(p.size == 4) { "bukan IPv4: $ip" }
        var v = 0
        for (s in p) v = (v shl 8) or (s.toInt() and 0xFF)
        return v
    }

    fun ipToString(v: Int): String =
        "${(v ushr 24) and 0xFF}.${(v ushr 16) and 0xFF}.${(v ushr 8) and 0xFF}.${v and 0xFF}"

    fun ipBytesToInt(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    private fun checksum(data: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        var i = off
        val end = off + len
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (data[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.toInt().inv() and 0xFFFF
    }

    private fun ipHeader(b: ByteArray, totalLen: Int, proto: Int, srcIp: Int, dstIp: Int) {
        b[0] = 0x45
        b[1] = 0
        put16(b, 2, totalLen)
        put16(b, 4, 0) // ID selalu 0
        put16(b, 6, 0x4000) // DF
        b[8] = 64 // TTL
        b[9] = proto.toByte()
        put16(b, 10, 0)
        put32(b, 12, srcIp.toLong())
        put32(b, 16, dstIp.toLong())
        put16(b, 10, checksum(b, 0, 20))
    }

    private fun transportChecksum(b: ByteArray, srcIp: Int, dstIp: Int, proto: Int, segOff: Int, segLen: Int): Int {
        var sum = 0L
        sum += (srcIp ushr 16) and 0xFFFF; sum += srcIp and 0xFFFF
        sum += (dstIp ushr 16) and 0xFFFF; sum += dstIp and 0xFFFF
        sum += proto; sum += segLen
        var i = segOff
        val end = segOff + segLen
        while (i + 1 < end) {
            sum += ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (b[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.toInt().inv() and 0xFFFF
    }

    /**
     * Paket TCP. Bila [mss] != null → header 24 byte dengan opsi MSS (untuk SYN-ACK);
     * selain itu header 20 byte. Window selalu 65535.
     */
    fun tcp(
        srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int,
        seq: Long, ack: Long, flags: Int,
        payload: ByteArray? = null, payloadOff: Int = 0, payloadLen: Int = 0,
        mss: Int? = null,
    ): ByteArray {
        // payloadLen <= 0 berarti "seluruh payload dari payloadOff"
        val plen = if (payloadLen > 0) payloadLen else if (payload != null) payload.size - payloadOff else 0
        val hdrLen = if (mss != null) 24 else 20
        val total = 20 + hdrLen + plen
        val b = ByteArray(total)
        ipHeader(b, total, 6, srcIp, dstIp)
        val t = 20
        put16(b, t, srcPort); put16(b, t + 2, dstPort)
        put32(b, t + 4, seq); put32(b, t + 8, ack)
        b[t + 12] = ((hdrLen / 4) shl 4).toByte()
        b[t + 13] = flags.toByte()
        put16(b, t + 14, 65535)
        if (mss != null) {
            b[t + 20] = 2; b[t + 21] = 4; put16(b, t + 22, mss)
        }
        if (payload != null && plen > 0) {
            System.arraycopy(payload, payloadOff, b, t + hdrLen, plen)
        }
        put16(b, t + 16, transportChecksum(b, srcIp, dstIp, 6, t, hdrLen + plen))
        return b
    }

    /** Paket UDP; checksum 0 diganti 0xFFFF seperti XVEON. */
    fun udp(
        srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int,
        payload: ByteArray, payloadOff: Int = 0, payloadLen: Int = payload.size,
    ): ByteArray {
        val total = 20 + 8 + payloadLen
        val b = ByteArray(total)
        ipHeader(b, total, 17, srcIp, dstIp)
        val u = 20
        put16(b, u, srcPort); put16(b, u + 2, dstPort)
        put16(b, u + 4, 8 + payloadLen)
        System.arraycopy(payload, payloadOff, b, u + 8, payloadLen)
        var cs = transportChecksum(b, srcIp, dstIp, 17, u, 8 + payloadLen)
        if (cs == 0) cs = 0xFFFF
        put16(b, u + 6, cs)
        return b
    }
}
