package id.tunnelku.xray

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Util kripto umum (javax.crypto/MessageDigest) untuk klien Xray Kotlin. */
object Crypto {
    fun md5(b: ByteArray): ByteArray = MessageDigest.getInstance("MD5").digest(b)
    fun sha1(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-1").digest(b)
    fun sha224(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-224").digest(b)
    fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    fun hmac(algo: String, key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(algo)
        mac.init(SecretKeySpec(key, algo))
        return mac.doFinal(data)
    }

    fun hmacSha1(key: ByteArray, data: ByteArray) = hmac("HmacSHA1", key, data)
    fun hmacSha256(key: ByteArray, data: ByteArray) = hmac("HmacSHA256", key, data)

    /** HKDF-SHA1 (RFC 5869) — untuk subkey Shadowsocks ("ss-subkey"). */
    fun hkdfSha1(secret: ByteArray, salt: ByteArray, info: ByteArray, outLen: Int): ByteArray {
        val prk = hmacSha1(salt, secret)
        val out = ByteArray(outLen)
        var t = ByteArray(0)
        var off = 0
        var counter = 1
        while (off < outLen) {
            t = hmacSha1(prk, t + info + byteArrayOf(counter.toByte()))
            val take = minOf(t.size, outLen - off)
            System.arraycopy(t, 0, out, off, take)
            off += take
            counter++
        }
        return out
    }

    /** AES-GCM seal: nonce 12 byte → ciphertext||tag(16). */
    fun aesGcmSeal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray? = null): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        if (aad != null) c.updateAAD(aad)
        return c.doFinal(plaintext)
    }

    fun aesGcmOpen(key: ByteArray, nonce: ByteArray, sealed: ByteArray, aad: ByteArray? = null): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        if (aad != null) c.updateAAD(aad)
        return c.doFinal(sealed)
    }

    /** Satu blok AES-ECB (untuk AuthID VMess). */
    fun aesEcbEncryptBlock(key: ByteArray, block16: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/ECB/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return c.doFinal(block16)
    }

    /** FNV-1a 32-bit (checksum header VMess). */
    fun fnv1a32(data: ByteArray): Int {
        var hash = 0x811c9dc5.toInt()
        for (b in data) {
            hash = hash xor (b.toInt() and 0xFF)
            hash *= 0x01000193
        }
        return hash
    }

    /** EVP_BytesToKey versi MD5 (kunci master Shadowsocks dari password). */
    fun evpBytesToKey(password: ByteArray, keyLen: Int): ByteArray {
        val out = ByteArray(keyLen)
        var prev = ByteArray(0)
        var off = 0
        while (off < keyLen) {
            prev = md5(prev + password)
            val take = minOf(prev.size, keyLen - off)
            System.arraycopy(prev, 0, out, off, take)
            off += take
        }
        return out
    }

    fun parseUuid(s: String): ByteArray {
        val hex = s.trim().replace("-", "")
        require(hex.length == 32) { "UUID tidak sah: $s" }
        return hexToBytes(hex)
    }

    fun hexToBytes(hex: String): ByteArray {
        val t = hex.trim()
        require(t.length % 2 == 0) { "hex ganjil" }
        return ByteArray(t.length / 2) {
            ((Character.digit(t[it * 2], 16) shl 4) or Character.digit(t[it * 2 + 1], 16)).toByte()
        }
    }

    fun bytesToHex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) sb.append("%02x".format(x.toInt() and 0xFF))
        return sb.toString()
    }
}

/** Pengkodean alamat gaya v2ray (VLESS/VMess: port dulu) & gaya SOCKS (Trojan/SS: alamat dulu). */
object Addr {
    /** [port 2B BE][tipe][alamat] — tipe: 1=IPv4, 2=domain, 3=IPv6. */
    fun writePortFirst(host: String, port: Int): ByteArray {
        val addr = writeAddr(host, ipv6Type = 3)
        val out = ByteArray(2 + addr.size)
        out[0] = (port shr 8).toByte(); out[1] = (port and 0xFF).toByte()
        System.arraycopy(addr, 0, out, 2, addr.size)
        return out
    }

    /** [tipe][alamat][port 2B BE] — tipe: 1=IPv4, 3=domain, 4=IPv6 (SOCKS5/Trojan/SS). */
    fun writeAddrFirst(host: String, port: Int): ByteArray {
        val addr = writeAddr(host, domainType = 3, ipv6Type = 4)
        val out = ByteArray(addr.size + 2)
        System.arraycopy(addr, 0, out, 0, addr.size)
        out[addr.size] = (port shr 8).toByte(); out[addr.size + 1] = (port and 0xFF).toByte()
        return out
    }

    private fun writeAddr(host: String, domainType: Int = 2, ipv6Type: Int): ByteArray {
        val v4 = parseIpv4(host)
        if (v4 != null) return byteArrayOf(1) + v4
        if (host.contains(":")) {
            val v6 = parseIpv6(host)
            if (v6 != null) return byteArrayOf(ipv6Type.toByte()) + v6
        }
        val hb = host.toByteArray(Charsets.UTF_8)
        require(hb.size <= 255) { "Nama host terlalu panjang" }
        return byteArrayOf(domainType.toByte(), hb.size.toByte()) + hb
    }

    /** Baca [tipe][alamat][port] dari stream; tipe domain & IPv6 mengikuti gaya SOCKS (3/4) atau v2ray (2/3) via parameter. */
    fun readAddrFirst(inp: java.io.InputStream, domainType: Int, ipv6Type: Int): Pair<String, Int> {
        val t = inp.read()
        if (t < 0) throw IllegalStateException("EOF alamat")
        val host = when (t) {
            1 -> {
                val b = readN(inp, 4)
                b.joinToString(".") { (it.toInt() and 0xFF).toString() }
            }
            domainType -> {
                val l = inp.read()
                if (l < 0) throw IllegalStateException("EOF panjang domain")
                String(readN(inp, l), Charsets.UTF_8)
            }
            ipv6Type -> {
                val b = readN(inp, 16)
                formatIpv6(b)
            }
            else -> throw IllegalStateException("Tipe alamat tidak dikenal: $t")
        }
        val pb = readN(inp, 2)
        val port = ((pb[0].toInt() and 0xFF) shl 8) or (pb[1].toInt() and 0xFF)
        return host to port
    }

    fun readN(inp: java.io.InputStream, n: Int): ByteArray {
        val buf = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = inp.read(buf, off, n - off)
            if (r < 0) throw IllegalStateException("EOF tak terduga")
            off += r
        }
        return buf
    }

    fun parseIpv4(host: String): ByteArray? {
        val parts = host.split(".")
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for (i in 0..3) {
            val v = parts[i].toIntOrNull() ?: return null
            if (v !in 0..255 || parts[i].isEmpty()) return null
            out[i] = v.toByte()
        }
        return out
    }

    fun parseIpv6(host: String): ByteArray? {
        return try {
            val a = java.net.InetAddress.getByName(host)
            if (a.address.size == 16) a.address else null
        } catch (e: Exception) {
            null
        }
    }

    fun formatIpv6(b: ByteArray): String =
        java.net.InetAddress.getByAddress(b).hostAddress ?: ""
}
