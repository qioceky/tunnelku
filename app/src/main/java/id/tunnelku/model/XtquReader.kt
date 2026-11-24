package id.tunnelku.model

import id.tunnelku.xray.Crypto
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.GZIPInputStream

/**
 * Pembaca format config TunnelKu sendiri `.xtqu` (v0.7.0).
 *
 * Wadah: `XTQ1 : flag : iterasi : b64(salt16) : b64(iv12) : b64(ct+tag16)`
 * Kunci: PBKDF2-HMAC-SHA256 atas material
 *   `UTF-8("tunnelku://xtqu/v1") || 0x00 || UTF-8(password UTUH, tanpa potong)`
 * Cipher: AES-256-GCM tag 128, AAD = `"XTQ1:<flag>:<iterasi>"`, plain = GZIP(JSON ≤ 1 MiB).
 * Spek penuh: ~/workspace/ghidra-work/xveon/FORMAT-XTQU.md
 *
 * CATATAN KRIPTO — PBKDF2 di sini ditulis manual lewat `Mac` HmacSHA256 (bukan
 * `SecretKeyFactory` + `PBEKeySpec`), sengaja: material kuncinya berupa BYTE
 * (domain + 0x00 + password UTF-8), sedangkan `PBEKeySpec` menerima `char[]`
 * dan konversi char→byte-nya berbeda-beda antar provider (jebakan UTF-8 /
 * byte-rendah). Dengan HMAC langsung, byte material dijamin identik dengan
 * implementasi referensi Python (`xtqu_format.py`) — dibuktikan uji silang
 * vektor di `app/src/test/.../XtquReaderTest.kt`.
 */
class XtquException(message: String) : Exception(message)

/** Hasil dekripsi wadah .xtqu (sebelum dipetakan ke [SshProfile]). */
data class XtquConfig(
    val creator: String,
    val creatorNote: String,
    val expiryTimestamp: Long,
    /** true bila file dikunci pembuatnya (flag `locked` / hide* di level file). */
    val locked: Boolean,
    val profiles: List<JSONObject>,
)

/** Hasil impor: profil yang lolos + jumlah profil yang dilewati karena kedaluwarsa. */
data class XtquImportResult(
    val imported: List<SshProfile>,
    val skippedExpired: Int,
)

object XtquReader {
    const val DOMAIN = "tunnelku://xtqu/v1"
    const val MIN_ITERATIONS = 10_000
    const val MAX_DECOMPRESSED = 1 shl 20 // 1 MiB

    private val HIDE_KEYS = listOf(
        "hideSsh", "hidePayload", "hideProxy", "hideSni",
        "hideSlowDns", "hideSlowDnsDns", "hideSlowDnsNs",
        "hideSlowDnsPubkey", "hideOvpnConfig",
    )

    /** PBKDF2-HMAC-SHA256 manual; `password` di sini adalah material BYTE utuh. */
    fun pbkdf2HmacSha256(password: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int = 32): ByteArray {
        require(iterations >= 1) { "iterasi PBKDF2 harus >= 1" }
        val hLen = 32
        val blocks = (dkLen + hLen - 1) / hLen
        val out = ByteArray(blocks * hLen)
        for (i in 1..blocks) {
            val intBuf = byteArrayOf(
                (i ushr 24).toByte(), (i ushr 16).toByte(), (i ushr 8).toByte(), i.toByte(),
            )
            var u = Crypto.hmacSha256(password, salt + intBuf)
            val t = u.copyOf()
            for (c in 2..iterations) {
                u = Crypto.hmacSha256(password, u)
                for (j in t.indices) t[j] = (t[j].toInt() xor u[j].toInt()).toByte()
            }
            System.arraycopy(t, 0, out, (i - 1) * hLen, hLen)
        }
        return out.copyOf(dkLen)
    }

    /** Kunci 32 byte dari password UTUH (tanpa potong, UTF-8 eksplisit). */
    fun deriveKey(password: String, salt: ByteArray, iterations: Int): ByteArray {
        val material = DOMAIN.toByteArray(Charsets.UTF_8) +
            byteArrayOf(0) +
            password.toByteArray(Charsets.UTF_8)
        return pbkdf2HmacSha256(material, salt, iterations, 32)
    }

    /** true bila wadah flag=1 (berpassword) — dibaca dari header saja, tanpa dekripsi. */
    fun needsPassword(text: String): Boolean {
        val t = text.trim().removePrefix("tunnelku://").trim()
        val parts = t.split(":")
        return parts.size == 6 && parts[0] == "XTQ1" && parts[1] == "1"
    }

    fun isExpired(expiryTimestamp: Long, nowMs: Long = System.currentTimeMillis()): Boolean =
        expiryTimestamp != 0L && expiryTimestamp < nowMs

    /** Dekrip wadah .xtqu (teks `XTQ1:…` atau URI `tunnelku://XTQ1:…`) menjadi config. */
    fun decrypt(text: String, password: String = ""): XtquConfig {
        val t = text.trim().let {
            if (it.startsWith("tunnelku://", ignoreCase = true)) it.substring("tunnelku://".length).trim() else it
        }
        val parts = t.split(":")
        if (parts.size != 6 || parts[0] != "XTQ1") {
            throw XtquException("Bukan config .xtqu — teks harus diawali XTQ1: atau tunnelku://XTQ1:")
        }
        val flag = parts[1]
        if (flag != "0" && flag != "1") {
            throw XtquException("Flag .xtqu tidak dikenal: $flag (harus 0 atau 1)")
        }
        val iterations = parts[2].toIntOrNull()
            ?: throw XtquException("Jumlah iterasi .xtqu tidak sah: ${parts[2]}")
        if (iterations < MIN_ITERATIONS) {
            throw XtquException("File .xtqu ditolak: iterasi PBKDF2 terlalu rendah ($iterations < $MIN_ITERATIONS)")
        }
        if (flag == "1" && password.isEmpty()) {
            throw XtquException("Config .xtqu ini berpassword — isi password lalu coba lagi")
        }
        val salt: ByteArray
        val iv: ByteArray
        val ct: ByteArray
        try {
            salt = Base64.getDecoder().decode(parts[3])
            iv = Base64.getDecoder().decode(parts[4])
            ct = Base64.getDecoder().decode(parts[5])
        } catch (e: IllegalArgumentException) {
            throw XtquException("Base64 .xtqu rusak: ${e.message}")
        }
        if (salt.size != 16) throw XtquException("Salt .xtqu harus 16 byte, ketemu ${salt.size}")
        if (iv.size != 12) throw XtquException("IV .xtqu harus 12 byte, ketemu ${iv.size}")

        val key = deriveKey(if (flag == "1") password else "", salt, iterations)
        val aad = "XTQ1:$flag:$iterations".toByteArray(Charsets.UTF_8)
        val comp = try {
            Crypto.aesGcmOpen(key, iv, ct, aad)
        } catch (e: Exception) {
            throw XtquException("Password salah, atau file .xtqu rusak / sudah diubah (GCM tidak cocok)")
        }
        val raw = gunzipCapped(comp)
        val json = try {
            JSONObject(String(raw, Charsets.UTF_8))
        } catch (e: Exception) {
            throw XtquException("Isi .xtqu bukan JSON yang sah: ${e.message}")
        }
        if (!json.has("profiles")) {
            throw XtquException("JSON .xtqu tidak berisi daftar profil")
        }
        val arr = json.optJSONArray("profiles") ?: throw XtquException("Daftar profil .xtqu rusak")
        val profiles = List(arr.length()) { arr.getJSONObject(it) }
        if (profiles.isEmpty()) throw XtquException("File .xtqu tidak berisi profil apa pun")
        return XtquConfig(
            creator = json.optString("creator", ""),
            creatorNote = json.optString("creatorNote", ""),
            expiryTimestamp = json.optLong("expiryTimestamp", 0),
            locked = json.optBoolean("locked", false) ||
                HIDE_KEYS.any { json.optBoolean(it, false) },
            profiles = profiles,
        )
    }

    /** Gunzip dengan batas [MAX_DECOMPRESSED]; lebih dari itu ditolak (bom zip). */
    private fun gunzipCapped(comp: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        try {
            GZIPInputStream(ByteArrayInputStream(comp)).use { gz ->
                while (true) {
                    val n = gz.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    if (out.size() > MAX_DECOMPRESSED) {
                        throw XtquException("Isi .xtqu melebihi batas 1 MiB setelah dekompresi")
                    }
                }
            }
        } catch (e: XtquException) {
            throw e
        } catch (e: Exception) {
            throw XtquException("GZIP .xtqu rusak: ${e.message}")
        }
        return out.toByteArray()
    }

    /**
     * Petakan satu objek profil JSON .xtqu (field sama seperti pemetaan .xveon)
     * menjadi [SshProfile]. `fileLocked` = flag `locked` / hide* di level file.
     * Melempar [XtquException] "Profil belum lengkap" bila host / kredensial
     * wajib kosong — cerminan validasi pra-sambung v0.6.1, tanpa retry.
     */
    fun mapProfile(o: JSONObject, fileLocked: Boolean): SshProfile {
        val name = o.optString("name", "").ifBlank { "Profil .xtqu" }
        val mode = if (o.optString("mode", "ssh").lowercase() == "xray") {
            SshProfile.MODE_XRAY
        } else {
            SshProfile.MODE_SSH
        }
        val host = o.optString("sshHost", "").trim()
        if (host.isBlank()) {
            throw XtquException("Profil belum lengkap: host \"$name\" kosong — config .xtqu tidak bisa diimpor")
        }
        val port = o.optInt("sshPort", 443).let { if (it in 1..65535) it else 443 }
        val protocol = o.optString("xrayProtocol", "vless").lowercase().ifBlank { "vless" }
        val sshUser = o.optString("sshUsername", "")
        val sshPass = o.optString("sshPassword", "")
        val xrayUuid = if (protocol == "vless" || protocol == "vmess") {
            sshUser.ifBlank { sshPass }
        } else {
            ""
        }
        val xrayPassword = if (protocol == "trojan" || protocol == "ss") sshPass else ""
        if (mode == SshProfile.MODE_XRAY) {
            when (protocol) {
                "vless", "vmess" -> if (xrayUuid.isBlank()) {
                    throw XtquException("Profil belum lengkap: UUID $protocol \"$name\" masih kosong")
                }
                "trojan", "ss" -> if (xrayPassword.isBlank()) {
                    throw XtquException("Profil belum lengkap: password $protocol \"$name\" masih kosong")
                }
            }
        }
        val transport = when (o.optString("xrayTransport", "TCP").uppercase()) {
            "WS" -> "ws"
            "GRPC" -> "grpc"
            else -> "tcp"
        }
        // forcingTls "AUTO" = TLS (pemetaan .xveon); OFF/NONE = tanpa TLS.
        val security = when (o.optString("forcingTls", "").uppercase()) {
            "OFF", "NONE", "NO" -> "none"
            else -> "tls"
        }
        val flow = o.optString("xrayFlow", "").let { if (it == "none") "" else it }
        val sniOn = o.optBoolean("enableSni", false)
        val sniHost = o.optString("sniHostname", "")
        val profileLocked = fileLocked ||
            o.optBoolean("lockedByCreator", false) ||
            HIDE_KEYS.any { o.optBoolean(it, false) }
        return SshProfile(
            name = name,
            host = host,
            port = port,
            username = sshUser,
            password = sshPass,
            usePrivateKey = o.optBoolean("usePrivateKey", false),
            privateKey = o.optString("sshPrivateKey", ""),
            privateKeyPassphrase = o.optString("sshPrivateKeyPassphrase", ""),
            proxyEnabled = o.optBoolean("enableProxy", false),
            proxyHost = o.optString("proxyHost", ""),
            proxyPort = o.optInt("proxyPort", 8080),
            payloadEnabled = o.optBoolean("enablePayload", false),
            payload = o.optString("payload", ""),
            sniEnabled = sniOn,
            sniHost = sniHost,
            udpgwEnabled = o.optBoolean("enableUdpgw", true),
            udpgwHost = o.optString("udpgwHost", "127.0.0.1"),
            udpgwPort = o.optInt("udpgwPort", 7300),
            mode = mode,
            xrayProtocol = protocol,
            xrayUuid = xrayUuid,
            xrayPassword = xrayPassword,
            xrayMethod = o.optString("xrayCipher", "").ifBlank { "aes-256-gcm" },
            xrayFlow = flow,
            xraySecurity = security,
            xraySni = sniHost,
            xrayNetwork = transport,
            xrayWsPath = o.optString("xrayWsPath", "/").ifBlank { "/" },
            xrayWsHost = o.optString("xrayWsHost", ""),
            xrayAlterId = o.optInt("xrayAlterId", 0),
            // xrayAllowInsecure=true WAJIB diteruskan — inilah celah parser impor
            // link v0.6.1 (UK O2) yang tidak boleh terulang di jalur .xtqu.
            xrayInsecure = o.optBoolean("xrayAllowInsecure", false),
            lockedByCreator = profileLocked,
        )
    }

    /**
     * Dekrip + petakan SEMUA profil dalam satu file .xtqu.
     * Config kedaluwarsa (level file) ditolak utuh; profil yang kedaluwarsa
     * sendiri dilewati dan dihitung di [XtquImportResult.skippedExpired].
     */
    fun importAll(
        text: String,
        password: String = "",
        nowMs: Long = System.currentTimeMillis(),
    ): XtquImportResult {
        val cfg = decrypt(text, password)
        if (isExpired(cfg.expiryTimestamp, nowMs)) {
            throw XtquException("Config .xtqu sudah kedaluwarsa — tidak bisa diimpor")
        }
        val fileLocked = cfg.locked
        val imported = mutableListOf<SshProfile>()
        var skipped = 0
        for (p in cfg.profiles) {
            val exp = p.optLong("expiryTimestamp", 0)
            if (isExpired(exp, nowMs)) {
                skipped++
                continue
            }
            imported.add(mapProfile(p, fileLocked))
        }
        if (imported.isEmpty() && skipped > 0) {
            throw XtquException("Semua profil dalam file .xtqu sudah kedaluwarsa")
        }
        return XtquImportResult(imported, skipped)
    }
}
