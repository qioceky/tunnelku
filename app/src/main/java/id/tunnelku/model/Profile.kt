package id.tunnelku.model

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/** Profil koneksi mode SSH (v0.1). Mode lain menyusul di versi berikutnya. */
data class SshProfile(
    val id: String = UUID.randomUUID().toString(),
    val name: String = "Profil SSH",
    val host: String = "",
    val port: Int = 443,
    val username: String = "",
    val password: String = "",
    val usePrivateKey: Boolean = false,
    val privateKey: String = "",
    val privateKeyPassphrase: String = "",
    val proxyEnabled: Boolean = false,
    val proxyType: String = "HTTP", // HTTP | SOCKS5
    val proxyHost: String = "",
    val proxyPort: Int = 8080,
    val payloadEnabled: Boolean = false,
    val payload: String = "",
    val sniEnabled: Boolean = false,
    val sniHost: String = "",
    val dns: String = "1.1.1.1",
    val mtu: Int = 1400,
    val udpgwEnabled: Boolean = true,
    val udpgwHost: String = "127.0.0.1",
    val udpgwPort: Int = 7300,
    val mode: String = MODE_SSH, // SSH | SLOWDNS | UDP_CUSTOM
    val dnsttDomain: String = "",
    val dnsttPubKey: String = "",
    val dnsttResolver: String = "1.1.1.1:53",
    val hyObfs: String = "",
    val hySni: String = "",
    val hyInsecure: Boolean = true,
    val xrayProtocol: String = "vless", // vless|vmess|trojan|ss
    val xrayUuid: String = "",
    val xrayPassword: String = "",
    val xrayMethod: String = "aes-256-gcm",
    val xrayFlow: String = "",
    val xraySecurity: String = "tls", // none|tls|reality
    val xraySni: String = "",
    val xrayFingerprint: String = "chrome",
    val xrayAlpn: String = "",
    val xrayPublicKey: String = "",
    val xrayShortId: String = "",
    val xraySpiderX: String = "",
    val xrayNetwork: String = "tcp", // tcp|ws|grpc
    val xrayWsPath: String = "/",
    val xrayWsHost: String = "",
    val xrayGrpcService: String = "",
    val xrayAlterId: Int = 0,
    val xrayVmessSecurity: String = "auto",
    val xrayInsecure: Boolean = false, // izinkan sertifikat TLS tidak tepercaya (allowInsecure)
    /** Profil dikunci pembuatnya (impor .xtqu dengan hide* / locked): bisa dipakai & dihapus, tapi tidak bisa diedit. */
    val lockedByCreator: Boolean = false,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id); put("name", name); put("host", host); put("port", port)
        put("username", username); put("password", password)
        put("usePrivateKey", usePrivateKey); put("privateKey", privateKey)
        put("privateKeyPassphrase", privateKeyPassphrase)
        put("proxyEnabled", proxyEnabled); put("proxyType", proxyType)
        put("proxyHost", proxyHost); put("proxyPort", proxyPort)
        put("payloadEnabled", payloadEnabled); put("payload", payload)
        put("sniEnabled", sniEnabled); put("sniHost", sniHost)
        put("dns", dns); put("mtu", mtu)
        put("udpgwEnabled", udpgwEnabled); put("udpgwHost", udpgwHost); put("udpgwPort", udpgwPort)
        put("mode", mode)
        put("dnsttDomain", dnsttDomain); put("dnsttPubKey", dnsttPubKey); put("dnsttResolver", dnsttResolver)
        put("hyObfs", hyObfs); put("hySni", hySni); put("hyInsecure", hyInsecure)
        put("xrayProtocol", xrayProtocol); put("xrayUuid", xrayUuid); put("xrayPassword", xrayPassword)
        put("xrayMethod", xrayMethod); put("xrayFlow", xrayFlow); put("xraySecurity", xraySecurity)
        put("xraySni", xraySni); put("xrayFingerprint", xrayFingerprint); put("xrayAlpn", xrayAlpn)
        put("xrayPublicKey", xrayPublicKey); put("xrayShortId", xrayShortId); put("xraySpiderX", xraySpiderX)
        put("xrayNetwork", xrayNetwork); put("xrayWsPath", xrayWsPath); put("xrayWsHost", xrayWsHost)
        put("xrayGrpcService", xrayGrpcService); put("xrayAlterId", xrayAlterId)
        put("xrayVmessSecurity", xrayVmessSecurity); put("xrayInsecure", xrayInsecure)
        put("lockedByCreator", lockedByCreator)
    }

    companion object {
        const val MODE_SSH = "SSH"
        const val MODE_SLOWDNS = "SLOWDNS"
        const val MODE_UDP_CUSTOM = "UDP_CUSTOM"
        const val MODE_XRAY = "XRAY"

        fun fromJson(o: JSONObject): SshProfile = SshProfile(
            id = o.optString("id", UUID.randomUUID().toString()),
            name = o.optString("name", "Profil SSH"),
            host = o.optString("host", ""),
            port = o.optInt("port", 443),
            username = o.optString("username", ""),
            password = o.optString("password", ""),
            usePrivateKey = o.optBoolean("usePrivateKey", false),
            privateKey = o.optString("privateKey", ""),
            privateKeyPassphrase = o.optString("privateKeyPassphrase", ""),
            proxyEnabled = o.optBoolean("proxyEnabled", false),
            proxyType = o.optString("proxyType", "HTTP"),
            proxyHost = o.optString("proxyHost", ""),
            proxyPort = o.optInt("proxyPort", 8080),
            payloadEnabled = o.optBoolean("payloadEnabled", false),
            payload = o.optString("payload", ""),
            sniEnabled = o.optBoolean("sniEnabled", false),
            sniHost = o.optString("sniHost", ""),
            dns = o.optString("dns", "1.1.1.1"),
            mtu = o.optInt("mtu", 1400),
            udpgwEnabled = o.optBoolean("udpgwEnabled", true),
            udpgwHost = o.optString("udpgwHost", "127.0.0.1"),
            udpgwPort = o.optInt("udpgwPort", 7300),
            mode = o.optString("mode", MODE_SSH),
            dnsttDomain = o.optString("dnsttDomain", ""),
            dnsttPubKey = o.optString("dnsttPubKey", ""),
            dnsttResolver = o.optString("dnsttResolver", "1.1.1.1:53"),
            hyObfs = o.optString("hyObfs", ""),
            hySni = o.optString("hySni", ""),
            hyInsecure = o.optBoolean("hyInsecure", true),
            xrayProtocol = o.optString("xrayProtocol", "vless"),
            xrayUuid = o.optString("xrayUuid", ""),
            xrayPassword = o.optString("xrayPassword", ""),
            xrayMethod = o.optString("xrayMethod", "aes-256-gcm"),
            xrayFlow = o.optString("xrayFlow", ""),
            xraySecurity = o.optString("xraySecurity", "tls"),
            xraySni = o.optString("xraySni", ""),
            xrayFingerprint = o.optString("xrayFingerprint", "chrome"),
            xrayAlpn = o.optString("xrayAlpn", ""),
            xrayPublicKey = o.optString("xrayPublicKey", ""),
            xrayShortId = o.optString("xrayShortId", ""),
            xraySpiderX = o.optString("xraySpiderX", ""),
            xrayNetwork = o.optString("xrayNetwork", "tcp"),
            xrayWsPath = o.optString("xrayWsPath", "/"),
            xrayWsHost = o.optString("xrayWsHost", ""),
            xrayGrpcService = o.optString("xrayGrpcService", ""),
            xrayAlterId = o.optInt("xrayAlterId", 0),
            xrayVmessSecurity = o.optString("xrayVmessSecurity", "auto"),
            xrayInsecure = o.optBoolean("xrayInsecure", false),
            lockedByCreator = o.optBoolean("lockedByCreator", false),
        )
    }
}

object ProfileStore {
    private const val PREFS = "tunnelku_profiles"
    private const val KEY_LIST = "profiles_ssh_v1"
    private const val KEY_ACTIVE = "active_profile_ssh_v1"

    fun load(ctx: Context): MutableList<SshProfile> {
        val raw = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_LIST, null)
            ?: return mutableListOf()
        return try {
            val arr = JSONArray(raw)
            MutableList(arr.length()) { SshProfile.fromJson(arr.getJSONObject(it)) }
        } catch (e: Exception) {
            mutableListOf()
        }
    }

    fun save(ctx: Context, list: List<SshProfile>) {
        val arr = JSONArray()
        list.forEach { arr.put(it.toJson()) }
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(KEY_LIST, arr.toString()).apply()
    }

    fun activeId(ctx: Context): String? =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_ACTIVE, null)

    fun setActiveId(ctx: Context, id: String?) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(KEY_ACTIVE, id).apply()
    }

    fun active(ctx: Context): SshProfile? {
        val list = load(ctx)
        val id = activeId(ctx)
        return list.firstOrNull { it.id == id } ?: list.firstOrNull()
    }
}

/** Pengaturan tampilan & perilaku. */
object SettingsStore {
    private const val PREFS = "tunnelku_settings"
    const val BG_WALLPAPER = "wallpaper" // tembus wallpaper HP
    const val BG_CUSTOM = "custom"       // gambar sendiri
    const val BG_GRADIENT = "gradient"   // gradasi bawaan

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun getBgMode(ctx: Context): String = p(ctx).getString("bg_mode", BG_GRADIENT) ?: BG_GRADIENT
    fun setBgMode(ctx: Context, v: String) = p(ctx).edit().putString("bg_mode", v).apply()
    fun getBgImage(ctx: Context): String? = p(ctx).getString("bg_image", null)
    fun setBgImage(ctx: Context, v: String?) = p(ctx).edit().putString("bg_image", v).apply()
    fun getBlur(ctx: Context): Float = p(ctx).getFloat("bg_blur", 14f)
    fun setBlur(ctx: Context, v: Float) = p(ctx).edit().putFloat("bg_blur", v).apply()
    fun getDim(ctx: Context): Float = p(ctx).getFloat("bg_dim", 0.25f)
    fun setDim(ctx: Context, v: Float) = p(ctx).edit().putFloat("bg_dim", v).apply()
    fun getGlass(ctx: Context): Float = p(ctx).getFloat("glass_alpha", 0.30f)
    fun setGlass(ctx: Context, v: Float) = p(ctx).edit().putFloat("glass_alpha", v).apply()
    fun getAutoReconnect(ctx: Context): Boolean = p(ctx).getBoolean("auto_reconnect", true)
    fun setAutoReconnect(ctx: Context, v: Boolean) = p(ctx).edit().putBoolean("auto_reconnect", v).apply()
}
