package id.tunnelku.model

/** Stub host-test: hanya field yang dipakai paket xray (cermin Profile.kt asli). */
data class SshProfile(
    val id: String = "test",
    val name: String = "Profil Uji",
    val host: String = "",
    val port: Int = 443,
    val mode: String = MODE_XRAY,
    val xrayProtocol: String = "vless",
    val xrayUuid: String = "",
    val xrayPassword: String = "",
    val xrayMethod: String = "aes-256-gcm",
    val xrayFlow: String = "",
    val xraySecurity: String = "tls",
    val xraySni: String = "",
    val xrayFingerprint: String = "chrome",
    val xrayAlpn: String = "",
    val xrayPublicKey: String = "",
    val xrayShortId: String = "",
    val xraySpiderX: String = "",
    val xrayNetwork: String = "tcp",
    val xrayWsPath: String = "/",
    val xrayWsHost: String = "",
    val xrayGrpcService: String = "",
    val xrayAlterId: Int = 0,
    val xrayVmessSecurity: String = "auto",
    val xrayInsecure: Boolean = false,
) {
    companion object {
        const val MODE_SSH = "SSH"
        const val MODE_SLOWDNS = "SLOWDNS"
        const val MODE_UDP_CUSTOM = "UDP_CUSTOM"
        const val MODE_XRAY = "XRAY"
    }
}
