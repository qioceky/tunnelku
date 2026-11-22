package id.tunnelku.model

/** Stub host-test: cermin penuh field SshProfile asli (Profile.kt), tanpa Android/JSON. */
data class SshProfile(
    val id: String = "test",
    val name: String = "Profil Uji",
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
    val mode: String = MODE_XRAY, // SSH | SLOWDNS | UDP_CUSTOM | XRAY
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
    val xrayInsecure: Boolean = false,
) {
    companion object {
        const val MODE_SSH = "SSH"
        const val MODE_SLOWDNS = "SLOWDNS"
        const val MODE_UDP_CUSTOM = "UDP_CUSTOM"
        const val MODE_XRAY = "XRAY"
    }
}
