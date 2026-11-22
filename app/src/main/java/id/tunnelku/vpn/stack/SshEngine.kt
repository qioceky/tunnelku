package id.tunnelku.vpn.stack

import id.tunnelku.model.SshProfile
import id.tunnelku.vpn.SshTunnel

/**
 * Adapter SSH (JSch) ke kontrak [OutboundEngine] — port `q6` XVEON:
 * UDP native tidak ada (throw), DNS native selalu null; UDP non-DNS hanya
 * lewat UDPGW, DNS lewat DNS-over-TCP per query di dalam stack.
 */
class SshEngine(
    private val tunnel: SshTunnel,
    private val profile: SshProfile,
) : OutboundEngine {

    @Volatile private var closing = false

    override fun isConnected(): Boolean = !closing && tunnel.isConnected

    override fun openTcp(host: String, port: Int, orgIp: String, orgPort: Int, timeoutMs: Int): TcpHandle =
        tunnel.openStream(host, port, orgIp, orgPort, timeoutMs)

    override fun openUdpSession(dstIp: String, dstPort: Int, timeoutMs: Int): UdpHandle =
        throw UnsupportedOperationException("Mode SSH memakai UDPGW / DNS-over-TCP")

    override fun exchangeDns(host: String, payload: ByteArray): ByteArray? = null

    override fun nativeUdpAvailable(): Boolean = false

    override fun udpForwardingEnabled(): Boolean = profile.udpgwEnabled

    override fun openUdpGw(): TcpHandle? {
        if (!profile.udpgwEnabled) return null
        return tunnel.openStream(
            profile.udpgwHost.ifBlank { "127.0.0.1" },
            profile.udpgwPort,
            "127.0.0.1", 0, 5000,
        )
    }

    override fun close() {
        closing = true
        tunnel.disconnect()
    }
}
