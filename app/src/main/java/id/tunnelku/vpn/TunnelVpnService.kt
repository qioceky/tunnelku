package id.tunnelku.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import id.tunnelku.MainActivity
import id.tunnelku.R
import id.tunnelku.model.ProfileStore
import id.tunnelku.model.SettingsStore
import id.tunnelku.model.SshProfile
import java.io.FileInputStream
import java.io.FileOutputStream
import kotlin.concurrent.thread

class TunnelVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "id.tunnelku.ACTION_CONNECT"
        const val ACTION_DISCONNECT = "id.tunnelku.ACTION_DISCONNECT"
        private const val CHANNEL_ID = "tunnelku_tunnel"
        private const val NOTIF_ID = 41
        private const val SOCKS_PORT = 11080
        private const val DNSTT_PORT = 11081
        @Volatile var instance: TunnelVpnService? = null
    }

    @Volatile private var running = false
    @Volatile private var manualStop = false
    private var tunFd: ParcelFileDescriptor? = null
    private var ssh: SshTunnel? = null
    private var forwarder: TunForwarder? = null
    @Volatile private var engineDnstt = false
    @Volatile private var engineHysteria = false
    private var udpgwProvider: UdpGwRelayProvider? = null
    private var socksUdpRelay: SocksUdpRelay? = null
    private var worker: Thread? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                manualStop = true
                stopTunnel()
                return START_NOT_STICKY
            }
            ACTION_CONNECT, null -> {
                if (running) return START_STICKY
                manualStop = false
                val profile = ProfileStore.active(this)
                if (profile == null) {
                    LogBus.log("Tidak ada profil — buat profil dulu di tab Profil")
                    LogBus.setStatus(TunnelStatus.ERROR)
                    stopSelf()
                    return START_NOT_STICKY
                }
                startForegroundCompat("Menghubungkan ke ${profile.name}…")
                worker = thread(name = "tk-worker", isDaemon = true) { runTunnel(profile) }
                return START_STICKY
            }
        }
        return START_STICKY
    }

    private fun runTunnel(profile: SshProfile) {
        var attempt = 0
        while (!manualStop) {
            attempt++
            try {
                connectOnce(profile)
                // connectOnce hanya kembali saat tunnel putus.
                if (manualStop) break
                LogBus.log("Tunnel putus")
            } catch (e: Exception) {
                LogBus.log("Gagal: ${e.message ?: e.javaClass.simpleName}")
            }
            cleanupConnection()
            if (manualStop) break
            val auto = SettingsStore.getAutoReconnect(this)
            if (!auto || attempt >= 5) {
                if (attempt >= 5) LogBus.log("Batas 5x percobaan sambung ulang tercapai")
                break
            }
            LogBus.setStatus(TunnelStatus.CONNECTING)
            LogBus.log("Sambung ulang dalam 3 detik… (percobaan ${attempt + 1})")
            try { Thread.sleep(3_000) } catch (e: InterruptedException) { break }
        }
        running = false
        LogBus.setStatus(if (manualStop) TunnelStatus.DISCONNECTED else TunnelStatus.ERROR)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun connectOnce(profile: SshProfile) {
        running = true
        LogBus.resetTraffic()
        LogBus.activeProfileName = profile.name
        LogBus.setStatus(TunnelStatus.CONNECTING)

        val transport: StreamTransport
        val udpProvider: (() -> UdpRelay?)?
        val aliveCheck: () -> Boolean

        when (profile.mode) {
            SshProfile.MODE_UDP_CUSTOM -> {
                LogBus.log("Menghubungkan (UDP Custom): ${profile.name} (${profile.host}:${profile.port})")
                engine.Engine.startHysteria(
                    "${profile.host}:${profile.port}",
                    "${profile.username}:${profile.password}",
                    profile.hyObfs, profile.hySni, profile.hyInsecure,
                    "127.0.0.1:$SOCKS_PORT",
                )
                engineHysteria = true
                LogBus.log("Mesin Hysteria (UDP Custom) tersambung, SOCKS5 lokal :$SOCKS_PORT")
                transport = SocksStreamTransport(SOCKS_PORT)
                val relay = SocksUdpRelay(
                    SOCKS_PORT,
                    { s -> protect(s) },
                    { srcIp, srcPort, dstIp, dstPort, payload ->
                        // Balasan UDP: tulis kembali ke TUN lewat forwarder.
                        forwarder?.injectUdpReply(srcIp, srcPort, dstIp, dstPort, payload)
                    },
                ) { LogBus.log(it) }
                socksUdpRelay = relay
                udpProvider = { relay }
                aliveCheck = { engineHysteria }
            }
            SshProfile.MODE_SLOWDNS -> {
                LogBus.log("Menghubungkan (SlowDNS): ${profile.name} — resolver ${profile.dnsttResolver}, domain ${profile.dnsttDomain}")
                engine.Engine.startDNSTT(
                    profile.dnsttResolver.ifBlank { "1.1.1.1:53" },
                    profile.dnsttDomain,
                    profile.dnsttPubKey,
                    "127.0.0.1:$DNSTT_PORT",
                )
                engineDnstt = true
                LogBus.log("Mesin DNSTT aktif, listener lokal :$DNSTT_PORT — membuka SSH di atasnya")
                val tunnel = SshTunnel(profile, { s -> protect(s) }, { LogBus.log(it) }, viaLocalPort = DNSTT_PORT)
                ssh = tunnel
                tunnel.connect()
                transport = SshStreamTransport(tunnel)
                udpProvider = sshUdpProvider(profile, tunnel)
                aliveCheck = { tunnel.isConnected }
            }
            else -> { // SSH
                LogBus.log("Menghubungkan: ${profile.name} (${profile.host}:${profile.port})")
                val tunnel = SshTunnel(profile, { s -> protect(s) }, { LogBus.log(it) })
                ssh = tunnel
                tunnel.connect()
                transport = SshStreamTransport(tunnel)
                udpProvider = sshUdpProvider(profile, tunnel)
                aliveCheck = { tunnel.isConnected }
            }
        }

        val builder = Builder()
            .setSession("TunnelKu")
            .setMtu(profile.mtu.coerceIn(576, 9000))
            .addAddress("10.10.14.2", 32)
            .addRoute("0.0.0.0", 0)
            .addAddress("fd00:14::2", 128)
            .addRoute("::", 0) // IPv6 ditelan TUN lalu dibuang forwarder (anti-bocor)
            .addDnsServer(profile.dns.ifBlank { "1.1.1.1" })
            .setBlocking(false)
        // Kecualikan app sendiri agar socket tunnel tidak berputar.
        try { builder.addDisallowedApplication(packageName) } catch (e: Exception) { /* abaikan */ }

        val fd = builder.establish()
            ?: throw IllegalStateException("Izin VPN dicabut — Android menolak establish()")
        tunFd = fd
        LogBus.log("Antarmuka TUN aktif (MTU ${profile.mtu})")

        val fwd = TunForwarder(
            FileInputStream(fd.fileDescriptor),
            FileOutputStream(fd.fileDescriptor),
            transport,
            profile.dns.ifBlank { "1.1.1.1" },
            udpProvider,
        ) { LogBus.log(it) }
        forwarder = fwd
        fwd.start()

        LogBus.setStatus(TunnelStatus.CONNECTED)
        updateNotification("Terhubung · ${profile.name}")
        LogBus.log("Terhubung: ${profile.name} ✓")

        // Tahan thread pekerja selama tunnel hidup.
        while (!manualStop && aliveCheck()) {
            Thread.sleep(1_000)
        }
        if (!manualStop) throw IllegalStateException("Sesi tunnel berakhir")
    }

    private fun sshUdpProvider(profile: SshProfile, tunnel: SshTunnel): (() -> UdpRelay?)? {
        if (!profile.udpgwEnabled) return null
        val provider = UdpGwRelayProvider(
            tunnel,
            profile.udpgwHost.ifBlank { "127.0.0.1" },
            profile.udpgwPort,
            { srcIp, srcPort, dstIp, dstPort, payload ->
                forwarder?.injectUdpReply(srcIp, srcPort, dstIp, dstPort, payload)
            },
        ) { LogBus.log(it) }
        udpgwProvider = provider
        return { provider.get() }
    }

    private fun cleanupConnection() {
        try { forwarder?.stop() } catch (e: Exception) { /* abaikan */ }
        forwarder = null
        try { udpgwProvider?.close() } catch (e: Exception) { /* abaikan */ }
        udpgwProvider = null
        try { socksUdpRelay?.close() } catch (e: Exception) { /* abaikan */ }
        socksUdpRelay = null
        try { tunFd?.close() } catch (e: Exception) { /* abaikan */ }
        tunFd = null
        try { ssh?.disconnect() } catch (e: Exception) { /* abaikan */ }
        ssh = null
        if (engineDnstt) {
            try { engine.Engine.stopDNSTT() } catch (e: Exception) { /* abaikan */ }
            engineDnstt = false
        }
        if (engineHysteria) {
            try { engine.Engine.stopHysteria() } catch (e: Exception) { /* abaikan */ }
            engineHysteria = false
        }
    }

    private fun stopTunnel() {
        LogBus.setStatus(TunnelStatus.DISCONNECTING)
        cleanupConnection()
        running = false
        LogBus.setStatus(TunnelStatus.DISCONNECTED)
        LogBus.log("Terputus")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        manualStop = true
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        manualStop = true
        cleanupConnection()
        instance = null
        super.onDestroy()
    }

    // ------------- notifikasi -------------

    private fun createChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        val ch = NotificationChannel(CHANNEL_ID, "Tunnel TunnelKu", NotificationManager.IMPORTANCE_LOW)
        ch.description = "Status koneksi tunnel aktif"
        ch.setShowBadge(false)
        nm.createNotificationChannel(ch)
    }

    private fun buildNotification(text: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            this, 1, Intent(this, TunnelVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("TunnelKu")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openIntent)
            .addAction(Notification.Action.Builder(0, "Putuskan", stopIntent).build())
            .setOngoing(true)
            .build()
    }

    private fun startForegroundCompat(text: String) {
        val notif = buildNotification(text)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notif)
        }
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIF_ID, buildNotification(text))
    }
}
