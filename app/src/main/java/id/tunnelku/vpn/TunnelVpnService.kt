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
        @Volatile var instance: TunnelVpnService? = null
    }

    @Volatile private var running = false
    @Volatile private var manualStop = false
    private var tunFd: ParcelFileDescriptor? = null
    private var ssh: SshTunnel? = null
    private var forwarder: TunForwarder? = null
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
                    LogBus.log("Tidak ada profil SSH — buat profil dulu di tab Profil")
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
        LogBus.log("Menghubungkan: ${profile.name} (${profile.host}:${profile.port})")

        val tunnel = SshTunnel(profile, { s -> protect(s) }, { LogBus.log(it) })
        ssh = tunnel
        tunnel.connect()

        val builder = Builder()
            .setSession("TunnelKu")
            .setMtu(profile.mtu.coerceIn(576, 9000))
            .addAddress("10.10.14.2", 32)
            .addRoute("0.0.0.0", 0)
            .addAddress("fd00:14::2", 128)
            .addRoute("::", 0) // IPv6 ditelan TUN lalu dibuang forwarder (anti-bocor)
            .addDnsServer(profile.dns.ifBlank { "1.1.1.1" })
            .setBlocking(false)
        // Kecualikan app sendiri agar socket SSH tidak berputar.
        try { builder.addDisallowedApplication(packageName) } catch (e: Exception) { /* abaikan */ }

        val fd = builder.establish()
            ?: throw IllegalStateException("Izin VPN dicabut — Android menolak establish()")
        tunFd = fd
        LogBus.log("Antarmuka TUN aktif (MTU ${profile.mtu})")

        val fwd = TunForwarder(
            FileInputStream(fd.fileDescriptor),
            FileOutputStream(fd.fileDescriptor),
            tunnel,
            profile.dns.ifBlank { "1.1.1.1" },
        ) { LogBus.log(it) }
        forwarder = fwd
        fwd.start()

        LogBus.setStatus(TunnelStatus.CONNECTED)
        updateNotification("Terhubung · ${profile.name}")
        LogBus.log("Terhubung: ${profile.name} ✓")

        // Tahan thread pekerja selama SSH hidup.
        while (!manualStop && tunnel.isConnected) {
            Thread.sleep(1_000)
        }
        if (!manualStop) throw IllegalStateException("Sesi SSH berakhir")
    }

    private fun cleanupConnection() {
        try { forwarder?.stop() } catch (e: Exception) { /* abaikan */ }
        forwarder = null
        try { tunFd?.close() } catch (e: Exception) { /* abaikan */ }
        tunFd = null
        try { ssh?.disconnect() } catch (e: Exception) { /* abaikan */ }
        ssh = null
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
