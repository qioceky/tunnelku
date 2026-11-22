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
import id.tunnelku.model.ProfileStore
import id.tunnelku.model.SettingsStore
import id.tunnelku.model.SshProfile
import id.tunnelku.vpn.stack.OutboundEngine
import id.tunnelku.vpn.stack.SshEngine
import id.tunnelku.vpn.stack.TunStack
import id.tunnelku.vpn.stack.XrayEngine
import java.io.FileInputStream
import java.io.FileOutputStream
import kotlin.concurrent.thread

/**
 * Layanan VPN TunnelKu — arsitektur remake setia XVEON (v0.6.0):
 * satu [TunStack] (port forwarder `z7`) untuk kedua mode; engine SSH (JSch)
 * atau Xray (klien Kotlin) di belakang kontrak [OutboundEngine] (`a8`).
 * TUN: 10.11.12.2/30, MTU dijepit 1280–1500, DNS profil (bawaan 1.1.1.1),
 * rute IPv6 blackhole (dibuang stack, anti-bocor).
 */
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
    @Volatile private var engineLost = false
    private var tunFd: ParcelFileDescriptor? = null
    private var stack: TunStack? = null
    private var engine: OutboundEngine? = null
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
            var fatal = false
            try {
                connectOnce(profile)
                // connectOnce hanya kembali saat tunnel putus.
                if (manualStop) break
                LogBus.log("Tunnel putus")
            } catch (e: Exception) {
                LogBus.log("Gagal: ${e.message ?: e.javaClass.simpleName}")
                // Error kredensial/izin/profil tidak di-retry (ala XVEON).
                val m = e.message ?: ""
                if (m.contains("Kredensial ditolak") || m.contains("auth fail", ignoreCase = true) ||
                    m.contains("sudah tidak didukung") || m.contains("belum lengkap")
                ) {
                    fatal = true
                }
            }
            cleanupConnection()
            if (manualStop || fatal) break
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

    /** Profil setengah kosong tidak usah dicoba — gagal jelas sekali, tanpa retry. */
    private fun validateProfile(profile: SshProfile) {
        if (profile.host.isBlank()) {
            throw IllegalStateException(
                "Profil belum lengkap: Host server masih kosong — buka tab Profil, edit profil ini, " +
                    "isi Host server, atau tempel link akun lalu tekan Impor dari Link, kemudian Simpan",
            )
        }
        if (profile.mode == SshProfile.MODE_XRAY) {
            when (profile.xrayProtocol) {
                "vless", "vmess" -> if (profile.xrayUuid.isBlank()) {
                    throw IllegalStateException(
                        "Profil belum lengkap: UUID ${profile.xrayProtocol} masih kosong — " +
                            "isi manual di editor profil atau pakai Impor dari Link",
                    )
                }
                "trojan", "ss" -> if (profile.xrayPassword.isBlank()) {
                    throw IllegalStateException(
                        "Profil belum lengkap: Password ${profile.xrayProtocol} masih kosong — " +
                            "isi manual di editor profil atau pakai Impor dari Link",
                    )
                }
            }
        }
    }

    private fun connectOnce(profile: SshProfile) {
        running = true
        engineLost = false
        LogBus.resetTraffic()
        LogBus.activeProfileName = profile.name
        LogBus.setStatus(TunnelStatus.CONNECTING)
        validateProfile(profile)

        val eng: OutboundEngine = when (profile.mode) {
            SshProfile.MODE_XRAY -> {
                LogBus.log("Menghubungkan (Xray/${profile.xrayProtocol}): ${profile.name} (${profile.host}:${profile.port})")
                val e = XrayEngine(
                    profile,
                    { s -> protect(s) },
                    { s -> protect(s) },
                ) { LogBus.log(it) }
                // Gerbang verifikasi sesi ala `da`: probe DNS + HTTP harus lolos
                // sebelum TUN dinyatakan terhubung.
                e.verify()
                e
            }
            SshProfile.MODE_SLOWDNS, SshProfile.MODE_UDP_CUSTOM -> {
                throw IllegalStateException("Mode ${profile.mode} sudah tidak didukung sejak v0.5.0 — TunnelKu fokus SSH & Xray. Buat profil mode SSH atau Xray.")
            }
            else -> { // SSH
                LogBus.log("Menghubungkan: ${profile.name} (${profile.host}:${profile.port})")
                val tunnel = SshTunnel(profile, { s -> protect(s) }, { LogBus.log(it) })
                tunnel.connect()
                SshEngine(tunnel, profile)
            }
        }
        engine = eng

        val mtu = profile.mtu.coerceIn(1280, 1500)
        val builder = Builder()
            .setSession("TunnelKu")
            .setMtu(mtu)
            .addAddress("10.11.12.2", 30)
            .addRoute("0.0.0.0", 0)
            .addAddress("fd00:14::2", 128)
            .addRoute("::", 0) // IPv6 ditelan TUN lalu dibuang stack (anti-bocor)
            .addDnsServer(profile.dns.ifBlank { "1.1.1.1" })
            .setBlocking(false)
        // Kecualikan app sendiri agar socket tunnel tidak berputar.
        try { builder.addDisallowedApplication(packageName) } catch (e: Exception) { /* abaikan */ }

        val fd = builder.establish()
            ?: throw IllegalStateException("Izin VPN dicabut — Android menolak establish()")
        tunFd = fd
        LogBus.log("Antarmuka TUN aktif (10.11.12.2/30, MTU $mtu)")

        val st = TunStack(
            FileInputStream(fd.fileDescriptor),
            FileOutputStream(fd.fileDescriptor),
            eng,
            mtu,
            tcpTimeoutMs = 30000,
            log = { LogBus.log(it) },
            onEngineLost = { msg ->
                LogBus.log("Koneksi engine hilang: $msg")
                engineLost = true
            },
            countUp = { LogBus.addTraffic(0, it.toLong()) },
            countDown = { LogBus.addTraffic(it.toLong(), 0) },
        )
        stack = st
        st.start()

        LogBus.setStatus(TunnelStatus.CONNECTED)
        updateNotification("Terhubung · ${profile.name}")
        LogBus.log("Terhubung: ${profile.name} ✓")

        // Tahan thread pekerja selama tunnel hidup.
        while (!manualStop && !engineLost && eng.isConnected()) {
            Thread.sleep(1_000)
        }
        if (!manualStop) throw IllegalStateException("Sesi tunnel berakhir")
    }

    private fun cleanupConnection() {
        try { stack?.stop() } catch (e: Exception) { /* abaikan */ }
        stack = null
        try { tunFd?.close() } catch (e: Exception) { /* abaikan */ }
        tunFd = null
        try { engine?.close() } catch (e: Exception) { /* abaikan */ }
        engine = null
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
