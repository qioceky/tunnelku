package id.tunnelku

import android.content.Intent
import android.graphics.BitmapFactory
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import id.tunnelku.model.ProfileStore
import id.tunnelku.ui.Fa
import id.tunnelku.ui.FaIcon
import id.tunnelku.model.SettingsStore
import id.tunnelku.model.SshProfile
import id.tunnelku.vpn.LogBus
import id.tunnelku.vpn.TunnelStatus
import id.tunnelku.vpn.TunnelVpnService
import kotlinx.coroutines.delay
import java.io.File

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        applyWindowBackgroundMode()
        setContent { TunnelKuApp(onBgModeChanged = { applyWindowBackgroundMode() }) }
    }

    override fun onResume() {
        super.onResume()
        applyWindowBackgroundMode()
    }

    /** Mode tembus wallpaper: aktifkan blur-di-belakang-jendela (Android 12+) bila diatur. */
    private fun applyWindowBackgroundMode() {
        val mode = SettingsStore.getBgMode(this)
        val blurPx = SettingsStore.getBlur(this).toInt()
        if (mode == SettingsStore.BG_WALLPAPER) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SHOW_WALLPAPER)
            if (Build.VERSION.SDK_INT >= 31 && blurPx > 0) {
                window.addFlags(WindowManager.LayoutParams.FLAG_BLUR_BEHIND)
                window.attributes = window.attributes.apply { blurBehindRadius = blurPx * 3 }
            } else {
                window.clearFlags(WindowManager.LayoutParams.FLAG_BLUR_BEHIND)
            }
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_BLUR_BEHIND)
            // FLAG_SHOW_WALLPAPER tetap dari tema; latar digambar Compose di atasnya.
        }
    }
}

// ---------------- util tampilan ----------------

private fun modeLabel(mode: String): String = when (mode) {
    SshProfile.MODE_SLOWDNS -> "SlowDNS"
    SshProfile.MODE_XRAY -> "Xray"
    SshProfile.MODE_UDP_CUSTOM -> "UDP Custom"
    else -> "SSH"
}

private fun fmtBytes(n: Long): String = when {
    n >= 1_000_000 -> "%.1f MB".format(n / 1_000_000.0)
    n >= 1_000 -> "%.1f KB".format(n / 1_000.0)
    else -> "$n B"
}

private fun fmtDuration(ms: Long): String {
    val s = ms / 1000
    return "%02d:%02d:%02d".format(s / 3600, (s % 3600) / 60, s % 60)
}

@Composable
private fun GlassCard(
    glassAlpha: Float,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(22.dp))
            .background(Color.White.copy(alpha = glassAlpha))
            .border(1.dp, Color.White.copy(alpha = 0.55f), RoundedCornerShape(22.dp))
            .padding(14.dp),
    ) { content() }
}

@Composable
private fun GlassTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    onGlass: Color,
    modifier: Modifier = Modifier,
    singleLine: Boolean = true,
    password: Boolean = false,
    numeric: Boolean = false,
    minLines: Int = 1,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label, fontSize = 12.sp) },
        singleLine = singleLine,
        minLines = minLines,
        visualTransformation = if (password) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
        keyboardOptions = KeyboardOptions(keyboardType = if (numeric) KeyboardType.Number else KeyboardType.Text),
        colors = OutlinedTextFieldDefaults.colors(
            focusedTextColor = onGlass, unfocusedTextColor = onGlass,
            focusedLabelColor = onGlass, unfocusedLabelColor = onGlass.copy(alpha = 0.75f),
            focusedBorderColor = Color.White.copy(alpha = 0.8f),
            unfocusedBorderColor = Color.White.copy(alpha = 0.4f),
            cursorColor = onGlass,
        ),
        modifier = modifier.fillMaxWidth(),
    )
}

// ---------------- aplikasi ----------------

@Composable
fun TunnelKuApp(onBgModeChanged: () -> Unit) {
    val ctx = LocalContext.current
    var tab by remember { mutableIntStateOf(0) }
    var bgMode by remember { mutableStateOf(SettingsStore.getBgMode(ctx)) }
    var blur by remember { mutableFloatStateOf(SettingsStore.getBlur(ctx)) }
    var dim by remember { mutableFloatStateOf(SettingsStore.getDim(ctx)) }
    var glass by remember { mutableFloatStateOf(SettingsStore.getGlass(ctx)) }
    var editing by remember { mutableStateOf<SshProfile?>(null) }
    var creatingNew by remember { mutableStateOf(false) }

    val onGlass = if (bgMode == SettingsStore.BG_GRADIENT) Color(0xFF10233F) else Color.White

    Box(modifier = Modifier.fillMaxSize()) {
        // ---- latar ----
        when (bgMode) {
            SettingsStore.BG_GRADIENT -> Box(
                Modifier.fillMaxSize().background(
                    Brush.linearGradient(
                        listOf(Color(0xFF7FB2FF), Color(0xFFB79CFF), Color(0xFF7FE3D0)),
                    ),
                ),
            )
            SettingsStore.BG_CUSTOM -> {
                val path = SettingsStore.getBgImage(ctx)
                val bmp = remember(path) {
                    path?.let { p -> try { BitmapFactory.decodeFile(p) } catch (e: Exception) { null } }
                }
                if (bmp != null) {
                    Image(
                        bitmap = bmp.asImageBitmap(),
                        contentDescription = null,
                        contentScale = ContentScale.Crop,
                        modifier = Modifier.fillMaxSize().then(
                            if (Build.VERSION.SDK_INT >= 31) Modifier.blur(blur.dp) else Modifier,
                        ),
                    )
                } else {
                    Box(Modifier.fillMaxSize().background(Color(0xFF20365E)))
                }
            }
            else -> Unit // WALLPAPER: transparan, wallpaper HP yang tampil
        }
        // lapisan penggelap agar teks terbaca
        Box(Modifier.fillMaxSize().background(Color.Black.copy(alpha = dim)))

        Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier.size(34.dp).clip(CircleShape).background(Color.White.copy(alpha = 0.25f))
                        .border(1.dp, Color.White.copy(alpha = 0.5f), CircleShape),
                    contentAlignment = Alignment.Center,
                ) { FaIcon(Fa.TOWER, size = 15.sp, color = onGlass) }
                Spacer(Modifier.size(8.dp))
                Text("TunnelKu", color = onGlass, fontSize = 22.sp, fontWeight = FontWeight.ExtraBold)
                Spacer(Modifier.size(8.dp))
                Box(
                    Modifier.clip(CircleShape).background(Color.White.copy(alpha = 0.3f))
                        .border(1.dp, Color.White.copy(alpha = 0.5f), CircleShape)
                        .padding(horizontal = 8.dp, vertical = 3.dp),
                ) {
                    Text("v0.4", color = onGlass, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                }
            }
            Spacer(Modifier.height(12.dp))

            Box(Modifier.weight(1f)) {
                if (editing != null || creatingNew) {
                    ProfileEditor(
                        initial = editing,
                        onGlass = onGlass,
                        glassAlpha = glass,
                        onCancel = { editing = null; creatingNew = false },
                        onSave = { p ->
                            val list = ProfileStore.load(ctx)
                            val idx = list.indexOfFirst { it.id == p.id }
                            if (idx >= 0) list[idx] = p else list.add(p)
                            ProfileStore.save(ctx, list)
                            if (ProfileStore.activeId(ctx) == null) ProfileStore.setActiveId(ctx, p.id)
                            editing = null; creatingNew = false
                            Toast.makeText(ctx, "Profil tersimpan", Toast.LENGTH_SHORT).show()
                        },
                        onDelete = { p ->
                            val list = ProfileStore.load(ctx)
                            list.removeAll { it.id == p.id }
                            ProfileStore.save(ctx, list)
                            if (ProfileStore.activeId(ctx) == p.id) {
                                ProfileStore.setActiveId(ctx, list.firstOrNull()?.id)
                            }
                            editing = null; creatingNew = false
                        },
                    )
                } else {
                    when (tab) {
                        0 -> HomeScreen(onGlass, glass, goProfiles = { tab = 1 })
                        1 -> ProfilesScreen(
                            onGlass, glass,
                            onEdit = { editing = it },
                            onNew = { creatingNew = true },
                        )
                        2 -> LogScreen(onGlass, glass)
                        else -> SettingsScreen(
                            onGlass, glass,
                            bgMode = bgMode,
                            onBgMode = { m ->
                                bgMode = m; SettingsStore.setBgMode(ctx, m); onBgModeChanged()
                            },
                            blur = blur, onBlur = { blur = it; SettingsStore.setBlur(ctx, it); onBgModeChanged() },
                            dim = dim, onDim = { dim = it; SettingsStore.setDim(ctx, it) },
                            glassAlpha = glass, onGlassAlpha = { glass = it; SettingsStore.setGlass(ctx, it) },
                        )
                    }
                }
            }

            Spacer(Modifier.height(12.dp))
            // nav bawah pill kaca
            Row(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(999.dp))
                    .background(Color.White.copy(alpha = glass))
                    .border(1.dp, Color.White.copy(alpha = 0.5f), RoundedCornerShape(999.dp))
                    .padding(vertical = 10.dp),
                horizontalArrangement = Arrangement.SpaceEvenly,
            ) {
                listOf(
                    Triple("Beranda", Fa.HOUSE, 0),
                    Triple("Profil", Fa.SERVER, 1),
                    Triple("Log", Fa.TERMINAL, 2),
                    Triple("Atur", Fa.GEAR, 3),
                ).forEach { (label, icon, i) ->
                    val selected = tab == i && editing == null && !creatingNew
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        modifier = Modifier.clickable { tab = i; editing = null; creatingNew = false }
                            .padding(horizontal = 10.dp, vertical = 2.dp),
                    ) {
                        FaIcon(icon, size = 16.sp, color = if (selected) onGlass else onGlass.copy(alpha = 0.65f))
                        Text(
                            label,
                            color = if (selected) onGlass else onGlass.copy(alpha = 0.65f),
                            fontWeight = if (selected) FontWeight.ExtraBold else FontWeight.Normal,
                            fontSize = 12.sp,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun HomeScreen(onGlass: Color, glass: Float, goProfiles: () -> Unit) {
    val ctx = LocalContext.current
    val status by LogBus.status.collectAsState()
    val traffic by LogBus.traffic.collectAsState()
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(status) {
        while (status == TunnelStatus.CONNECTED) {
            now = System.currentTimeMillis()
            delay(1000)
        }
    }
    val active = remember(status) { ProfileStore.active(ctx) }

    val vpnLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        if (res.resultCode == android.app.Activity.RESULT_OK) {
            ctx.startForegroundService(
                Intent(ctx, TunnelVpnService::class.java).setAction(TunnelVpnService.ACTION_CONNECT),
            )
        } else {
            Toast.makeText(ctx, "Izin VPN ditolak", Toast.LENGTH_SHORT).show()
        }
    }

    Column(Modifier.verticalScroll(rememberScrollState())) {
        GlassCard(glass, Modifier.fillMaxWidth()) {
            Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                Box(
                    Modifier.size(118.dp).clip(CircleShape)
                        .background(Color.White.copy(alpha = 0.18f))
                        .border(
                            2.dp,
                            when (status) {
                                TunnelStatus.CONNECTED -> Color(0xFF2EE66B)
                                TunnelStatus.CONNECTING, TunnelStatus.DISCONNECTING -> Color(0xFFFFC44D)
                                TunnelStatus.ERROR -> Color(0xFFFF5D5D)
                                else -> Color.White.copy(alpha = 0.6f)
                            },
                            CircleShape,
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        if (status == TunnelStatus.CONNECTED && LogBus.connectedSinceMs > 0)
                            fmtDuration(now - LogBus.connectedSinceMs)
                        else "--:--:--",
                        color = onGlass, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, fontSize = 15.sp,
                    )
                }
                Spacer(Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    FaIcon(
                        if (status == TunnelStatus.CONNECTED) Fa.CIRCLE_CHECK else Fa.CIRCLE,
                        size = 12.sp,
                        color = when (status) {
                            TunnelStatus.CONNECTED -> Color(0xFF2EE66B)
                            TunnelStatus.CONNECTING, TunnelStatus.DISCONNECTING -> Color(0xFFFFC44D)
                            TunnelStatus.ERROR -> Color(0xFFFF5D5D)
                            else -> onGlass.copy(alpha = 0.6f)
                        },
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(
                        when (status) {
                            TunnelStatus.CONNECTED -> "TERHUBUNG"
                            TunnelStatus.CONNECTING -> "MENGHUBUNGKAN…"
                            TunnelStatus.DISCONNECTING -> "MEMUTUSKAN…"
                            TunnelStatus.ERROR -> "GALAT — lihat Log"
                            else -> "TERPUTUS"
                        },
                        color = onGlass, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, fontSize = 13.sp,
                    )
                }
                Text(
                    "↓ ${fmtBytes(traffic.first)} · ↑ ${fmtBytes(traffic.second)}",
                    color = onGlass.copy(alpha = 0.9f), fontSize = 12.sp,
                )
            }
        }
        Spacer(Modifier.height(10.dp))

        GlassCard(glass, Modifier.fillMaxWidth().clickable { goProfiles() }) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                FaIcon(Fa.SERVER, size = 16.sp, color = onGlass)
                Spacer(Modifier.width(10.dp))
                Column {
                Text(
                    active?.let { "${modeLabel(it.mode)} · ${it.name}" } ?: "Belum ada profil",
                    color = onGlass, fontWeight = FontWeight.Bold, fontSize = 14.sp,
                )
                Text(
                    active?.let {
                        "${it.host}:${it.port}" +
                            (if (it.payloadEnabled) " · payload" else "") +
                            (if (it.sniEnabled) " · SNI" else "") +
                            (if (it.proxyEnabled) " · proxy" else "")
                    } ?: "Ketuk untuk membuat profil pertamamu",
                    color = onGlass.copy(alpha = 0.85f), fontSize = 12.sp,
                )
                }
            }
        }
        Spacer(Modifier.height(10.dp))

        Row(
            Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            listOf("SSH" to true, "SlowDNS" to true, "UDP" to true, "Xray" to true, "OVPN" to false).forEach { (label, on) ->
                Box(
                    Modifier.clip(RoundedCornerShape(999.dp))
                        .background(if (on) Color.White.copy(alpha = 0.75f) else Color.White.copy(alpha = 0.18f))
                        .border(1.dp, Color.White.copy(alpha = 0.45f), RoundedCornerShape(999.dp))
                        .padding(horizontal = 10.dp, vertical = 5.dp),
                ) {
                    Text(
                        if (on) label else "$label · segera",
                        color = if (on) Color(0xFF10233F) else onGlass.copy(alpha = 0.75f),
                        fontSize = 11.sp, fontWeight = if (on) FontWeight.Bold else FontWeight.Normal,
                    )
                }
            }
        }
        Spacer(Modifier.height(14.dp))

        val isOn = status == TunnelStatus.CONNECTED || status == TunnelStatus.CONNECTING
        Button(
            onClick = {
                if (isOn) {
                    ctx.startService(Intent(ctx, TunnelVpnService::class.java).setAction(TunnelVpnService.ACTION_DISCONNECT))
                } else {
                    if (ProfileStore.active(ctx) == null) {
                        Toast.makeText(ctx, "Buat profil dulu di tab Profil", Toast.LENGTH_LONG).show()
                        goProfiles()
                        return@Button
                    }
                    val prep = VpnService.prepare(ctx)
                    if (prep != null) vpnLauncher.launch(prep)
                    else ctx.startForegroundService(
                        Intent(ctx, TunnelVpnService::class.java).setAction(TunnelVpnService.ACTION_CONNECT),
                    )
                }
            },
            colors = ButtonDefaults.buttonColors(
                containerColor = Color(0xFF0A162C).copy(alpha = 0.78f),
                contentColor = Color.White,
            ),
            shape = RoundedCornerShape(18.dp),
            modifier = Modifier.fillMaxWidth().height(54.dp),
        ) {
            FaIcon(Fa.POWER, size = 16.sp, color = Color.White)
            Spacer(Modifier.width(8.dp))
            Text(if (isOn) "PUTUSKAN" else "SAMBUNGKAN", fontWeight = FontWeight.ExtraBold, fontSize = 15.sp)
        }
        Spacer(Modifier.height(8.dp))
        Text(
            "Empat mode: SSH (payload/proxy/SNI/UDPGW), SlowDNS (DNSTT), UDP Custom (Hysteria), Xray (VLESS/VMess/Trojan/SS).",
            color = onGlass.copy(alpha = 0.8f), fontSize = 11.sp,
        )
    }
}

@Composable
private fun ProfilesScreen(
    onGlass: Color,
    glass: Float,
    onEdit: (SshProfile) -> Unit,
    onNew: () -> Unit,
) {
    val ctx = LocalContext.current
    var refresh by remember { mutableIntStateOf(0) }
    val list = remember(refresh) { ProfileStore.load(ctx) }
    val activeId = remember(refresh) { ProfileStore.activeId(ctx) } ?: list.firstOrNull()?.id

    Column {
        LazyColumn(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (list.isEmpty()) {
                item {
                    GlassCard(glass, Modifier.fillMaxWidth()) {
                        Text("Belum ada profil. Tekan tombol di bawah untuk membuat profil pertamamu.", color = onGlass, fontSize = 13.sp)
                    }
                }
            }
            items(list) { p ->
                GlassCard(glass, Modifier.fillMaxWidth().clickable { onEdit(p) }) {
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            FaIcon(Fa.SERVER, size = 13.sp, color = onGlass.copy(alpha = 0.8f))
                            Spacer(Modifier.width(8.dp))
                            Text(p.name, color = onGlass, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                            if (p.id == activeId) {
                                Spacer(Modifier.size(8.dp))
                                Text("AKTIF", color = Color(0xFF2EE66B), fontSize = 10.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
                            }
                        }
                        Text(
                            if (p.mode == SshProfile.MODE_XRAY) "${modeLabel(p.mode)} · ${p.xrayProtocol}@${p.host}:${p.port}"
                            else "${modeLabel(p.mode)} · ${p.username}@${p.host}:${p.port}",
                            color = onGlass.copy(alpha = 0.85f), fontSize = 12.sp, fontFamily = FontFamily.Monospace,
                        )
                        if (p.id != activeId) {
                            Text(
                                "Jadikan aktif",
                                color = onGlass, fontSize = 12.sp, fontWeight = FontWeight.Bold,
                                modifier = Modifier.clickable {
                                    ProfileStore.setActiveId(ctx, p.id); refresh++
                                }.padding(top = 6.dp),
                            )
                        }
                    }
                }
            }
        }
        Spacer(Modifier.height(10.dp))
        Button(
            onClick = onNew,
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF0A162C).copy(alpha = 0.78f), contentColor = Color.White),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth().height(50.dp),
        ) {
            FaIcon(Fa.PLUS, size = 14.sp, color = Color.White)
            Spacer(Modifier.width(8.dp))
            Text("Profil Baru", fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
private fun ProfileEditor(
    initial: SshProfile?,
    onGlass: Color,
    glassAlpha: Float,
    onCancel: () -> Unit,
    onSave: (SshProfile) -> Unit,
    onDelete: (SshProfile) -> Unit,
) {
    val base = initial ?: SshProfile()
    var mode by remember { mutableStateOf(base.mode) }
    var name by remember { mutableStateOf(base.name) }
    var host by remember { mutableStateOf(base.host) }
    var port by remember { mutableStateOf(base.port.toString()) }
    var username by remember { mutableStateOf(base.username) }
    var password by remember { mutableStateOf(base.password) }
    var useKey by remember { mutableStateOf(base.usePrivateKey) }
    var privateKey by remember { mutableStateOf(base.privateKey) }
    var keyPass by remember { mutableStateOf(base.privateKeyPassphrase) }
    var proxyOn by remember { mutableStateOf(base.proxyEnabled) }
    var proxyType by remember { mutableStateOf(base.proxyType) }
    var proxyHost by remember { mutableStateOf(base.proxyHost) }
    var proxyPort by remember { mutableStateOf(base.proxyPort.toString()) }
    var payloadOn by remember { mutableStateOf(base.payloadEnabled) }
    var payload by remember { mutableStateOf(base.payload) }
    var sniOn by remember { mutableStateOf(base.sniEnabled) }
    var sniHost by remember { mutableStateOf(base.sniHost) }
    var dns by remember { mutableStateOf(base.dns) }
    var mtu by remember { mutableStateOf(base.mtu.toString()) }
    var udpgwOn by remember { mutableStateOf(base.udpgwEnabled) }
    var udpgwHost by remember { mutableStateOf(base.udpgwHost) }
    var udpgwPort by remember { mutableStateOf(base.udpgwPort.toString()) }
    var dnsttDomain by remember { mutableStateOf(base.dnsttDomain) }
    var dnsttPubKey by remember { mutableStateOf(base.dnsttPubKey) }
    var dnsttResolver by remember { mutableStateOf(base.dnsttResolver) }
    var hyObfs by remember { mutableStateOf(base.hyObfs) }
    var hySni by remember { mutableStateOf(base.hySni) }
    var hyInsecure by remember { mutableStateOf(base.hyInsecure) }
    var importLink by remember { mutableStateOf("") }
    var xrProto by remember { mutableStateOf(base.xrayProtocol) }
    var xrUuid by remember { mutableStateOf(base.xrayUuid) }
    var xrPassword by remember { mutableStateOf(base.xrayPassword) }
    var xrMethod by remember { mutableStateOf(base.xrayMethod) }
    var xrFlow by remember { mutableStateOf(base.xrayFlow) }
    var xrSecurity by remember { mutableStateOf(base.xraySecurity) }
    var xrSni by remember { mutableStateOf(base.xraySni) }
    var xrFingerprint by remember { mutableStateOf(base.xrayFingerprint) }
    var xrAlpn by remember { mutableStateOf(base.xrayAlpn) }
    var xrPubKey by remember { mutableStateOf(base.xrayPublicKey) }
    var xrShortId by remember { mutableStateOf(base.xrayShortId) }
    var xrSpiderX by remember { mutableStateOf(base.xraySpiderX) }
    var xrNetwork by remember { mutableStateOf(base.xrayNetwork) }
    var xrWsPath by remember { mutableStateOf(base.xrayWsPath) }
    var xrWsHost by remember { mutableStateOf(base.xrayWsHost) }
    var xrGrpcService by remember { mutableStateOf(base.xrayGrpcService) }
    var xrAlterId by remember { mutableStateOf(base.xrayAlterId.toString()) }
    var xrVmessSecurity by remember { mutableStateOf(base.xrayVmessSecurity) }

    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(if (initial == null) "Profil Baru" else "Ubah Profil", color = onGlass, fontWeight = FontWeight.ExtraBold, fontSize = 16.sp)
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf(
                SshProfile.MODE_SSH to "SSH",
                SshProfile.MODE_SLOWDNS to "SlowDNS",
                SshProfile.MODE_UDP_CUSTOM to "UDP Custom",
                SshProfile.MODE_XRAY to "Xray",
            ).forEach { (m, label) ->
                Box(
                    Modifier.clip(RoundedCornerShape(999.dp))
                        .background(if (mode == m) Color.White.copy(alpha = 0.75f) else Color.White.copy(alpha = 0.18f))
                        .border(1.dp, Color.White.copy(alpha = 0.45f), RoundedCornerShape(999.dp))
                        .clickable { mode = m }
                        .padding(horizontal = 12.dp, vertical = 7.dp),
                ) {
                    Text(label, color = if (mode == m) Color(0xFF10233F) else onGlass, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                }
            }
        }
        Text(
            when (mode) {
                SshProfile.MODE_SLOWDNS -> "SSH di atas tunnel DNS (DNSTT): server DNSTT meneruskan ke SSH-mu."
                SshProfile.MODE_UDP_CUSTOM -> "Protokol Hysteria v1 (server udp-custom ePro): akun = user & password Linux server."
                SshProfile.MODE_XRAY -> "Core Xray resmi: VLESS / VMess / Trojan / Shadowsocks. Tempel link berbagi untuk mengisi otomatis."
                else -> "SSH langsung / lewat proxy, payload, dan TLS/SNI."
            },
            color = onGlass.copy(alpha = 0.85f), fontSize = 11.sp,
        )
        GlassTextField(name, { name = it }, "Nama profil", onGlass)
        GlassTextField(host, { host = it }, if (mode == SshProfile.MODE_UDP_CUSTOM) "Host server UDP Custom" else if (mode == SshProfile.MODE_XRAY) "Host server" else "Host SSH", onGlass)
        GlassTextField(port, { port = it }, if (mode == SshProfile.MODE_UDP_CUSTOM) "Port UDP" else "Port", onGlass, numeric = true)
        if (mode != SshProfile.MODE_XRAY) {
            GlassTextField(username, { username = it }, "Username", onGlass)
            GlassTextField(password, { password = it }, "Password", onGlass, password = true)
        }
        if (mode == SshProfile.MODE_XRAY) {
            GlassTextField(importLink, { importLink = it }, "Tempel link vless:// / vmess:// / trojan:// / ss://", onGlass, singleLine = false, minLines = 2)
            Box(
                Modifier.clip(RoundedCornerShape(12.dp)).background(Color.White.copy(alpha = 0.25f))
                    .border(1.dp, Color.White.copy(alpha = 0.4f), RoundedCornerShape(12.dp))
                    .clickable {
                        val parsed = id.tunnelku.vpn.XraySupport.parseShareLink(importLink, base)
                        if (parsed == null) {
                            Toast.makeText(ctx, "Link tidak dikenal / rusak", Toast.LENGTH_LONG).show()
                        } else {
                            name = parsed.name; host = parsed.host; port = parsed.port.toString()
                            xrProto = parsed.xrayProtocol; xrUuid = parsed.xrayUuid; xrPassword = parsed.xrayPassword
                            xrMethod = parsed.xrayMethod; xrFlow = parsed.xrayFlow; xrSecurity = parsed.xraySecurity
                            xrSni = parsed.xraySni; xrFingerprint = parsed.xrayFingerprint; xrAlpn = parsed.xrayAlpn
                            xrPubKey = parsed.xrayPublicKey; xrShortId = parsed.xrayShortId; xrSpiderX = parsed.xraySpiderX
                            xrNetwork = parsed.xrayNetwork; xrWsPath = parsed.xrayWsPath; xrWsHost = parsed.xrayWsHost
                            xrGrpcService = parsed.xrayGrpcService; xrAlterId = parsed.xrayAlterId.toString()
                            xrVmessSecurity = parsed.xrayVmessSecurity
                            Toast.makeText(ctx, "Link terimpor — periksa lalu Simpan", Toast.LENGTH_SHORT).show()
                        }
                    }
                    .padding(horizontal = 14.dp, vertical = 9.dp),
            ) { Text("Impor dari Link", color = onGlass, fontSize = 13.sp, fontWeight = FontWeight.Bold) }
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf("vless" to "VLESS", "vmess" to "VMess", "trojan" to "Trojan", "ss" to "SS").forEach { (m, label) ->
                    Box(
                        Modifier.clip(RoundedCornerShape(999.dp))
                            .background(if (xrProto == m) Color.White.copy(alpha = 0.75f) else Color.White.copy(alpha = 0.18f))
                            .border(1.dp, Color.White.copy(alpha = 0.45f), RoundedCornerShape(999.dp))
                            .clickable { xrProto = m }
                            .padding(horizontal = 11.dp, vertical = 6.dp),
                    ) { Text(label, color = if (xrProto == m) Color(0xFF10233F) else onGlass, fontSize = 12.sp, fontWeight = FontWeight.Bold) }
                }
            }
            if (xrProto == "vless" || xrProto == "vmess") {
                GlassTextField(xrUuid, { xrUuid = it }, "UUID", onGlass)
            }
            if (xrProto == "vless") {
                GlassTextField(xrFlow, { xrFlow = it }, "Flow (kosong / xtls-rprx-vision)", onGlass)
            }
            if (xrProto == "vmess") {
                GlassTextField(xrAlterId, { xrAlterId = it }, "AlterID (Xray hanya 0)", onGlass, numeric = true)
                GlassTextField(xrVmessSecurity, { xrVmessSecurity = it }, "Security VMess (auto)", onGlass)
            }
            if (xrProto == "trojan" || xrProto == "ss") {
                GlassTextField(xrPassword, { xrPassword = it }, "Password", onGlass, password = true)
            }
            if (xrProto == "trojan") {
                GlassTextField(xrFlow, { xrFlow = it }, "Flow (opsional)", onGlass)
            }
            if (xrProto == "ss") {
                GlassTextField(xrMethod, { xrMethod = it }, "Method (aes-256-gcm / chacha20-poly1305 / 2022-...)", onGlass)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf("tcp" to "TCP", "ws" to "WS", "grpc" to "gRPC").forEach { (m, label) ->
                    Box(
                        Modifier.clip(RoundedCornerShape(999.dp))
                            .background(if (xrNetwork == m) Color.White.copy(alpha = 0.75f) else Color.White.copy(alpha = 0.18f))
                            .border(1.dp, Color.White.copy(alpha = 0.45f), RoundedCornerShape(999.dp))
                            .clickable { xrNetwork = m }
                            .padding(horizontal = 11.dp, vertical = 6.dp),
                    ) { Text(label, color = if (xrNetwork == m) Color(0xFF10233F) else onGlass, fontSize = 12.sp, fontWeight = FontWeight.Bold) }
                }
            }
            if (xrNetwork == "ws") {
                GlassTextField(xrWsPath, { xrWsPath = it }, "Path WebSocket", onGlass)
                GlassTextField(xrWsHost, { xrWsHost = it }, "Host WebSocket (header)", onGlass)
            }
            if (xrNetwork == "grpc") {
                GlassTextField(xrGrpcService, { xrGrpcService = it }, "Service name gRPC", onGlass)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf("none" to "Tanpa", "tls" to "TLS", "reality" to "REALITY").forEach { (m, label) ->
                    Box(
                        Modifier.clip(RoundedCornerShape(999.dp))
                            .background(if (xrSecurity == m) Color.White.copy(alpha = 0.75f) else Color.White.copy(alpha = 0.18f))
                            .border(1.dp, Color.White.copy(alpha = 0.45f), RoundedCornerShape(999.dp))
                            .clickable { xrSecurity = m }
                            .padding(horizontal = 11.dp, vertical = 6.dp),
                    ) { Text(label, color = if (xrSecurity == m) Color(0xFF10233F) else onGlass, fontSize = 12.sp, fontWeight = FontWeight.Bold) }
                }
            }
            if (xrSecurity == "tls" || xrSecurity == "reality") {
                GlassTextField(xrSni, { xrSni = it }, "SNI / serverName", onGlass)
                GlassTextField(xrFingerprint, { xrFingerprint = it }, "Fingerprint uTLS (chrome)", onGlass)
            }
            if (xrSecurity == "tls") {
                GlassTextField(xrAlpn, { xrAlpn = it }, "ALPN (mis. h2,http/1.1 — opsional)", onGlass)
            }
            if (xrSecurity == "reality") {
                GlassTextField(xrPubKey, { xrPubKey = it }, "Public key REALITY (pbk)", onGlass)
                GlassTextField(xrShortId, { xrShortId = it }, "Short ID (sid, hex)", onGlass)
                GlassTextField(xrSpiderX, { xrSpiderX = it }, "SpiderX (spx, opsional)", onGlass)
            }
        }
        if (mode == SshProfile.MODE_SLOWDNS) {
            GlassTextField(dnsttDomain, { dnsttDomain = it }, "Domain DNSTT (mis. dns.contoh.com)", onGlass)
            GlassTextField(dnsttPubKey, { dnsttPubKey = it }, "Kunci publik DNSTT (64 hex)", onGlass, singleLine = false, minLines = 2)
            GlassTextField(dnsttResolver, { dnsttResolver = it }, "Resolver DNS (host:port)", onGlass)
        }
        if (mode == SshProfile.MODE_UDP_CUSTOM) {
            GlassTextField(hyObfs, { hyObfs = it }, "Obfs password (kosongkan bila tidak ada)", onGlass)
            GlassTextField(hySni, { hySni = it }, "SNI (kosongkan = ikut host)", onGlass)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Abaikan verifikasi TLS (sertifikat mandiri)", color = onGlass, fontSize = 13.sp, modifier = Modifier.weight(1f))
                Switch(hyInsecure, { hyInsecure = it })
            }
        }
        if (mode == SshProfile.MODE_SSH) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Pakai private key", color = onGlass, fontSize = 13.sp, modifier = Modifier.weight(1f))
            Switch(useKey, { useKey = it })
        }
        if (useKey) {
            GlassTextField(privateKey, { privateKey = it }, "Private key (PEM / OpenSSH)", onGlass, singleLine = false, minLines = 3)
            GlassTextField(keyPass, { keyPass = it }, "Passphrase key (opsional)", onGlass, password = true)
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Proxy remote", color = onGlass, fontSize = 13.sp, modifier = Modifier.weight(1f))
            Switch(proxyOn, { proxyOn = it })
        }
        if (proxyOn) {
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf("HTTP", "SOCKS5").forEach { t ->
                    Box(
                        Modifier.clip(RoundedCornerShape(999.dp))
                            .background(if (proxyType == t) Color.White.copy(alpha = 0.75f) else Color.White.copy(alpha = 0.18f))
                            .clickable { proxyType = t }
                            .padding(horizontal = 12.dp, vertical = 6.dp),
                    ) { Text(t, color = if (proxyType == t) Color(0xFF10233F) else onGlass, fontSize = 12.sp, fontWeight = FontWeight.Bold) }
                }
            }
            GlassTextField(proxyHost, { proxyHost = it }, "Host proxy", onGlass)
            GlassTextField(proxyPort, { proxyPort = it }, "Port proxy", onGlass, numeric = true)
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Payload kustom", color = onGlass, fontSize = 13.sp, modifier = Modifier.weight(1f))
            Switch(payloadOn, { payloadOn = it })
        }
        if (payloadOn) {
            GlassTextField(payload, { payload = it }, "Payload — [host] [host_port] [crlf] didukung", onGlass, singleLine = false, minLines = 3)
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("TLS / SNI", color = onGlass, fontSize = 13.sp, modifier = Modifier.weight(1f))
            Switch(sniOn, { sniOn = it })
        }
        if (sniOn) {
            GlassTextField(sniHost, { sniHost = it }, "Host SNI (bug host)", onGlass)
        }
        }
        GlassTextField(dns, { dns = it }, "DNS di dalam tunnel", onGlass)
        GlassTextField(mtu, { mtu = it }, "MTU TUN", onGlass, numeric = true)
        if (mode != SshProfile.MODE_UDP_CUSTOM && mode != SshProfile.MODE_XRAY) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("UDP penuh (UDPGW)", color = onGlass, fontSize = 13.sp)
                Text("UDP untuk game/VoIP lewat BadVPN udpgw di server SSH", color = onGlass.copy(alpha = 0.8f), fontSize = 11.sp)
            }
            Switch(udpgwOn, { udpgwOn = it })
        }
        if (udpgwOn) {
            GlassTextField(udpgwHost, { udpgwHost = it }, "Host UDPGW (dari sisi server SSH)", onGlass)
            GlassTextField(udpgwPort, { udpgwPort = it }, "Port UDPGW", onGlass, numeric = true)
        }
        }

        Spacer(Modifier.height(4.dp))
        Button(
            onClick = {
                onSave(
                    base.copy(
                        name = name.ifBlank { "Profil SSH" },
                        host = host.trim(), port = port.toIntOrNull() ?: 443,
                        username = username.trim(), password = password,
                        usePrivateKey = useKey, privateKey = privateKey, privateKeyPassphrase = keyPass,
                        proxyEnabled = proxyOn, proxyType = proxyType,
                        proxyHost = proxyHost.trim(), proxyPort = proxyPort.toIntOrNull() ?: 8080,
                        payloadEnabled = payloadOn, payload = payload,
                        sniEnabled = sniOn, sniHost = sniHost.trim(),
                        dns = dns.ifBlank { "1.1.1.1" }, mtu = mtu.toIntOrNull() ?: 1400,
                        udpgwEnabled = udpgwOn, udpgwHost = udpgwHost.ifBlank { "127.0.0.1" },
                        udpgwPort = udpgwPort.toIntOrNull() ?: 7300,
                        mode = mode,
                        dnsttDomain = dnsttDomain.trim(), dnsttPubKey = dnsttPubKey.trim(),
                        dnsttResolver = dnsttResolver.ifBlank { "1.1.1.1:53" },
                        hyObfs = hyObfs, hySni = hySni.trim(), hyInsecure = hyInsecure,
                        xrayProtocol = xrProto, xrayUuid = xrUuid.trim(), xrayPassword = xrPassword,
                        xrayMethod = xrMethod.trim().ifBlank { "aes-256-gcm" }, xrayFlow = xrFlow.trim(),
                        xraySecurity = xrSecurity, xraySni = xrSni.trim(), xrayFingerprint = xrFingerprint.trim().ifBlank { "chrome" },
                        xrayAlpn = xrAlpn.trim(), xrayPublicKey = xrPubKey.trim(), xrayShortId = xrShortId.trim(),
                        xraySpiderX = xrSpiderX.trim(), xrayNetwork = xrNetwork, xrayWsPath = xrWsPath.ifBlank { "/" },
                        xrayWsHost = xrWsHost.trim(), xrayGrpcService = xrGrpcService.trim(),
                        xrayAlterId = xrAlterId.toIntOrNull() ?: 0, xrayVmessSecurity = xrVmessSecurity.trim().ifBlank { "auto" },
                    ),
                )
            },
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF0A162C).copy(alpha = 0.85f), contentColor = Color.White),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth().height(50.dp),
        ) { Text("Simpan", fontWeight = FontWeight.Bold) }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = onCancel,
                colors = ButtonDefaults.buttonColors(containerColor = Color.White.copy(alpha = 0.25f), contentColor = onGlass),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.weight(1f),
            ) { Text("Batal") }
            if (initial != null) {
                Button(
                    onClick = { onDelete(base) },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFB3261E).copy(alpha = 0.85f), contentColor = Color.White),
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier.weight(1f),
                ) { Text("Hapus") }
            }
        }
        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun LogScreen(onGlass: Color, glass: Float) {
    val logs by LogBus.logs.collectAsState()
    val clipboard = LocalClipboardManager.current
    val listState = rememberLazyListState()
    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) listState.scrollToItem(logs.size - 1)
    }
    Column {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = { clipboard.setText(AnnotatedString(logs.joinToString("\n"))) },
                colors = ButtonDefaults.buttonColors(containerColor = Color.White.copy(alpha = 0.25f), contentColor = onGlass),
                shape = RoundedCornerShape(12.dp),
            ) {
                FaIcon(Fa.COPY, size = 13.sp, color = onGlass)
                Spacer(Modifier.width(6.dp))
                Text("Salin Log")
            }
            Button(
                onClick = { LogBus.clearLogs() },
                colors = ButtonDefaults.buttonColors(containerColor = Color.White.copy(alpha = 0.25f), contentColor = onGlass),
                shape = RoundedCornerShape(12.dp),
            ) {
                FaIcon(Fa.TRASH, size = 13.sp, color = onGlass)
                Spacer(Modifier.width(6.dp))
                Text("Bersihkan")
            }
        }
        Spacer(Modifier.height(10.dp))
        GlassCard(glass, Modifier.fillMaxSize()) {
            if (logs.isEmpty()) {
                Text("Log kosong — mulai koneksi untuk melihat aktivitas tunnel.", color = onGlass.copy(alpha = 0.85f), fontSize = 12.sp)
            } else {
                LazyColumn(state = listState) {
                    items(logs) { line ->
                        Text(line, color = onGlass, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                    }
                }
            }
        }
    }
}

@Composable
private fun SettingsScreen(
    onGlass: Color,
    glass: Float,
    bgMode: String,
    onBgMode: (String) -> Unit,
    blur: Float, onBlur: (Float) -> Unit,
    dim: Float, onDim: (Float) -> Unit,
    glassAlpha: Float, onGlassAlpha: (Float) -> Unit,
) {
    val ctx = LocalContext.current
    var autoReconnect by remember { mutableStateOf(SettingsStore.getAutoReconnect(ctx)) }

    val imageLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            try {
                val file = File(ctx.filesDir, "custom_bg.jpg")
                ctx.contentResolver.openInputStream(uri)?.use { input ->
                    file.outputStream().use { out -> input.copyTo(out) }
                }
                SettingsStore.setBgImage(ctx, file.absolutePath)
                onBgMode(SettingsStore.BG_CUSTOM)
                Toast.makeText(ctx, "Gambar latar dipasang", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(ctx, "Gagal membaca gambar: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Latar Belakang", color = onGlass, fontWeight = FontWeight.ExtraBold, fontSize = 15.sp)
        listOf(
            Triple(SettingsStore.BG_WALLPAPER, Fa.WINDOW, "Tembus wallpaper HP" to "Latar app = wallpaper home kamu"),
            Triple(SettingsStore.BG_CUSTOM, Fa.IMAGE, "Gambar custom" to "Foto pilihanmu dari galeri"),
            Triple(SettingsStore.BG_GRADIENT, Fa.PALETTE, "Gradasi bawaan" to "Mesh biru–ungu–toska TunnelKu"),
        ).forEach { (mode, icon, texts) ->
            GlassCard(
                glass,
                Modifier.fillMaxWidth().clickable { onBgMode(mode) },
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    FaIcon(icon, size = 17.sp, color = onGlass)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(texts.first, color = onGlass, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        Text(texts.second, color = onGlass.copy(alpha = 0.85f), fontSize = 12.sp)
                    }
                    if (bgMode == mode) FaIcon(Fa.CIRCLE_CHECK, size = 15.sp, color = Color(0xFF2EE66B))
                }
            }
        }
        if (bgMode == SettingsStore.BG_CUSTOM) {
            Button(
                onClick = { imageLauncher.launch(arrayOf("image/*")) },
                colors = ButtonDefaults.buttonColors(containerColor = Color.White.copy(alpha = 0.25f), contentColor = onGlass),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                FaIcon(Fa.IMAGE, size = 14.sp, color = onGlass)
                Spacer(Modifier.width(8.dp))
                Text("Pilih Gambar dari Galeri")
            }
        }

        Text("Kekuatan blur kaca: ${blur.toInt()}", color = onGlass, fontSize = 12.sp)
        Slider(blur, onBlur, valueRange = 0f..30f)
        Text("Gelap latar: ${(dim * 100).toInt()}%", color = onGlass, fontSize = 12.sp)
        Slider(dim, onDim, valueRange = 0f..0.7f)
        Text("Kejernihan kaca: ${(glassAlpha * 100).toInt()}%", color = onGlass, fontSize = 12.sp)
        Slider(glassAlpha, onGlassAlpha, valueRange = 0.12f..0.6f)

        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Sambung ulang otomatis", color = onGlass, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                Text("Maks 5x, jeda 3 detik, saat koneksi putus sendiri", color = onGlass.copy(alpha = 0.85f), fontSize = 11.sp)
            }
            Switch(autoReconnect, { autoReconnect = it; SettingsStore.setAutoReconnect(ctx, it) })
        }

        Spacer(Modifier.height(8.dp))
        Text(
            "TunnelKu v0.4.0 · id.tunnelku\nIkon: Font Awesome Free 6.5.2 (CC BY 4.0).\nAplikasi tunnel versi kita sendiri — clean-room, tanpa server bawaan, tanpa iklan/tracker. Semua server dari profilmu.",
            color = onGlass.copy(alpha = 0.8f), fontSize = 11.sp,
        )
        Spacer(Modifier.height(16.dp))
    }
}
