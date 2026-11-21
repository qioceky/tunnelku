package id.tunnelku.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class TunnelStatus { DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING, ERROR }

/** Keadaan tunnel + log yang dibagi antara service dan UI. */
object LogBus {
    private val _status = MutableStateFlow(TunnelStatus.DISCONNECTED)
    val status: StateFlow<TunnelStatus> = _status

    private val _logs = MutableStateFlow<List<String>>(emptyList())
    val logs: StateFlow<List<String>> = _logs

    private val _traffic = MutableStateFlow(0L to 0L) // down, up
    val traffic: StateFlow<Pair<Long, Long>> = _traffic

    @Volatile var connectedSinceMs: Long = 0L
    @Volatile var activeProfileName: String = ""

    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    fun setStatus(s: TunnelStatus) {
        _status.value = s
        if (s == TunnelStatus.CONNECTED) connectedSinceMs = System.currentTimeMillis()
        if (s == TunnelStatus.DISCONNECTED || s == TunnelStatus.ERROR) {
            connectedSinceMs = 0L
        }
    }

    fun log(msg: String) {
        val line = "[${fmt.format(Date())}] $msg"
        val cur = _logs.value + line
        _logs.value = if (cur.size > 400) cur.takeLast(400) else cur
    }

    fun clearLogs() { _logs.value = emptyList() }

    fun addTraffic(down: Long, up: Long) {
        val (d, u) = _traffic.value
        _traffic.value = (d + down) to (u + up)
    }

    fun resetTraffic() { _traffic.value = 0L to 0L }
}
