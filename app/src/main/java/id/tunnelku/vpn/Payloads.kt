package id.tunnelku.vpn

import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.util.concurrent.atomic.AtomicInteger

/** Nilai-nilai untuk substitusi template payload (placeholder ala XVEON). */
data class PayloadVars(
    val host: String = "",
    val port: Int = 0,
    val sni: String = "",
    val wsHost: String = "",
    val path: String = "",
    val authLine: String = "", // baris "Proxy-Authorization: Basic ...\r\n" atau ""
    val wsKey: String = "",
    val ua: String = "Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36",
)

/**
 * Renderer + pengirim payload ala injector XVEON (`z` untuk SSH, `da` untuk Xray):
 * [rotate=a|b|c] (counter global), [split]/[instant_split]/[delay_split] (60 ms),
 * placeholder [host] [host_port] [ip] [sni] [port] [protocol] [ua] [auth]
 * [proxy_auth] [ws_host] [path] [ws_key] [real_raw] [crlf] [cr] [lf] + escape \r\n \n.
 */
object Payloads {
    private val rotateCounter = AtomicInteger(0)
    private val rotateRegex = Regex("""\[rotate=([^\]]+)]""", RegexOption.IGNORE_CASE)
    private val splitRegex = Regex("""\[(instant_split|delay_split|split)]""", RegexOption.IGNORE_CASE)
    private val delayRegex = Regex("""\[delay_split]""", RegexOption.IGNORE_CASE)

    fun render(template: String, vars: PayloadVars): String {
        var p = template
        // [rotate=...] dievaluasi PERTAMA (counter global per proses, seperti XVEON)
        p = rotateRegex.replace(p) { m ->
            val options = m.groupValues[1].split('|', ',').map { it.trim() }.filter { it.isNotEmpty() }
            if (options.isEmpty()) {
                ""
            } else {
                val idx = (rotateCounter.getAndIncrement() and Int.MAX_VALUE) % options.size
                options[idx]
            }
        }
        fun rep(token: String, value: String) {
            p = p.replace(token, value, ignoreCase = true)
        }
        rep("[host_port]", "${vars.host}:${vars.port}")
        rep("[host]", vars.host)
        rep("[ip]", vars.host)
        rep("[sni]", vars.sni)
        rep("[port]", vars.port.toString())
        rep("[protocol]", "HTTP/1.1")
        rep("[ua]", vars.ua)
        rep("[proxy_auth]", vars.authLine)
        rep("[auth]", vars.authLine)
        rep("[ws_host]", vars.wsHost)
        rep("[path]", vars.path)
        rep("[ws_key]", vars.wsKey)
        rep("[real_raw]", "\r\n\r\n")
        rep("[crlf][crlf]", "\r\n\r\n")
        rep("[crlf]", "\r\n")
        rep("[cr]", "\r")
        rep("[lf]", "\n")
        p = p.replace("\\r\\n", "\r\n").replace("\\n", "\n")
        // Sisipkan Proxy-Authorization otomatis sebagai header terakhir bila ada
        // kredensial, payload belum memuatnya, dan ada blank line penutup.
        if (vars.authLine.isNotEmpty() && !p.contains("Proxy-Authorization:", ignoreCase = true)) {
            val idx = p.indexOf("\r\n\r\n")
            if (idx >= 0) {
                p = p.substring(0, idx + 2) + vars.authLine + p.substring(idx + 2)
            }
        }
        return p
    }

    /** Pecah payload pada marker split dan kirim per segmen (delay 60 ms untuk [delay_split]). */
    fun sendWithSplits(out: OutputStream, rendered: String) {
        val hasDelay = delayRegex.containsMatchIn(rendered)
        val segments = splitRegex.split(rendered)
        segments.forEachIndexed { i, seg ->
            if (seg.isNotEmpty()) {
                out.write(seg.toByteArray(Charsets.ISO_8859_1))
                out.flush()
            }
            if (hasDelay && i < segments.size - 1) {
                try { Thread.sleep(60) } catch (e: InterruptedException) { /* abaikan */ }
            }
        }
    }

    /**
     * Kuras respons HTTP di kepala koneksi (perilaku `z.o` XVEON):
     * byte pertama bukan 'H' → dianggap banner mentah, stream dikembalikan utuh
     * (pushback). Selain itu baca head sampai CRLFCRLF (maks 16384), berhenti di
     * status 101, kuras body Content-Length (1..32768), lanjut maks [maxResponses].
     * Mengembalikan stream yang harus dipakai selanjutnya + status line terakhir.
     */
    fun drainHttpResponses(inp: InputStream, maxResponses: Int): Pair<InputStream, String?> {
        val push = PushbackInputStream(inp, 16384)
        var lastStatus: String? = null
        var count = 0
        while (count < maxResponses) {
            count++
            val first = push.read()
            if (first < 0) break
            if (first != 'H'.code) {
                push.unread(first)
                return push to lastStatus
            }
            push.unread(first)
            val head = readHead(push) ?: break
            val statusLine = head.lineSequence().firstOrNull() ?: ""
            lastStatus = statusLine
            if (statusLine.contains("101")) break
            val cl = Regex("""Content-Length:\s*(\d+)""", RegexOption.IGNORE_CASE)
                .find(head)?.groupValues?.get(1)?.toIntOrNull()
            if (cl != null && cl in 1..32768) {
                var remaining = cl
                val buf = ByteArray(8192)
                while (remaining > 0) {
                    val n = push.read(buf, 0, minOf(buf.size, remaining))
                    if (n < 0) break
                    remaining -= n
                }
            }
        }
        return push to lastStatus
    }

    private fun readHead(inp: InputStream): String? {
        val sb = StringBuilder()
        var state = 0
        var count = 0
        while (count < 16384) {
            val b = inp.read()
            if (b < 0) return if (sb.isEmpty()) null else sb.toString()
            count++
            sb.append(b.toChar())
            state = when {
                state == 0 && b == '\r'.code -> 1
                state == 1 && b == '\n'.code -> 2
                state == 2 && b == '\r'.code -> 3
                state == 3 && b == '\n'.code -> 4
                b == '\r'.code -> 1
                else -> 0
            }
            if (state == 4) break
        }
        return sb.toString()
    }
}
