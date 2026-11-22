package id.tunnelku.vpn

import android.util.Base64
import id.tunnelku.model.SshProfile
import org.json.JSONObject
import java.net.URLDecoder

/** Pembangun parameter Xray (skema datar untuk mesin Go) + parser link berbagi. */
object XraySupport {

    fun buildParamsJson(p: SshProfile, socksPort: Int): String {
        val o = JSONObject()
        o.put("protocol", p.xrayProtocol)
        o.put("address", p.host)
        o.put("port", p.port)
        o.put("id", p.xrayUuid)
        o.put("password", p.xrayPassword)
        o.put("method", p.xrayMethod)
        o.put("alterId", p.xrayAlterId)
        o.put("vmessSecurity", p.xrayVmessSecurity)
        o.put("flow", p.xrayFlow)
        o.put("network", p.xrayNetwork)
        o.put("security", p.xraySecurity)
        o.put("sni", p.xraySni)
        o.put("fingerprint", p.xrayFingerprint)
        o.put("alpn", p.xrayAlpn)
        o.put("publicKey", p.xrayPublicKey)
        o.put("shortId", p.xrayShortId)
        o.put("spiderX", p.xraySpiderX)
        o.put("wsPath", p.xrayWsPath)
        o.put("wsHost", p.xrayWsHost)
        o.put("grpcService", p.xrayGrpcService)
        o.put("socksPort", socksPort)
        return o.toString()
    }

    /** Parse link vless://, vmess://, trojan://, ss:// menjadi profil mode XRAY. Null bila tak dikenal. */
    fun parseShareLink(raw: String, base: SshProfile): SshProfile? {
        val link = raw.trim()
        return try {
            when {
                link.startsWith("vless://") -> parseVlessTrojan(link, "vless", base)
                link.startsWith("trojan://") -> parseVlessTrojan(link, "trojan", base)
                link.startsWith("vmess://") -> parseVmess(link, base)
                link.startsWith("ss://") -> parseSs(link, base)
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun dec(s: String): String = try {
        URLDecoder.decode(s, "UTF-8")
    } catch (e: Exception) {
        s
    }

    private fun b64decode(s: String): String {
        var t = s.trim()
        val pad = (4 - t.length % 4) % 4
        t += "=".repeat(pad)
        val bytes = try {
            Base64.decode(t, Base64.URL_SAFE or Base64.NO_WRAP)
        } catch (e: Exception) {
            Base64.decode(t, Base64.NO_WRAP)
        }
        return String(bytes, Charsets.UTF_8)
    }

    private fun queryParams(q: String?): Map<String, String> {
        if (q.isNullOrBlank()) return emptyMap()
        return q.split("&").mapNotNull {
            val i = it.indexOf('=')
            if (i < 0) null else dec(it.substring(0, i)) to dec(it.substring(i + 1))
        }.toMap()
    }

    private fun parseVlessTrojan(link: String, proto: String, base: SshProfile): SshProfile? {
        val rest = link.substringAfter("://")
        val name = dec(rest.substringAfter("#", ""))
        val noFrag = rest.substringBefore("#")
        val q = queryParams(noFrag.substringAfter("?", ""))
        val authority = noFrag.substringBefore("?")
        val at = authority.lastIndexOf('@')
        if (at < 0) return null
        val userInfo = dec(authority.substring(0, at))
        val hostPort = authority.substring(at + 1)
        val host = hostPort.substringBefore(":").removeSurrounding("[", "]")
        val port = hostPort.substringAfter(":", "443").substringBefore("/").toIntOrNull() ?: 443

        var p = base.copy(
            mode = SshProfile.MODE_XRAY,
            name = name.ifBlank { base.name },
            host = host,
            port = port,
            xrayProtocol = proto,
            xrayNetwork = when (q["type"]?.lowercase()) {
                "ws" -> "ws"; "grpc" -> "grpc"; else -> "tcp"
            },
            xraySecurity = when (q["security"]?.lowercase()) {
                "tls" -> "tls"; "reality" -> "reality"; else -> "none"
            },
            xraySni = q["sni"] ?: "",
            xrayFingerprint = q["fp"] ?: "chrome",
            xrayAlpn = q["alpn"] ?: "",
            xrayPublicKey = q["pbk"] ?: "",
            xrayShortId = q["sid"] ?: "",
            xraySpiderX = q["spx"] ?: "",
            xrayWsPath = q["path"] ?: "/",
            xrayWsHost = q["host"] ?: "",
            xrayGrpcService = q["serviceName"] ?: "",
        )
        p = if (proto == "vless") {
            p.copy(xrayUuid = userInfo, xrayFlow = q["flow"] ?: "")
        } else {
            p.copy(xrayPassword = userInfo, xrayFlow = q["flow"] ?: "")
        }
        return p
    }

    private fun parseVmess(link: String, base: SshProfile): SshProfile? {
        val json = JSONObject(b64decode(link.substringAfter("vmess://").substringBefore("#")))
        val tls = json.optString("tls", "")
        return base.copy(
            mode = SshProfile.MODE_XRAY,
            name = json.optString("ps", base.name).ifBlank { base.name },
            host = json.optString("add", ""),
            port = json.optString("port", "443").toIntOrNull() ?: 443,
            xrayProtocol = "vmess",
            xrayUuid = json.optString("id", ""),
            xrayAlterId = json.optString("aid", "0").toIntOrNull() ?: 0,
            xrayVmessSecurity = json.optString("scy", "auto").ifBlank { "auto" },
            xrayNetwork = when (json.optString("net", "tcp").lowercase()) {
                "ws" -> "ws"; "grpc" -> "grpc"; else -> "tcp"
            },
            xraySecurity = when (tls.lowercase()) {
                "tls" -> "tls"; "reality" -> "reality"; else -> "none"
            },
            xraySni = json.optString("sni", ""),
            xrayFingerprint = json.optString("fp", "chrome"),
            xrayAlpn = json.optString("alpn", ""),
            xrayWsPath = json.optString("path", "/"),
            xrayWsHost = json.optString("host", ""),
            xrayGrpcService = json.optString("serviceName", json.optString("path", "")),
        )
    }

    private fun parseSs(link: String, base: SshProfile): SshProfile? {
        val rest = link.substringAfter("ss://")
        val name = dec(rest.substringAfter("#", ""))
        val noFrag = rest.substringBefore("#").substringBefore("?")
        val method: String
        val password: String
        val host: String
        val port: Int
        val at = noFrag.lastIndexOf('@')
        if (at >= 0 && !noFrag.substring(0, at).contains(":")) {
            // ss://base64(method:password)@host:port
            val cred = b64decode(dec(noFrag.substring(0, at)))
            method = cred.substringBefore(":")
            password = cred.substringAfter(":", "")
            val hp = noFrag.substring(at + 1)
            host = hp.substringBefore(":")
            port = hp.substringAfter(":", "8388").toIntOrNull() ?: 8388
        } else {
            // ss://base64(method:password@host:port)
            val all = b64decode(noFrag)
            val at2 = all.lastIndexOf('@')
            if (at2 < 0) return null
            val cred = all.substring(0, at2)
            method = cred.substringBefore(":")
            password = cred.substringAfter(":", "")
            val hp = all.substring(at2 + 1)
            host = hp.substringBefore(":")
            port = hp.substringAfter(":", "8388").toIntOrNull() ?: 8388
        }
        return base.copy(
            mode = SshProfile.MODE_XRAY,
            name = name.ifBlank { base.name },
            host = host,
            port = port,
            xrayProtocol = "ss",
            xrayMethod = method,
            xrayPassword = password,
            xrayNetwork = "tcp",
            xraySecurity = "none",
        )
    }
}
