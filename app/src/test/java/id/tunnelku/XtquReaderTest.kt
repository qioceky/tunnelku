package id.tunnelku

import id.tunnelku.model.SshProfile
import id.tunnelku.model.XtquException
import id.tunnelku.model.XtquReader
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Uji silang Kotlin ↔ Python untuk impor .xtqu (v0.7.0).
 * Vektor dibuat implementasi referensi `xtqu_format.py` (FORMAT-XTQU.md):
 * flag0 = profil ASLI user (jumat+CONFERENC, VLESS/WS), flag1 = multi-profil
 * password "rahasia", longpw = password >15 karakter (anti-truncasi XVEON).
 */
class XtquReaderTest {

    private fun vector(name: String): String =
        javaClass.classLoader!!.getResourceAsStream(name)!!.bufferedReader().readText().trim()

    @Test
    fun flag0_sampleReal_decryptsAndMaps() {
        val r = XtquReader.importAll(vector("vector-flag0-sample-real.xtqu"))
        assertEquals(1, r.imported.size)
        assertEquals(0, r.skippedExpired)
        val p = r.imported[0]
        assertEquals("jumat+CONFERENC", p.name)
        assertEquals(SshProfile.MODE_XRAY, p.mode)
        assertEquals("ten.duduls.my.id", p.host)
        assertEquals(443, p.port)
        assertEquals("178200df-d2ab-462b-9d00-349e4d8d0c3b", p.xrayUuid)
        assertEquals("vless", p.xrayProtocol)
        assertEquals("ws", p.xrayNetwork)
        assertEquals("/vless", p.xrayWsPath)
        assertEquals("m.instagram.com", p.xraySni)
        assertTrue(p.sniEnabled)
        // xrayAllowInsecure=true WAJIB diteruskan (celah parser link v0.6.1).
        assertTrue(p.xrayInsecure)
        assertEquals("tls", p.xraySecurity)
        assertEquals(0, p.xrayAlterId)
        assertEquals("", p.xrayFlow)
        assertTrue(p.udpgwEnabled)
        assertEquals("127.0.0.1", p.udpgwHost)
        assertEquals(7300, p.udpgwPort)
        assertFalse(p.lockedByCreator)
    }

    @Test
    fun flag1_multiProfile_decryptsWithPassword() {
        val r = XtquReader.importAll(vector("vector-flag1.xtqu"), "rahasia")
        assertEquals(2, r.imported.size)
        val ssh = r.imported[0]
        assertEquals(SshProfile.MODE_SSH, ssh.mode)
        assertEquals("SSH Uji", ssh.name)
        assertEquals("ssh.contoh.id", ssh.host)
        assertEquals("user1", ssh.username)
        assertEquals("pass1", ssh.password)
        val xray = r.imported[1]
        assertEquals(SshProfile.MODE_XRAY, xray.mode)
        assertEquals("Xray Uji", xray.name)
        assertTrue(xray.xrayInsecure)
    }

    @Test
    fun longPassword_fullWorks_truncationRejected() {
        val blob = vector("vector-flag1-longpw.xtqu")
        val longPw = "password-panjang-lebih-dari-15-karakter"
        val r = XtquReader.importAll(blob, longPw)
        assertEquals(2, r.imported.size)
        // Potongan 15 char ala XVEON WAJIB ditolak — bukti tak ada truncasi.
        assertThrows(XtquException::class.java) {
            XtquReader.importAll(blob, longPw.substring(0, 15))
        }
    }

    @Test
    fun wrongPassword_rejected() {
        assertThrows(XtquException::class.java) {
            XtquReader.importAll(vector("vector-flag1.xtqu"), "salah")
        }
    }

    @Test
    fun flag1WithoutPassword_rejected() {
        assertThrows(XtquException::class.java) {
            XtquReader.importAll(vector("vector-flag1.xtqu"), "")
        }
    }

    @Test
    fun tamperedIterations_rejected() {
        val bad = vector("vector-flag1.xtqu").replace(":120000:", ":120001:")
        assertThrows(XtquException::class.java) { XtquReader.importAll(bad, "rahasia") }
    }

    @Test
    fun tamperedFlag_rejected() {
        val bad = vector("vector-flag1.xtqu").replace("XTQ1:1:", "XTQ1:0:")
        assertThrows(XtquException::class.java) { XtquReader.importAll(bad, "rahasia") }
    }

    @Test
    fun weakIterations_rejected() {
        val bad = vector("vector-flag1.xtqu").replace(":120000:", ":9999:")
        assertThrows(XtquException::class.java) { XtquReader.importAll(bad, "rahasia") }
    }

    @Test
    fun xvn1Blob_rejected() {
        assertThrows(XtquException::class.java) {
            XtquReader.importAll("XVN1:0:AAAA:BBBB:CCCC", "")
        }
    }

    @Test
    fun needsPassword_peeksFlag() {
        assertTrue(XtquReader.needsPassword(vector("vector-flag1.xtqu")))
        assertFalse(XtquReader.needsPassword(vector("vector-flag0-sample-real.xtqu")))
    }

    @Test
    fun expiryLogic() {
        assertTrue(XtquReader.isExpired(1L, nowMs = 2L))
        assertFalse(XtquReader.isExpired(0L, nowMs = 2L))
        assertFalse(XtquReader.isExpired(9_999_999_999_999L, nowMs = 2L))
    }

    @Test
    fun emptyHost_rejectedAsIncomplete() {
        val bad = org.json.JSONObject(
            mapOf("name" to "Tanpa Host", "mode" to "ssh", "sshHost" to "", "sshPort" to 443),
        )
        assertThrows(XtquException::class.java) { XtquReader.mapProfile(bad, false) }
    }
}
