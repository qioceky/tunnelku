package id.tunnelku.vpn.stack

import java.io.InputStream
import java.io.OutputStream

/** Handle stream TCP upstream — padanan `p` + `b8` XVEON. */
interface TcpHandle {
    val input: InputStream
    val output: OutputStream
    fun isConnected(): Boolean
    fun setTimeout(ms: Int)
    fun close()
}

/** Handle sesi UDP native (mode Xray) — padanan `c8` XVEON. Destinasi tetap per sesi. */
interface UdpHandle {
    fun isAlive(): Boolean
    /**
     * Daftarkan penerima; dipanggil sekali sebelum [send] pertama.
     * onPacket: (srcIp int, srcPort, data, off, len) — alamat sumber paket balasan
     * (untuk asosiasi bersama ala Trojan, alamat dibaca dari paket protokolnya).
     */
    fun startReceiver(onPacket: (srcIp: Int, srcPort: Int, data: ByteArray, off: Int, len: Int) -> Unit)
    fun send(data: ByteArray, off: Int, len: Int)
    fun flush()
    fun setTimeout(ms: Int)
    fun close()
}

/**
 * Kontrak engine transport — port interface `a8` XVEON.
 * Diimplementasikan adapter SSH (JSch) dan adapter Xray (klien protokol Kotlin).
 */
interface OutboundEngine {
    /** a8.I — engine/sesi masih terhubung? */
    fun isConnected(): Boolean

    /** a8.o — buka stream TCP ke (host, port); originator = alamat TUN klien. */
    fun openTcp(host: String, port: Int, orgIp: String, orgPort: Int, timeoutMs: Int): TcpHandle

    /** a8.Il — buka sesi UDP native ke (dstIp, dstPort). Hanya mode Xray. */
    fun openUdpSession(dstIp: String, dstPort: Int, timeoutMs: Int): UdpHandle

    /** a8.O — tukar pesan DNS synchronous lewat engine (Xray); null = tidak didukung/gagal. */
    fun exchangeDns(host: String, payload: ByteArray): ByteArray?

    /** a8.l1 — UDP native tersedia? (SSH: false) */
    fun nativeUdpAvailable(): Boolean

    /** a8.lI — forwarding UDP (UDPGW / DoT) aktif? */
    fun udpForwardingEnabled(): Boolean

    /** Buka stream UDPGW (mode SSH); null = tidak tersedia. */
    fun openUdpGw(): TcpHandle?

    /** Semua sesi UDP dari engine ini berbagi satu asosiasi per klien (Trojan). */
    fun sharesUdpAssociation(): Boolean = false

    /** a8.l — tutup engine. */
    fun close()
}
