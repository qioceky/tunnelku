package id.tunnelku.vpn

import java.io.FilterOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket

/**
 * Socket delegasi: meneruskan semua ke socket fisik, tapi getInputStream /
 * getOutputStream bisa diganti (mis. stream pushback hasil kuras respons HTTP,
 * agar tidak ada byte yang hilang saat dibungkus SSLSocket).
 */
open class StreamSocket(
    protected val delegate: Socket,
    private val inOverride: InputStream? = null,
    private val outOverride: OutputStream? = null,
) : Socket() {
    override fun getInputStream(): InputStream = inOverride ?: delegate.getInputStream()
    override fun getOutputStream(): OutputStream = outOverride ?: delegate.getOutputStream()
    override fun close() = delegate.close()
    override fun isClosed(): Boolean = delegate.isClosed
    override fun isConnected(): Boolean = delegate.isConnected
    override fun getInetAddress(): InetAddress = delegate.inetAddress
    override fun getPort(): Int = delegate.port
    override fun getLocalPort(): Int = delegate.localPort
    override fun getLocalAddress(): InetAddress = delegate.localAddress
    override fun setSoTimeout(timeout: Int) { delegate.soTimeout = timeout }
    override fun getSoTimeout(): Int = delegate.soTimeout
    override fun setTcpNoDelay(on: Boolean) { delegate.tcpNoDelay = on }
    override fun getTcpNoDelay(): Boolean = delegate.tcpNoDelay
    override fun setKeepAlive(on: Boolean) { delegate.keepAlive = on }
    override fun getKeepAlive(): Boolean = delegate.keepAlive
}

/**
 * Socket pembungkus yang memecah ClientHello pertama menjadi beberapa
 * penulisan TCP (fragmentasi DPI ala XVEON `x`/`t`): potong setelah header
 * record (5 byte) dan di tengah hostname SNI, jeda 20 ms antar potongan.
 * Hanya penulisan pertama yang difragmentasi.
 */
class FragmentingSocket(
    delegate: Socket,
    private val sni: String,
    inOverride: InputStream? = null,
) : StreamSocket(delegate, inOverride) {

    private val fragOut: OutputStream by lazy {
        object : FilterOutputStream(delegate.getOutputStream()) {
            private var fragmented = false

            override fun write(b: ByteArray, off: Int, len: Int) {
                if (fragmented || len < 10) {
                    out.write(b, off, len)
                    return
                }
                fragmented = true
                val end = off + len
                val sniBytes = sni.toByteArray(Charsets.US_ASCII)
                var sniMid = -1
                if (sniBytes.isNotEmpty()) {
                    outer@ for (i in off..end - sniBytes.size) {
                        for (j in sniBytes.indices) {
                            if (b[i + j] != sniBytes[j]) continue@outer
                        }
                        sniMid = i + sniBytes.size / 2
                        break
                    }
                }
                val cuts = sortedSetOf(off + 5)
                if (sniMid > off + 5 && sniMid < end) cuts.add(sniMid)
                var pos = off
                for (cut in cuts) {
                    if (cut <= pos || cut >= end) continue
                    out.write(b, pos, cut - pos)
                    out.flush()
                    try { Thread.sleep(20) } catch (e: InterruptedException) { /* abaikan */ }
                    pos = cut
                }
                out.write(b, pos, end - pos)
                out.flush()
            }
        }
    }

    override fun getOutputStream(): OutputStream = fragOut
}
