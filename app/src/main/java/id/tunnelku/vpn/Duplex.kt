package id.tunnelku.vpn

import java.io.InputStream
import java.io.OutputStream

/** Satu aliran dupleks (TCP) yang dibuka lewat transport aktif. */
interface DuplexStream {
    val input: InputStream
    val output: OutputStream
    fun close()
}
