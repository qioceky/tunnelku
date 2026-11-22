package id.tunnelku.vpn

import java.io.InputStream
import java.io.OutputStream

/** Stub host-test: cermin interface DuplexStream di Transport.kt. */
interface DuplexStream {
    val input: InputStream
    val output: OutputStream
    fun close()
}
