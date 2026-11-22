import id.tunnelku.model.SshProfile
import id.tunnelku.vpn.DuplexStream
import id.tunnelku.xray.*
import java.io.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

// ===== Util =====
var failures = 0
fun check(name: String, cond: Boolean, detail: String = "") {
    if (cond) println("PASS $name") else { println("FAIL $name $detail"); failures++ }
}

fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

fun runLegacyRef(vararg args: String): String {
    val pb = ProcessBuilder(listOf("/home/hatch/workspace/tunnelku/host-test/go-legacy/legacyref") + args)
    pb.redirectErrorStream(false)
    val p = pb.start()
    val out = p.inputStream.readBytes().toString(Charsets.UTF_8)
    val err = p.errorStream.readBytes().toString(Charsets.UTF_8)
    val code = p.waitFor()
    if (code != 0) throw IllegalStateException("legacyref ${args[0]} gagal ($code): $err")
    return out
}

fun runRef(vararg args: String): String {
    val pb = ProcessBuilder(listOf("/home/hatch/workspace/tunnelku/host-test/go-ref/refcheck") + args)
    pb.redirectErrorStream(false)
    val p = pb.start()
    val out = p.inputStream.readBytes().toString(Charsets.UTF_8)
    val err = p.errorStream.readBytes().toString(Charsets.UTF_8)
    val code = p.waitFor()
    if (code != 0) throw IllegalStateException("refcheck ${args[0]} gagal ($code): $err")
    return out
}

class CaptureStream : DuplexStream {
    val captured = ByteArrayOutputStream()
    private val pipeIn = PipedInputStream(1 shl 16)
    private val pipeOut = PipedOutputStream(pipeIn)
    override val input: InputStream = pipeIn
    override val output: OutputStream = object : OutputStream() {
        override fun write(b: Int) = synchronized(captured) { captured.write(b) }
        override fun write(b: ByteArray, off: Int, len: Int) = synchronized(captured) { captured.write(b, off, len) }
        override fun flush() {}
    }
    fun snapshot(): ByteArray = synchronized(captured) { captured.toByteArray() }
    fun feed(bytes: ByteArray) { pipeOut.write(bytes); pipeOut.flush() }
    override fun close() { try { pipeOut.close() } catch (e: Exception) {} }
}

class FakeDialer(profile: SshProfile, private val stream: DuplexStream) :
    XrayDialer(profile, { true }, { true }, {}) {
    override fun dialServer(timeoutMs: Int): DuplexStream = stream
    override fun dialUdpSocket(): java.net.DatagramSocket = throw UnsupportedOperationException("udp socket tidak dipakai di uji ini")
}

fun tmpFile(name: String, bytes: ByteArray): File {
    val f = File("/tmp/tk-test-$name")
    f.writeBytes(bytes)
    return f
}

// ===== Uji vektor =====
fun testVectors() {
    // SHA-256 murni vs MessageDigest
    val data = ByteArray(1000) { (it * 7 % 251).toByte() }
    check("sha256pure", hex(Sha256Pure.hash(data)) == hex(java.security.MessageDigest.getInstance("SHA-256").digest(data)))
    check("sha256pure-abc", hex(Sha256Pure.hash("abc".toByteArray())) ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    // KDF vs Go (kasus tetap dari sesi riset)
    val key = unhex("00112233445566778899aabbccddeeff")
    check("kdf-0", hex(VmessKdf.kdf(key)) == "faa38697d858e550a836db7d0bb06633888a4c84c01ab8afd6380e0994a95d70")
    check("kdf-1", hex(VmessKdf.kdf(key, "VMess Header AEAD Key".toByteArray())) ==
        "dfea3f40396885de3dcf6f1a011b7402f5e1120b257611c68a1873c01669bb12")
    check("kdf-3", hex(VmessKdf.kdf(key, "VMess Header AEAD Key".toByteArray(), "AUTHIDBYTES".toByteArray(), "NONCEBYTES".toByteArray())) ==
        "fe37121a437d00f941b5deb07d61f27cd3f3deb3ba16c8c925892c3a2c7053e7")
    // KDF vs Go (kasus acak via subprocess)
    val rk = ByteArray(24) { (it * 13 % 256).toByte() }
    val goOut = runRef("kdf", hex(rk), "VMess Header AEAD Key|xyz|12345678").trim().lines()
    check("kdf-go-full", hex(VmessKdf.kdf(rk, "VMess Header AEAD Key".toByteArray(), "xyz".toByteArray(), "12345678".toByteArray())) == goOut[0].trim())
    check("kdf-go-16", hex(VmessKdf.kdf16(rk, "VMess Header AEAD Key".toByteArray(), "xyz".toByteArray(), "12345678".toByteArray())) == goOut[1].trim())
    // SHAKE128: cetak untuk dibandingkan driver dengan Python hashlib
    val shake = Shake128()
    shake.write("vmess-shake-test".toByteArray())
    println("SHAKE " + hex(shake.readBytes(64)))
    val shake2 = Shake128()
    shake2.write(ByteArray(300) { 0xAB.toByte() }) // > rate 168: banyak blok
    println("SHAKE2 " + hex(shake2.readBytes(32)))
    // ChaCha vs Go x/crypto
    val ck = ByteArray(32) { it.toByte() }
    val cn = unhex("070000004041424344454647")
    val caad = unhex("50515253c0c1c2c3c4c5c6c7")
    val cpt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".toByteArray()
    val mine = ChaCha.sealIetf(ck, cn, cpt, caad)
    val goSealed = runRef("chacha", hex(ck), hex(cn), hex(caad), hex(cpt)).trim()
    check("chacha-ietf", hex(mine) == goSealed, "mine=${hex(mine)} go=$goSealed")
    check("chacha-open", ChaCha.openIetf(ck, cn, mine, caad).contentEquals(cpt))
    // XChaCha: bandingkan silang dengan Go lewat konstruksi HChaCha+ IETF di sisi uji? Go x/crypto punya NewX — tambah mode nanti bila perlu; cek roundtrip dulu
    val xk = ByteArray(32) { (255 - it).toByte() }
    val xn = ByteArray(24) { (it * 3).toByte() }
    val xsealed = ChaCha.sealX(xk, xn, cpt, caad)
    check("xchacha-roundtrip", ChaCha.openX(xk, xn, xsealed, caad).contentEquals(cpt))
    // FNV-1a
    println("FNV " + "%08x".format(Crypto.fnv1a32("hello".toByteArray())))
    // EVP BytesToKey & HKDF dicetak untuk driver
    println("EVP " + hex(Crypto.evpBytesToKey("password-uji".toByteArray(), 32)))
}

// ===== VMess =====
fun testVmess(secName: String, secInt: Int) {
    val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
    val profile = SshProfile(xrayProtocol = "vmess", xrayUuid = uuid, xrayVmessSecurity = secName, xraySecurity = "none", xrayNetwork = "tcp")
    val cap = CaptureStream()
    val proto = VmessProto(profile, FakeDialer(profile, cap))
    val stream = proto.openTcp("example.com", 80)
    val payload = "HELLO-VMESS-PAYLOAD"
    stream.output.write(payload.toByteArray())
    stream.output.close()
    val inF = tmpFile("vmess-$secName.bin", cap.snapshot())
    val outF = File("/tmp/tk-test-vmess-$secName.out")
    val res = runRef("vmess-rt", uuid, secInt.toString(), inF.absolutePath, outF.absolutePath)
    val lines = res.trim().lines()
    check("vmess-$secName-header", lines.any { it.contains("addr=example.com") && it.contains("port=80") && it.contains("security=$secInt") }, res)
    check("vmess-$secName-payload", lines.any { it == "PAYLOAD " + hex(payload.toByteArray()) }, res)
    cap.feed(outF.readBytes())
    val got = ByteArray(13)
    var off = 0
    while (off < got.size) {
        val n = stream.input.read(got, off, got.size - off)
        if (n < 0) break
        off += n
    }
    check("vmess-$secName-resp", String(got.copyOf(off)) == "RESP-OK-12345", "got=${String(got.copyOf(off))}")
    stream.close()
}

fun testVmessLegacy() {
    val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
    val profile = SshProfile(xrayProtocol = "vmess", xrayUuid = uuid, xrayAlterId = 2, xrayVmessSecurity = "auto", xraySecurity = "none", xrayNetwork = "tcp")
    val cap = CaptureStream()
    val proto = VmessProto(profile, FakeDialer(profile, cap), legacy = true)
    val stream = proto.openTcp("example.com", 80)
    val payload = "HELLO-VMESS-LEGACY"
    stream.output.write(payload.toByteArray())
    stream.output.close()
    val inF = tmpFile("vmess-legacy.bin", cap.snapshot())
    val outF = File("/tmp/tk-test-vmess-legacy.out")
    val res = runLegacyRef("legacy-rt", uuid, "3", inF.absolutePath, outF.absolutePath)
    val lines = res.trim().lines()
    check("vmess-legacy-header", lines.any { it.contains("addr=example.com") && it.contains("port=80") }, res)
    check("vmess-legacy-payload", lines.any { it == "PAYLOAD " + hex(payload.toByteArray()) }, res)
    cap.feed(outF.readBytes())
    val got = ByteArray(13)
    var off = 0
    while (off < got.size) {
        val n = stream.input.read(got, off, got.size - off)
        if (n < 0) break
        off += n
    }
    check("vmess-legacy-resp", String(got.copyOf(off)) == "RESP-OK-12345", "got=${String(got.copyOf(off))}")
    stream.close()
}

fun testVmessUdp() {
    val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
    val profile = SshProfile(xrayProtocol = "vmess", xrayUuid = uuid, xrayVmessSecurity = "auto", xraySecurity = "none", xrayNetwork = "tcp")
    val cap = CaptureStream()
    val proto = VmessProto(profile, FakeDialer(profile, cap))
    val latch = CountDownLatch(1)
    val replyBox = arrayOfNulls<ByteArray>(1)
    val session = proto.openUdp("8.8.8.8", 53) { _, _, reply ->
        replyBox[0] = reply
        latch.countDown()
    }
    session.send("DNSQUERY123".toByteArray())
    Thread.sleep(200)
    val inF = tmpFile("vmess-udp.bin", cap.snapshot())
    val outF = File("/tmp/tk-test-vmess-udp.out")
    val res = runRef("vmess-rt", uuid, "3", inF.absolutePath, outF.absolutePath)
    check("vmess-udp-payload", res.contains("PAYLOAD " + hex("DNSQUERY123".toByteArray())), res)
    cap.feed(outF.readBytes())
    val ok = latch.await(5, TimeUnit.SECONDS)
    check("vmess-udp-reply", ok && String(replyBox[0]!!) == "RESP-OK-12345", "ok=$ok reply=${replyBox[0]?.let { String(it) }}")
    session.close()
}

// ===== Shadowsocks =====
fun testSsTcp(cipher: String) {
    val profile = SshProfile(xrayProtocol = "ss", xrayMethod = cipher, xrayPassword = "kata-sandi-uji", xraySecurity = "none", xrayNetwork = "tcp")
    val cap = CaptureStream()
    val proto = SsProto(profile, FakeDialer(profile, cap))
    val stream = proto.openTcp("example.com", 8388)
    stream.output.write("HELLO-SS".toByteArray())
    stream.output.flush()
    val inF = tmpFile("ss-$cipher.bin", cap.snapshot())
    val outF = File("/tmp/tk-test-ss-$cipher.out")
    val res = runRef("ss-tcp", cipher, "kata-sandi-uji", inF.absolutePath, outF.absolutePath)
    check("ss-$cipher-header", res.contains("addr=example.com") && res.contains("port=8388"), res)
    check("ss-$cipher-payload", res.contains("PAYLOAD " + hex("HELLO-SS".toByteArray())), res)
    cap.feed(outF.readBytes())
    val got = ByteArray(10)
    var off = 0
    while (off < got.size) {
        val n = stream.input.read(got, off, got.size - off)
        if (n < 0) break
        off += n
    }
    check("ss-$cipher-resp", String(got.copyOf(off)) == "RESP-SS-OK", "got=${String(got.copyOf(off))}")
    stream.close()
}

fun testSsUdp(cipher: String) {
    val profile = SshProfile(xrayProtocol = "ss", xrayMethod = cipher, xrayPassword = "kata-sandi-uji", xraySecurity = "none", xrayNetwork = "tcp")
    val proto = SsProto(profile, FakeDialer(profile, CaptureStream()))
    val pkt = proto.encodeUdpPacket("8.8.8.8", 53, "SSUDP".toByteArray())
    val inF = tmpFile("ssudp-$cipher.bin", pkt)
    val res = runRef("ss-udp-dec", cipher, "kata-sandi-uji", inF.absolutePath)
    check("ssudp-$cipher-dec", res.contains("addr=8.8.8.8") && res.contains("PAYLOAD " + hex("SSUDP".toByteArray())), res)
    val outF = File("/tmp/tk-test-ssudp-$cipher.out")
    runRef("ss-udp-enc", cipher, "kata-sandi-uji", "8.8.8.8", "53", hex("REPLY".toByteArray()), outF.absolutePath)
    val decoded = proto.decodeUdpPacket(outF.readBytes())
    check("ssudp-$cipher-enc", decoded != null && String(decoded) == "REPLY", "decoded=${decoded?.let { String(it) }}")
}

// ===== VLESS & Trojan =====
fun testVless() {
    val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
    val profile = SshProfile(xrayProtocol = "vless", xrayUuid = uuid, xraySecurity = "none", xrayNetwork = "tcp")
    val cap = CaptureStream()
    val proto = VlessProto(profile, FakeDialer(profile, cap))
    val stream = proto.openTcp("example.com", 443)
    val expected = byteArrayOf(0) + Crypto.parseUuid(uuid) + byteArrayOf(0, 1) +
        byteArrayOf(0x01, 0xBB.toByte(), 2, 11) + "example.com".toByteArray()
    check("vless-header", cap.snapshot().contentEquals(expected), "got=${hex(cap.snapshot())} want=${hex(expected)}")
    cap.feed(byteArrayOf(0, 0) + "DATA".toByteArray())
    val got = ByteArray(4)
    var off = 0
    while (off < 4) { val n = stream.input.read(got, off, 4 - off); if (n < 0) break; off += n }
    check("vless-data", String(got.copyOf(off)) == "DATA")
    stream.close()
    // UDP
    val cap2 = CaptureStream()
    val proto2 = VlessProto(profile, FakeDialer(profile, cap2))
    val latch = CountDownLatch(1)
    val box = arrayOfNulls<ByteArray>(1)
    val sess = proto2.openUdp("8.8.8.8", 53) { _, _, payload -> box[0] = payload; latch.countDown() }
    sess.send("PING".toByteArray())
    Thread.sleep(200)
    val snap = cap2.snapshot()
    val tail = snap.copyOfRange(snap.size - 6, snap.size)
    check("vless-udp-frame", tail.contentEquals(byteArrayOf(0, 4) + "PING".toByteArray()), "tail=${hex(tail)}")
    cap2.feed(byteArrayOf(0, 0, 0, 4) + "PONG".toByteArray())
    val ok = latch.await(5, TimeUnit.SECONDS)
    check("vless-udp-reply", ok && String(box[0]!!) == "PONG")
    sess.close()
}

fun testTrojan() {
    val profile = SshProfile(xrayProtocol = "trojan", xrayPassword = "rahasia", xraySecurity = "none", xrayNetwork = "tcp")
    val cap = CaptureStream()
    val proto = TrojanProto(profile, FakeDialer(profile, cap))
    val stream = proto.openTcp("example.com", 443)
    println("TROJANHDR " + hex(cap.snapshot()))
    stream.close()
    // UDP framing
    val cap2 = CaptureStream()
    val proto2 = TrojanProto(profile, FakeDialer(profile, cap2))
    val latch = CountDownLatch(1)
    val box = arrayOfNulls<ByteArray>(1)
    val sess = proto2.openUdp("8.8.8.8", 53) { _, _, payload -> box[0] = payload; latch.countDown() }
    sess.send("PING".toByteArray())
    Thread.sleep(200)
    val snap = cap2.snapshot()
    val expectTail = byteArrayOf(1, 8, 8, 8, 8, 0, 53, 0, 4, 0x0D, 0x0A) + "PING".toByteArray()
    check("trojan-udp-frame", snap.size >= expectTail.size && snap.copyOfRange(snap.size - expectTail.size, snap.size).contentEquals(expectTail),
        "tail=${hex(snap.copyOfRange(maxOf(0, snap.size - expectTail.size), snap.size))}")
    cap2.feed(byteArrayOf(1, 8, 8, 8, 8, 0, 53, 0, 4, 0x0D, 0x0A) + "PONG".toByteArray())
    val ok = latch.await(5, TimeUnit.SECONDS)
    check("trojan-udp-reply", ok && String(box[0]!!) == "PONG")
    sess.close()
}

// ===== WebSocket lewat stdio (driver Python menyambungkan ke peer Go) =====
fun testWsStdio() {
    val base = object : DuplexStream {
        override val input: InputStream = System.`in`
        override val output: OutputStream = System.out
        override fun close() {}
    }
    val ws = WsClientStream(base, "example.com", "/ws-path?ed=2048")
    val small = "hello-websocket".toByteArray()
    ws.output.write(small)
    ws.output.flush()
    val gotSmall = ByteArray(small.size)
    var off = 0
    while (off < gotSmall.size) {
        val n = ws.input.read(gotSmall, off, gotSmall.size - off)
        if (n < 0) break
        off += n
    }
    System.err.println(if (gotSmall.contentEquals(small)) "WS-SMALL-OK" else "WS-SMALL-BAD")
    val big = ByteArray(200_000) { (it % 253).toByte() }
    ws.output.write(big)
    ws.output.flush()
    val gotBig = ByteArray(big.size)
    off = 0
    while (off < gotBig.size) {
        val n = ws.input.read(gotBig, off, gotBig.size - off)
        if (n < 0) break
        off += n
    }
    System.err.println(if (gotBig.contentEquals(big)) "WS-BIG-OK" else "WS-BIG-BAD off=$off")
    ws.close()
}

fun main(args: Array<String>) {
    when (args.getOrNull(0)) {
        "ws" -> { testWsStdio(); return }
        "vectors" -> testVectors()
        "vmess" -> { testVmess("auto", 3); testVmess("chacha20-poly1305", 4); testVmess("none", 5); testVmessUdp(); testVmessLegacy() }
        "ss" -> {
            for (c in listOf("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305")) {
                testSsTcp(c); testSsUdp(c)
            }
        }
        "vless" -> testVless()
        "trojan" -> testTrojan()
        else -> { testVectors(); testVmess("auto", 3); testVmess("chacha20-poly1305", 4); testVmess("none", 5); testVmessUdp(); testVless(); testTrojan() }
    }
    println(if (failures == 0) "ALL-DONE" else "FAILURES=$failures")
    if (failures > 0) kotlin.system.exitProcess(1)
}
