// Package engine adalah mesin Go TunnelKu yang di-bind via gomobile:
// klien DNSTT (SlowDNS) resmi dan klien Hysteria v1 (UDP Custom) resmi,
// masing-masing disajikan lewat antarmuka lokal sederhana untuk Kotlin.
package engine

// StartDNSTT memulai klien SlowDNS/DNSTT.
// resolver: server DNS rekursif "host:port" (UDP). domain: domain tunnel
// server. pubkey: kunci publik server DNSTT (64 hex). listen: alamat
// listener TCP lokal, mis. "127.0.0.1:11081" — setiap koneksi ke listener
// ini diteruskan server DNSTT ke tujuan yang ia layani (umumnya SSH).
func StartDNSTT(resolver, domain, pubkey, listen string) error {
	return startDNSTT(resolver, domain, pubkey, listen)
}

// StopDNSTT menghentikan klien DNSTT.
func StopDNSTT() { stopDNSTT() }

// StartHysteria memulai klien UDP Custom (Hysteria v1) dan server SOCKS5
// lokal di socks ("127.0.0.1:port") yang mendukung CONNECT dan
// UDP ASSOCIATE. auth = "user:password" akun server.
func StartHysteria(server, auth, obfs, sni string, insecure bool, socks string) error {
	return startHysteria(server, auth, obfs, sni, insecure, socks)
}

// StopHysteria menghentikan klien Hysteria.
func StopHysteria() { stopHysteria() }

// StartXray memulai core Xray dari config JSON (inbound SOCKS5 lokal +
// outbound sesuai profil). socksPort di dalam config menentukan port lokal.
func StartXray(configJSON string) error { return startXray(configJSON) }

// StopXray menghentikan core Xray.
func StopXray() { stopXray() }
