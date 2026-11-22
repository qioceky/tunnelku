# TunnelKu v0.6.0 — Remake setia mengikuti perilaku XVEON

Inti tunnel ditulis ulang mengikuti hasil bedah XVEON Tunnel Pro (perilaku stack-nya), dengan tampilan liquid glass TunnelKu tetap.

## Yang berubah

- **Stack TUN baru (TunStack)** — port perilaku forwarder XVEON:
  - SYN-ACK dikirim **setelah** koneksi upstream berhasil dibuka (gagal connect → RST, handshake tidak optimistis).
  - Window TCP tetap 65535, tanpa retransmit/RTO buatan sendiri — keandalan dititipkan ke SSH/TCP di bawahnya, sama seperti aslinya.
  - MSS = clamp(MTU, 1280, 1500) − 140 (default 1260), batas 96 sesi TCP, buffer out-of-order 32 segmen/sesi.
  - DNS diperlakukan khusus: cache per pertanyaan (TTL tetap 45 detik) → DNS native engine → DNS-over-TCP per query (resolver: tujuan paket → 1.1.1.1 → 8.8.8.8) → UDPGW.
  - UDP native maks 48 sesi; ICMP & IPv6 dibuang di dispatcher (blackhole IPv6 anti-bocor tetap dipertahankan).
- **SSH**: urutan rantai diperbaiki — socket → SOCKS5 opsional → **TLS/SNI dulu** (dengan tangga retry + fragmentasi ClientHello) → **payload menggantikan CONNECT** bila aktif → kuras respons handshake maks 4. Direktif payload sekarang lengkap: `[rotate=a|b|c]`, `[split]`, `[instant_split]`, `[delay_split]` (jeda 60 ms), placeholder `[host] [host_port] [ip] [sni] [port] [protocol] [ua] [auth] [proxy_auth] [real_raw] [crlf] [cr] [lf]`, auto-sisip `Proxy-Authorization`. Cipher JSch GCM diutamakan, ServerAlive 30 dtk × 3.
- **Xray**: dialer ditulis ulang sebagai **injektor** seperti aslinya — per aliran: connect → fronting proxy (payload/CONNECT) → TLS → handshake transport → header protokol. Server SOCKS lokal dibuang; stack TUN bicara langsung ke protokol.
  - **Verifikasi sesi**: VPN tidak dinyatakan tersambung sebelum probe DNS `one.one.one.one` via 1.1.1.1 dan HTTP HEAD `/generate_204` benar-benar round-trip; error dibedakan "kredensial ditolak" vs "timeout/upstream".
  - **VMess alterId > 0 sekarang didukung** (mode legacy HmacMD5 + AES-CFB) dengan fallback otomatis AEAD → legacy saat verifikasi.
  - **Flow VLESS diabaikan** (disambung sebagai VLESS polos), sama seperti aslinya.
  - SNI berupa template, tanpa verifikasi hostname (ala aslinya), retry fragmentasi ClientHello saat handshake TLS gagal.
  - Field proxy + payload di editor profil sekarang juga tampil untuk mode Xray (fronting).
- **TUN**: alamat sekarang 10.11.12.2/30, MTU dijepit 1280–1500 (default profil 1400).

## Yang masih belum

- gRPC & REALITY masih ditolak dengan pesan jelas (belum di-port).
- SlowDNS & UDP Custom masih belum kembali (tahap 2 remake); OpenVPN tahap 3.
- **Koneksi Xray ke server asli masih belum terverifikasi di lapangan** — uji host lolos semua (stack 20/20, protokol VMess/SS/VLESS/Trojan vs implementasi resmi, VMess legacy vs server v2fly), tapi belum ada verdict dari server beneran.

Silakan uji: (1) profil SSH yang biasa dipakai, (2) satu profil Xray asli (paling gampang lewat Impor dari Link). Kalau gagal, kirim log-nya — sekarang log membedakan error kredensial vs timeout.
