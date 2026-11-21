# TunnelKu

Aplikasi Android tunnel VPN versi kita sendiri (clean-room, `id.tunnelku`) — UI Bahasa Indonesia bergaya **liquid glass soft** dengan latar transparan 3 mode: tembus wallpaper HP, gambar custom, atau gradasi bawaan (plus slider blur/dim/kejernihan kaca).

## Peta versi

- **v0.1.0 — Mode SSH**: JSch (fork mwiede) di atas jalur socket kustom — proxy remote HTTP (CONNECT / payload) & SOCKS5, payload kustom (`[host]`, `[host_port]`, `[crlf]`), TLS + SNI, autentikasi password / private key. TUN memakai tumpukan TCP userspace murni Kotlin di atas channel direct-tcpip; DNS diteruskan via DNS-over-TCP di dalam SSH.
- v0.2 — UDP Custom + SlowDNS (DNSTT) + UDP penuh (UDPGW)
- v0.3 — Xray (VLESS/VMess/Trojan/SS) + subscription
- v0.4 — OpenVPN
- v0.5 — Format config terenkripsi sendiri, Payload Generator, ShareNet, filter per-app

## Batas jujur v0.1

- UDP selain DNS (port 53) belum diteruskan — dibuang & dicatat di log. Game/VoIP belum cocok di versi ini.
- IPv6 diarahkan ke TUN lalu dibuang (anti-bocor), belum diteruskan.
- Tumpukan TCP-nya ringkas (go-back-N); cukup untuk browsing/API umum, bukan pengganti stack kernel.

## Build

Hanya via GitHub Actions (`.github/workflows/build.yml`). Keystore tetap dipulihkan dari secret repo (`TUNNELKU_KEYSTORE_BASE64` dkk.) dan sidik jari APK diverifikasi terhadap pin `3978BE01…C6440F` sebelum artefak diunggah.
