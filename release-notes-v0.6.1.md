# TunnelKu v0.6.1 — Perbaikan diagnosis profil kosong

Menindaklanjuti log lapangan v0.6.0: profil yang dicoba ternyata **Host server-nya kosong** (`Profil SSH (:443)`), tetapi aplikasi melaporkan "DNS tidak dijawab dalam 2500 ms" lalu mengulang 5× — padahal kegagalannya seketika dan penyebab aslinya tertelan.

## Yang diperbaiki

- **Validasi profil sebelum menyambung.** Host kosong, atau UUID kosong (VLESS/VMess), atau password kosong (Trojan/SS) sekarang langsung gagal dengan pesan jelas — *apa* yang kosong dan *bagaimana* mengisinya (isi manual di editor profil, atau tempel link akun lalu tekan **Impor dari Link**, kemudian Simpan). Error jenis ini **tidak di-retry** lagi.
- **Probe verifikasi tidak lagi menelan penyebab asli.** Kegagalan dial saat pertukaran DNS sekarang muncul di log sebagai "penyebab: …", jadi timeout beneran bisa dibedakan dari koneksi ditolak/dial gagal.
- **Guard host kosong di dialer Xray.** Host kosong tidak lagi diam-diam ter-resolve ke loopback oleh Java; langsung digagalkan dengan pesan terus terang.

Tidak ada perubahan perilaku tunnel dari v0.6.0 selain diagnosis di atas.

## Catatan uji

Profil dari log kemarin memang belum ada host-nya. Untuk uji Xray: buka tab Profil → buat/edit profil → tempel link `vless://…` di kolom impor → **Impor dari Link** → periksa Host/UUID terisi → **Simpan** → sambungkan. Kalau masih gagal, log sekarang menyebut penyebab aslinya — kirim log-nya ke sini.
