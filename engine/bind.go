package engine

// Menahan dependensi golang.org/x/mobile/bind agar tidak dibuang
// `go mod tidy` — paket ini wajib ada saat gomobile bind berjalan.
import _ "golang.org/x/mobile/bind"
