package engine

import "testing"

// Reproduksi laporan lapangan v0.4.0: instance Xray harus berhasil dibuat
// untuk semua kombinasi protokol/keamanan (tanpa koneksi ke server).
func TestStartXrayInstances(t *testing.T) {
	cases := map[string]string{
		"vless-tls":     `{"protocol":"vless","address":"127.0.0.1","port":443,"id":"00000000-0000-0000-0000-000000000000","network":"tcp","security":"tls","sni":"example.com","fingerprint":"chrome","socksPort":11099}`,
		"vless-reality": `{"protocol":"vless","address":"127.0.0.1","port":443,"id":"00000000-0000-0000-0000-000000000000","flow":"xtls-rprx-vision","network":"tcp","security":"reality","sni":"example.com","fingerprint":"chrome","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":"01ab","socksPort":11099}`,
		"vless-ws-tls":  `{"protocol":"vless","address":"127.0.0.1","port":443,"id":"00000000-0000-0000-0000-000000000000","network":"ws","security":"tls","sni":"example.com","wsPath":"/ws","wsHost":"example.com","socksPort":11099}`,
		"vmess-none":    `{"protocol":"vmess","address":"127.0.0.1","port":10086,"id":"00000000-0000-0000-0000-000000000000","security":"none","socksPort":11099}`,
		"trojan-tls":    `{"protocol":"trojan","address":"127.0.0.1","port":443,"password":"secret","security":"tls","sni":"example.com","socksPort":11099}`,
		"ss-classic":    `{"protocol":"ss","address":"127.0.0.1","port":8388,"password":"secret","method":"aes-256-gcm","socksPort":11099}`,
		"ss-2022":       `{"protocol":"ss","address":"127.0.0.1","port":8388,"password":"AAAAAAAAAAAAAAAAAAAAAA==","method":"2022-blake3-aes-128-gcm","socksPort":11099}`,
	}
	for name, js := range cases {
		if err := StartXray(js); err != nil {
			t.Fatalf("%s: StartXray gagal: %v", name, err)
		}
		StopXray()
		t.Logf("%s: OK", name)
	}
}
