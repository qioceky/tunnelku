module tunnelku/engine

go 1.20

require (
	github.com/apernet/hysteria/core v1.3.5
	github.com/quic-go/quic-go v0.35.1
	github.com/xtaci/kcp-go/v5 v5.6.1
	github.com/xtaci/smux v1.5.19
	github.com/xtls/xray-core v1.8.3
	golang.org/x/mobile v0.0.0-20230531173138-3c911d8e3eda
	www.bamsoftware.com/git/dnstt.git v0.0.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/coreos/go-iptables v0.6.0 // indirect
	github.com/dgryski/go-metro v0.0.0-20211217172704-adc40b04c140 // indirect
	github.com/flynn/noise v1.0.0 // indirect
	github.com/gaukas/godicttls v0.0.3 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/pprof v0.0.0-20230602150820-91b7bce49751 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.1 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/klauspost/cpuid/v2 v2.2.6 // indirect
	github.com/klauspost/reedsolomon v1.12.0 // indirect
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40 // indirect
	github.com/onsi/ginkgo/v2 v2.11.0 // indirect
	github.com/oschwald/geoip2-golang v1.8.0 // indirect
	github.com/oschwald/maxminddb-golang v1.10.0 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pires/go-proxyproto v0.7.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/quic-go/qtls-go1-19 v0.3.2 // indirect
	github.com/quic-go/qtls-go1-20 v0.2.2 // indirect
	github.com/refraction-networking/utls v1.6.6 // indirect
	github.com/riobard/go-bloom v0.0.0-20200614022211-cdc8013cb5b3 // indirect
	github.com/sagernet/sing v0.2.5 // indirect
	github.com/sagernet/sing-shadowsocks v0.2.2 // indirect
	github.com/seiflotfy/cuckoofilter v0.0.0-20220411075957-e3b120b3f5fb // indirect
	github.com/templexxx/cpu v0.1.0 // indirect
	github.com/templexxx/xorsimd v0.4.2 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/txthinking/runnergroup v0.0.0-20210608031112-152c7c4432bf // indirect
	github.com/txthinking/socks5 v0.0.0-20220212043548-414499347d4a // indirect
	github.com/txthinking/x v0.0.0-20210326105829-476fab902fbe // indirect
	github.com/v2fly/ss-bloomring v0.0.0-20210312155135-28617310f63e // indirect
	github.com/xtls/reality v0.0.0-20230613075828-e07c3b04b983 // indirect
	golang.org/x/crypto v0.21.0 // indirect
	golang.org/x/exp v0.0.0-20230522175609-2e198f4a06a1 // indirect
	golang.org/x/mod v0.11.0 // indirect
	golang.org/x/net v0.23.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.10.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230711160842-782d3b101e98 // indirect
	google.golang.org/grpc v1.57.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	lukechampine.com/blake3 v1.2.1 // indirect
)

// Sumber resmi dibundel saat build CI (lihat .github/workflows/build.yml):
// dnstt dari www.bamsoftware.com/git/dnstt.git, hysteria dari tag v1.3.5.
replace www.bamsoftware.com/git/dnstt.git => ./dnstt-src

replace github.com/apernet/hysteria/core => ./hysteria-src/core

// quic-go harus fork apernet (sama seperti replace di go.mod core hysteria).
replace github.com/quic-go/quic-go => github.com/apernet/quic-go v0.34.1-0.20230507231629-ec008b7e8473

// kcp-go/smux versi baru menuntut Go 1.21; core hysteria menuntut Go <= 1.20 (qtls).
replace github.com/xtaci/kcp-go/v5 => github.com/xtaci/kcp-go/v5 v5.6.1

replace github.com/xtaci/smux => github.com/xtaci/smux v1.5.19

replace github.com/refraction-networking/utls v1.6.6 => github.com/refraction-networking/utls v1.3.2
