module tunnelku/engine

go 1.20

require (
	github.com/apernet/hysteria/core v1.3.5
	github.com/quic-go/quic-go v0.34.0
	github.com/xtaci/kcp-go/v5 v5.6.8
	github.com/xtaci/smux v1.5.24
	www.bamsoftware.com/git/dnstt.git v0.0.0-00010101000000-000000000000
)

// Sumber resmi dibundel saat build CI (lihat .github/workflows/build.yml):
// dnstt dari www.bamsoftware.com/git/dnstt.git, hysteria dari tag v1.3.5.
replace www.bamsoftware.com/git/dnstt.git => ./dnstt-src

replace github.com/apernet/hysteria/core => ./hysteria-src/core

require (
	github.com/coreos/go-iptables v0.6.0 // indirect
	github.com/flynn/noise v1.0.0 // indirect
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/pprof v0.0.0-20230131232505-5a9e8f65f08f // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.1 // indirect
	github.com/klauspost/cpuid/v2 v2.2.6 // indirect
	github.com/klauspost/reedsolomon v1.12.0 // indirect
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40 // indirect
	github.com/onsi/ginkgo/v2 v2.8.0 // indirect
	github.com/oschwald/geoip2-golang v1.8.0 // indirect
	github.com/oschwald/maxminddb-golang v1.10.0 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/quic-go/qtls-go1-19 v0.3.2 // indirect
	github.com/quic-go/qtls-go1-20 v0.2.2 // indirect
	github.com/templexxx/cpu v0.1.0 // indirect
	github.com/templexxx/xorsimd v0.4.2 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/txthinking/runnergroup v0.0.0-20210608031112-152c7c4432bf // indirect
	github.com/txthinking/socks5 v0.0.0-20220212043548-414499347d4a // indirect
	github.com/txthinking/x v0.0.0-20210326105829-476fab902fbe // indirect
	golang.org/x/crypto v0.21.0 // indirect
	golang.org/x/exp v0.0.0-20230131160201-f062dba9d201 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/net v0.23.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/tools v0.6.0 // indirect
)

replace github.com/quic-go/quic-go => github.com/apernet/quic-go v0.34.1-0.20230507231629-ec008b7e8473

replace github.com/xtaci/kcp-go/v5 => github.com/xtaci/kcp-go/v5 v5.6.1

replace github.com/xtaci/smux => github.com/xtaci/smux v1.5.19
