package engine

// Mode Xray: core Xray resmi (github.com/xtls/xray-core v1.8.3).
// Config dibangun terprogram dari skema JSON datar milik TunnelKu
// (bukan loader serial xray) agar paket QUIC/DNS xray yang bentrok
// dengan fork quic-go Hysteria tidak ikut terkompilasi.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/xtls/xray-core/app/dispatcher"
	applog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessout "github.com/xtls/xray-core/proxy/vmess/outbound"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/websocket"

	clog "github.com/xtls/xray-core/common/log"

	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/proxy/shadowsocks"
	_ "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
)

// xrayParams adalah skema datar dari sisi Kotlin.
type xrayParams struct {
	Protocol      string `json:"protocol"` // vless|vmess|trojan|ss
	Address       string `json:"address"`
	Port          int    `json:"port"`
	ID            string `json:"id"`       // uuid vless/vmess
	Password      string `json:"password"` // trojan/ss
	Method        string `json:"method"`   // ss
	AlterID       int    `json:"alterId"`  // vmess
	VmessSecurity string `json:"vmessSecurity"`
	Flow          string `json:"flow"` // vless
	Network       string `json:"network"` // tcp|ws|grpc
	Security      string `json:"security"` // none|tls|reality
	SNI           string `json:"sni"`
	Fingerprint   string `json:"fingerprint"`
	ALPN          string `json:"alpn"`
	PublicKey     string `json:"publicKey"` // reality (base64url)
	ShortID       string `json:"shortId"`   // reality (hex)
	SpiderX       string `json:"spiderX"`
	WsPath        string `json:"wsPath"`
	WsHost        string `json:"wsHost"`
	GrpcService   string `json:"grpcService"`
	SocksPort     int    `json:"socksPort"`
}

var (
	xrayMu  sync.Mutex
	xrayCur *core.Instance
)

func xrayStreamSettings(p *xrayParams) (*internet.StreamConfig, error) {
	sc := &internet.StreamConfig{ProtocolName: p.Network}
	switch p.Network {
	case "ws":
		path := p.WsPath
		if path == "" {
			path = "/"
		}
		cfg := &websocket.Config{Path: path}
		if p.WsHost != "" {
			cfg.Header = []*websocket.Header{{Key: "Host", Value: p.WsHost}}
		}
		sc.TransportSettings = []*internet.TransportConfig{{ProtocolName: "websocket", Settings: serial.ToTypedMessage(cfg)}}
	case "grpc":
		sc.TransportSettings = []*internet.TransportConfig{{ProtocolName: "grpc", Settings: serial.ToTypedMessage(&grpc.Config{
			ServiceName:        p.GrpcService,
			MultiMode:          false,
			IdleTimeout:        60,
			HealthCheckTimeout: 20,
		})}}
	case "tcp", "":
		sc.ProtocolName = "tcp"
	default:
		return nil, fmt.Errorf("network Xray tidak didukung: %s", p.Network)
	}

	switch p.Security {
	case "tls":
		t := &tls.Config{ServerName: p.SNI, Fingerprint: p.Fingerprint}
		if p.ALPN != "" {
			t.NextProtocol = strings.Split(p.ALPN, ",")
		}
		sc.SecurityType = "tls"
		sc.SecuritySettings = []*serial.TypedMessage{serial.ToTypedMessage(t)}
	case "reality":
		pub, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(p.PublicKey))
		if err != nil {
			// Coba varian dengan padding.
			pub, err = base64.URLEncoding.DecodeString(strings.TrimSpace(p.PublicKey))
			if err != nil {
				return nil, fmt.Errorf("publicKey REALITY tidak sah: %v", err)
			}
		}
		var sid []byte
		if p.ShortID != "" {
			sid, err = hex.DecodeString(p.ShortID)
			if err != nil {
				return nil, fmt.Errorf("shortId REALITY tidak sah: %v", err)
			}
		}
		fp := p.Fingerprint
		if fp == "" {
			fp = "chrome"
		}
		sc.SecurityType = "reality"
		sc.SecuritySettings = []*serial.TypedMessage{serial.ToTypedMessage(&reality.Config{
			Fingerprint: fp,
			ServerName:  p.SNI,
			PublicKey:   pub,
			ShortId:     sid,
			SpiderX:     p.SpiderX,
		})}
	case "none", "":
		// tanpa keamanan transport
	default:
		return nil, fmt.Errorf("security Xray tidak didukung: %s", p.Security)
	}
	return sc, nil
}

func xrayOutbound(p *xrayParams) (*core.OutboundHandlerConfig, error) {
	addr := net.NewIPOrDomain(net.ParseAddress(p.Address))
	stream, err := xrayStreamSettings(p)
	if err != nil {
		return nil, err
	}
	out := &core.OutboundHandlerConfig{Tag: "proxy"}
	sender := &proxyman.SenderConfig{StreamSettings: stream}
	out.SenderSettings = serial.ToTypedMessage(sender)

	server := &protocol.ServerEndpoint{Address: addr, Port: uint32(p.Port)}
	switch p.Protocol {
	case "vless":
		flow := p.Flow
		account := &vless.Account{Id: p.ID, Flow: flow, Encryption: "none"}
		server.User = []*protocol.User{{Account: serial.ToTypedMessage(account)}}
		out.ProxySettings = serial.ToTypedMessage(&vlessout.Config{Vnext: []*protocol.ServerEndpoint{server}})
	case "vmess":
		sec := protocol.SecurityType_AUTO
		switch strings.ToLower(p.VmessSecurity) {
		case "aes-128-gcm":
			sec = protocol.SecurityType_AES128_GCM
		case "chacha20-poly1305":
			sec = protocol.SecurityType_CHACHA20_POLY1305
		case "none":
			sec = protocol.SecurityType_NONE
		case "zero":
			sec = protocol.SecurityType_ZERO
		}
		if p.AlterID > 0 {
			return nil, fmt.Errorf("VMess alterId > 0 tidak didukung Xray modern (hanya AEAD/alterId 0)")
		}
		account := &vmess.Account{
			Id:               p.ID,
			SecuritySettings: &protocol.SecurityConfig{Type: sec},
		}
		server.User = []*protocol.User{{Account: serial.ToTypedMessage(account)}}
		out.ProxySettings = serial.ToTypedMessage(&vmessout.Config{Receiver: []*protocol.ServerEndpoint{server}})
	case "trojan":
		account := &trojan.Account{Password: p.Password, Flow: p.Flow}
		server.User = []*protocol.User{{Account: serial.ToTypedMessage(account)}}
		out.ProxySettings = serial.ToTypedMessage(&trojan.ClientConfig{Server: []*protocol.ServerEndpoint{server}})
	case "ss":
		if strings.HasPrefix(p.Method, "2022-") {
			out.ProxySettings = serial.ToTypedMessage(&ss2022.ClientConfig{
				Address: addr,
				Port:    uint32(p.Port),
				Method:  p.Method,
				Key:     p.Password,
			})
		} else {
			ct := shadowsocks.CipherType_UNKNOWN
			switch p.Method {
			case "aes-128-gcm":
				ct = shadowsocks.CipherType_AES_128_GCM
			case "aes-256-gcm":
				ct = shadowsocks.CipherType_AES_256_GCM
			case "chacha20-poly1305", "chacha20-ietf-poly1305":
				ct = shadowsocks.CipherType_CHACHA20_POLY1305
			case "xchacha20-poly1305", "xchacha20-ietf-poly1305":
				ct = shadowsocks.CipherType_XCHACHA20_POLY1305
			case "none":
				ct = shadowsocks.CipherType_NONE
			default:
				return nil, fmt.Errorf("method Shadowsocks tidak didukung: %s", p.Method)
			}
			account := &shadowsocks.Account{Password: p.Password, CipherType: ct}
			server.User = []*protocol.User{{Account: serial.ToTypedMessage(account)}}
			out.ProxySettings = serial.ToTypedMessage(&shadowsocks.ClientConfig{Server: []*protocol.ServerEndpoint{server}})
		}
	default:
		return nil, fmt.Errorf("protokol Xray tidak didukung: %s", p.Protocol)
	}
	return out, nil
}

// startXray memulai instance Xray dari skema JSON datar TunnelKu.
func startXray(paramsJSON string) error {
	xrayMu.Lock()
	defer xrayMu.Unlock()
	if xrayCur != nil {
		return fmt.Errorf("Xray sudah berjalan")
	}
	var p xrayParams
	if err := json.Unmarshal([]byte(paramsJSON), &p); err != nil {
		return fmt.Errorf("parameter Xray tidak sah: %v", err)
	}
	if p.SocksPort == 0 {
		p.SocksPort = 11082
	}
	if os.Getenv("SSL_CERT_DIR") == "" {
		os.Setenv("SSL_CERT_DIR", "/system/etc/security/cacerts")
	}
	outbound, err := xrayOutbound(&p)
	if err != nil {
		return err
	}
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&applog.Config{
				ErrorLogType:  applog.LogType_Console,
				ErrorLogLevel: clog.Severity_Warning,
			}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			Tag: "socks-in",
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{{From: uint32(p.SocksPort), To: uint32(p.SocksPort)}}},
				Listen:    net.NewIPOrDomain(net.ParseAddress("127.0.0.1")),
			}),
			ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
				AuthType:   socks.AuthType_NO_AUTH,
				UdpEnabled: true,
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{outbound},
	}
	inst, err := core.New(cfg)
	if err != nil {
		return fmt.Errorf("gagal membuat instance Xray: %v", err)
	}
	if err := inst.Start(); err != nil {
		return fmt.Errorf("gagal memulai Xray: %v", err)
	}
	xrayCur = inst
	return nil
}

func stopXray() {
	xrayMu.Lock()
	defer xrayMu.Unlock()
	if xrayCur == nil {
		return
	}
	xrayCur.Close()
	xrayCur = nil
}
