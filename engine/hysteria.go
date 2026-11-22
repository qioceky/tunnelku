package engine

// Klien UDP Custom: protokolnya = Hysteria v1 (riset atas server resmi
// ePro udp-custom: binary tertutup berbasis core Hysteria v1 + auth PAM).
// Di sini dipakai core Hysteria v1 resmi (github.com/apernet/hysteria,
// v1.3.5) dan hasilnya disajikan sebagai server SOCKS5 lokal agar sisi
// Kotlin punya satu jalur transport yang seragam.

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/cs"
	"github.com/apernet/hysteria/core/pktconns"
	quic "github.com/quic-go/quic-go"
)

type hysteriaInstance struct {
	client   *cs.Client
	ln       net.Listener
	udpRelay *net.UDPConn
	done     chan struct{}
}

var (
	hyMu  sync.Mutex
	hyCur *hysteriaInstance
)

// startHysteria menghubungkan klien Hysteria v1 ke serverAddr (host:port),
// auth = "user:password" akun server (PAM), lalu menyajikan SOCKS5 di
// socksAddr (127.0.0.1:port) dengan CONNECT (TCP) + UDP ASSOCIATE.
func startHysteria(serverAddr, auth, obfs, sni string, insecure bool, socksAddr string) error {
	hyMu.Lock()
	defer hyMu.Unlock()
	if hyCur != nil {
		return fmt.Errorf("Hysteria sudah berjalan")
	}
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return fmt.Errorf("alamat server tidak sah: %v", err)
	}
	serverName := sni
	if serverName == "" {
		serverName = host
	}
	tlsConfig := &tls.Config{
		NextProtos:         []string{"hysteria"},
		ServerName:         serverName,
		InsecureSkipVerify: insecure, // server udp-custom umumnya sertifikat mandiri
		MinVersion:         tls.VersionTLS13,
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     16777216,
		MaxStreamReceiveWindow:         16777216,
		InitialConnectionReceiveWindow: 41943040,
		MaxConnectionReceiveWindow:     41943040,
		HandshakeIdleTimeout:           10 * time.Second,
		MaxIdleTimeout:                 20 * time.Second,
		KeepAlivePeriod:                8 * time.Second,
		EnableDatagrams:                true,
	}
	pktConnFunc := pktconns.NewClientUDPConnFunc(obfs, 0)
	client, err := cs.NewClient(serverAddr, []byte(auth), tlsConfig, quicConfig, pktConnFunc, 0, 0, false, false, nil)
	if err != nil {
		return fmt.Errorf("Hysteria gagal tersambung: %v", err)
	}
	ln, err := net.Listen("tcp", socksAddr)
	if err != nil {
		client.Close()
		return fmt.Errorf("membuka SOCKS5 lokal: %v", err)
	}
	inst := &hysteriaInstance{client: client, ln: ln, done: make(chan struct{})}
	hyCur = inst
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSocks(conn, inst)
		}
	}()
	return nil
}

func stopHysteria() {
	hyMu.Lock()
	defer hyMu.Unlock()
	if hyCur == nil {
		return
	}
	hyCur.ln.Close()
	if hyCur.udpRelay != nil {
		hyCur.udpRelay.Close()
	}
	hyCur.client.Close()
	hyCur = nil
}

// ---------- SOCKS5 minimal (tanpa autentikasi, loopback saja) ----------

func socksAddrString(atyp byte, addr []byte, port uint16) string {
	switch atyp {
	case 0x01:
		return net.JoinHostPort(net.IP(addr).String(), strconv.Itoa(int(port)))
	case 0x03:
		return net.JoinHostPort(string(addr), strconv.Itoa(int(port)))
	case 0x04:
		return net.JoinHostPort(net.IP(addr).String(), strconv.Itoa(int(port)))
	}
	return ""
}

// readSocksAddr membaca ATYP+addr+port dari r. Mengembalikan representasi
// string "host:port" dan byte mentah untuk dibalas ke klien.
func readSocksAddr(r io.Reader) (string, byte, []byte, uint16, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", 0, nil, 0, err
	}
	var addr []byte
	switch atyp[0] {
	case 0x01:
		addr = make([]byte, 4)
	case 0x04:
		addr = make([]byte, 16)
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", 0, nil, 0, err
		}
		addr = make([]byte, int(l[0]))
	default:
		return "", 0, nil, 0, fmt.Errorf("atyp tidak didukung: %d", atyp[0])
	}
	if _, err := io.ReadFull(r, addr); err != nil {
		return "", 0, nil, 0, err
	}
	var portB [2]byte
	if _, err := io.ReadFull(r, portB[:]); err != nil {
		return "", 0, nil, 0, err
	}
	port := binary.BigEndian.Uint16(portB[:])
	return socksAddrString(atyp[0], addr, port), atyp[0], addr, port, nil
}

func handleSocks(conn net.Conn, inst *hysteriaInstance) {
	defer conn.Close()
	buf := make([]byte, 262)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}
	// Tanpa autentikasi.
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil || head[0] != 0x05 {
		return
	}
	cmd := head[1]
	switch cmd {
	case 0x01: // CONNECT
		target, _, _, _, err := readSocksAddr(conn)
		if err != nil || target == "" {
			conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		up, err := inst.client.DialTCP(target)
		if err != nil {
			log.Printf("hysteria DialTCP %s: %v", target, err)
			conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		done := make(chan struct{}, 2)
		go func() { io.Copy(up, conn); done <- struct{}{} }()
		go func() { io.Copy(conn, up); done <- struct{}{} }()
		<-done
	case 0x03: // UDP ASSOCIATE
		if _, _, _, _, err := readSocksAddr(conn); err != nil {
			return
		}
		relayAddr, err := startUDPRelay(inst)
		if err != nil {
			conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		ra := relayAddr.(*net.UDPAddr)
		ip := ra.IP.To4()
		resp := []byte{0x05, 0x00, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(ra.Port >> 8), byte(ra.Port)}
		if _, err := conn.Write(resp); err != nil {
			return
		}
		// Tahan koneksi kontrol sampai klien menutupnya.
		io.Copy(io.Discard, conn)
	default:
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

func startUDPRelay(inst *hysteriaInstance) (net.Addr, error) {
	if inst.udpRelay != nil {
		return inst.udpRelay.LocalAddr(), nil
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return nil, err
	}
	inst.udpRelay = relay
	hyUDP, err := inst.client.DialUDP()
	if err != nil {
		relay.Close()
		inst.udpRelay = nil
		return nil, err
	}
	var clientAddr *net.UDPAddr
	var mu sync.Mutex
	// Klien (SOCKS) -> Hysteria
	go func() {
		buf := make([]byte, 65535)
		for {
			n, ca, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			clientAddr = ca
			mu.Unlock()
			if n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
				continue // frag/RSV tidak sah
			}
			// Parse header SOCKS UDP dari byte mentah.
			off := 3
			atyp := buf[off]
			off++
			var target string
			switch atyp {
			case 0x01:
				if n < off+6 {
					continue
				}
				ip := net.IP(buf[off : off+4])
				port := binary.BigEndian.Uint16(buf[off+4 : off+6])
				target = net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
				off += 6
			case 0x03:
				if n < off+1 {
					continue
				}
				l := int(buf[off])
				off++
				if n < off+l+2 {
					continue
				}
				host := string(buf[off : off+l])
				port := binary.BigEndian.Uint16(buf[off+l : off+l+2])
				target = net.JoinHostPort(host, strconv.Itoa(int(port)))
				off += l + 2
			default:
				continue
			}
			payload := make([]byte, n-off)
			copy(payload, buf[off:n])
			if err := hyUDP.WriteTo(payload, target); err != nil {
				log.Printf("hysteria WriteTo %s: %v", target, err)
			}
		}
	}()
	// Hysteria -> klien (SOCKS)
	go func() {
		for {
			data, from, err := hyUDP.ReadFrom()
			if err != nil {
				return
			}
			mu.Lock()
			ca := clientAddr
			mu.Unlock()
			if ca == nil {
				continue
			}
			host, portStr, err := net.SplitHostPort(from)
			if err != nil {
				continue
			}
			port, _ := strconv.Atoi(portStr)
			ip := net.ParseIP(host)
			var pkt []byte
			if ip4 := ip.To4(); ip4 != nil {
				pkt = append([]byte{0, 0, 0, 0x01}, ip4...)
			} else {
				pkt = append([]byte{0, 0, 0, 0x04}, ip.To16()...)
			}
			pkt = append(pkt, byte(port>>8), byte(port))
			pkt = append(pkt, data...)
			relay.WriteToUDP(pkt, ca)
		}
	}()
	return relay.LocalAddr(), nil
}
