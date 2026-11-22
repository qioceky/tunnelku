package engine

// Klien SlowDNS/DNSTT — logika disadur dari dnstt-client resmi
// (www.bamsoftware.com/git/dnstt, CC0): KCP di atas DNSPacketConn,
// Noise_NK_25519_ChaChaPoly_BLAKE2s, lalu smux; listener TCP lokal
// meneruskan setiap koneksi ke satu stream smux (tujuan akhir diatur
// server dnstt, umumnya SSH).

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"
	kcp "github.com/xtaci/kcp-go/v5"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const dnsttIdleTimeout = 2 * time.Minute

type dnsttInstance struct {
	ln     *net.TCPListener
	pconn  net.PacketConn
	sess   *smux.Session
	closed chan struct{}
}

var (
	dnsttMu  sync.Mutex
	dnsttCur *dnsttInstance
)

// dnsNameCapacity: sama persis dengan dnstt-client resmi.
func dnsNameCapacity(domain dns.Name) int {
	capacity := 255
	capacity -= 1
	for _, label := range domain {
		capacity -= len(label) + 1
	}
	capacity = capacity * 63 / 64
	capacity = capacity * 5 / 8
	return capacity
}

func dnsttHandle(local *net.TCPConn, sess *smux.Session) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("membuka stream smux: %v", err)
	}
	defer stream.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("dnstt stream copy: %v", err)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("dnstt stream copy: %v", err)
		}
		local.CloseWrite()
	}()
	wg.Wait()
	return nil
}

// startDNSTT menjalankan klien DNSTT: resolverAddr = server DNS rekursif
// (host:port, UDP), domain = domain tunnel, pubkeyHex = kunci publik server
// (64 digit hex), listenAddr = listener lokal (127.0.0.1:port).
func startDNSTT(resolverAddr, domainStr, pubkeyHex, listenAddr string) error {
	dnsttMu.Lock()
	defer dnsttMu.Unlock()
	if dnsttCur != nil {
		return fmt.Errorf("DNSTT sudah berjalan")
	}
	pubkey, err := noise.DecodeKey(pubkeyHex)
	if err != nil {
		return fmt.Errorf("pubkey DNSTT tidak sah: %v", err)
	}
	domain, err := dns.ParseName(domainStr)
	if err != nil {
		return fmt.Errorf("domain DNSTT tidak sah: %v", err)
	}
	remoteAddr, err := net.ResolveUDPAddr("udp", resolverAddr)
	if err != nil {
		return fmt.Errorf("resolver DNS tidak sah: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return fmt.Errorf("membuka socket UDP: %v", err)
	}
	pconn := NewDNSPacketConn(udpConn, remoteAddr, domain)

	localAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		pconn.Close()
		return fmt.Errorf("alamat listen tidak sah: %v", err)
	}
	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		pconn.Close()
		return fmt.Errorf("membuka listener lokal: %v", err)
	}

	mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1
	if mtu < 80 {
		ln.Close()
		pconn.Close()
		return fmt.Errorf("domain %s menyisakan hanya %d byte payload", domainStr, mtu)
	}

	conn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, pconn)
	if err != nil {
		ln.Close()
		pconn.Close()
		return fmt.Errorf("membuka KCP: %v", err)
	}
	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if rc := conn.SetMtu(mtu); !rc {
		ln.Close()
		pconn.Close()
		return fmt.Errorf("gagal mengatur MTU KCP")
	}

	rw, err := noise.NewClient(conn, pubkey)
	if err != nil {
		conn.Close()
		ln.Close()
		pconn.Close()
		return err
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = dnsttIdleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		conn.Close()
		ln.Close()
		pconn.Close()
		return fmt.Errorf("membuka sesi smux: %v", err)
	}

	inst := &dnsttInstance{ln: ln, pconn: pconn, sess: sess, closed: make(chan struct{})}
	dnsttCur = inst
	go func() {
		defer close(inst.closed)
		for {
			local, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer local.Close()
				if err := dnsttHandle(local.(*net.TCPConn), sess); err != nil {
					log.Printf("dnstt handle: %v", err)
				}
			}()
		}
	}()
	return nil
}

func stopDNSTT() {
	dnsttMu.Lock()
	defer dnsttMu.Unlock()
	if dnsttCur == nil {
		return
	}
	dnsttCur.ln.Close()
	dnsttCur.sess.Close()
	dnsttCur.pconn.Close()
	dnsttCur = nil
}
