package main

// Server WebSocket manual (RFC 6455) di atas stdin/stdout — peer independen
// untuk menguji WsClientStream Kotlin. Meng-echo semua pesan biner/teks.

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	r := bufio.NewReader(os.Stdin)
	w := os.Stdout
	var key string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			fmt.Fprintln(os.Stderr, "EOF header")
			os.Exit(1)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "sec-websocket-key:") {
			key = strings.TrimSpace(line[strings.Index(line, ":")+1:])
		}
	}
	if key == "" {
		fmt.Fprintln(os.Stderr, "tidak ada Sec-WebSocket-Key")
		os.Exit(1)
	}
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(h[:])
	fmt.Fprintf(w, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)

	readN := func(n int) ([]byte, error) {
		buf := make([]byte, n)
		_, err := io.ReadFull(r, buf)
		return buf, err
	}
	writeFrame := func(opcode byte, payload []byte) {
		hdr := []byte{0x80 | opcode}
		l := len(payload)
		switch {
		case l < 126:
			hdr = append(hdr, byte(l))
		case l <= 0xFFFF:
			hdr = append(hdr, 126, byte(l>>8), byte(l))
		default:
			hdr = append(hdr, 127)
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], uint64(l))
			hdr = append(hdr, b[:]...)
		}
		w.Write(hdr)
		w.Write(payload)
	}
	var assembled []byte
	for {
		h, err := readN(2)
		if err != nil {
			return
		}
		fin := h[0]&0x80 != 0
		opcode := h[0] & 0x0F
		masked := h[1]&0x80 != 0
		l := uint64(h[1] & 0x7F)
		if l == 126 {
			e, err := readN(2)
			if err != nil { return }
			l = uint64(binary.BigEndian.Uint16(e))
		} else if l == 127 {
			e, err := readN(8)
			if err != nil { return }
			l = binary.BigEndian.Uint64(e)
		}
		var mask []byte
		if masked {
			mask, err = readN(4)
			if err != nil { return }
		}
		payload, err := readN(int(l))
		if err != nil { return }
		if mask != nil {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}
		switch opcode {
		case 9:
			writeFrame(0x0A, payload)
		case 8:
			writeFrame(0x08, nil)
			return
		case 0, 1, 2:
			assembled = append(assembled, payload...)
			if fin {
				writeFrame(0x02, assembled)
				assembled = nil
			}
		}
	}
}
