package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/aead"
	vmessenc "github.com/xtls/xray-core/proxy/vmess/encoding"
	"golang.org/x/crypto/chacha20poly1305"
)

func must(err error, what string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", what, err)
		os.Exit(1)
	}
}

func readAllBuf(r buf.Reader) []byte {
	var out []byte
	for {
		mb, err := r.ReadMultiBuffer()
		if err != nil {
			break
		}
		for _, b := range mb {
			out = append(out, b.Bytes()...)
			b.Release()
		}
	}
	return out
}

func main() {
	mode := os.Args[1]
	switch mode {
	case "kdf":
		key, _ := hex.DecodeString(os.Args[2])
		var path []string
		if len(os.Args) > 3 && os.Args[3] != "" {
			path = strings.Split(os.Args[3], "|")
		}
		fmt.Println(hex.EncodeToString(aead.KDF(key, path...)))
		fmt.Println(hex.EncodeToString(aead.KDF16(key, path...)))
	case "chacha":
		key, _ := hex.DecodeString(os.Args[2])
		nonce, _ := hex.DecodeString(os.Args[3])
		aad, _ := hex.DecodeString(os.Args[4])
		pt, _ := hex.DecodeString(os.Args[5])
		a, err := chacha20poly1305.New(key)
		must(err, "chacha new")
		fmt.Println(hex.EncodeToString(a.Seal(nil, nonce, pt, aad)))
	case "vmess-rt":
		uuidStr := os.Args[2]
		secInt, _ := strconv.Atoi(os.Args[3])
		inFile, outFile := os.Args[4], os.Args[5]
		validator := vmess.NewTimedUserValidator()
		acct, err := (&vmess.Account{
			Id:               uuidStr,
			SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType(secInt)},
		}).AsAccount()
		must(err, "account")
		must(validator.Add(&protocol.MemoryUser{Account: acct}), "validator add")
		session := vmessenc.NewServerSession(validator, vmessenc.NewSessionHistory())
		data, err := os.ReadFile(inFile)
		must(err, "read in")
		reader := bytes.NewReader(data)
		req, err := session.DecodeRequestHeader(reader, false)
		must(err, "decode request header")
		fmt.Printf("HEADER cmd=%d addr=%s port=%d security=%d\n", req.Command, req.Address.String(), req.Port, req.Security)
		bodyReader, err := session.DecodeRequestBody(req, reader)
		must(err, "decode request body")
		payload := readAllBuf(bodyReader)
		fmt.Printf("PAYLOAD %s\n", hex.EncodeToString(payload))
		var outBuf bytes.Buffer
		bw := buf.NewBufferedWriter(buf.NewWriter(&outBuf))
		session.EncodeResponseHeader(&protocol.ResponseHeader{}, bw)
		respWriter, err := session.EncodeResponseBody(req, bw)
		must(err, "encode response body")
		rb := buf.New()
		rb.Write([]byte("RESP-OK-12345"))
		must(respWriter.WriteMultiBuffer(buf.MultiBuffer{rb}), "write resp body")
		must(bw.Flush(), "flush")
		must(os.WriteFile(outFile, outBuf.Bytes(), 0o644), "write out")
	case "ss-tcp":
		cipherName, password := os.Args[2], os.Args[3]
		inFile, outFile := os.Args[4], os.Args[5]
		validator := &shadowsocks.Validator{}
		acct, err := (&shadowsocks.Account{
			CipherType: cipherByName(cipherName),
			Password:   password,
		}).AsAccount()
		must(err, "ss account")
		must(validator.Add(&protocol.MemoryUser{Account: acct}), "ss validator add")
		data, err := os.ReadFile(inFile)
		must(err, "read in")
		req, bodyReader, err := shadowsocks.ReadTCPSession(validator, bytes.NewReader(data))
		must(err, "read tcp session")
		fmt.Printf("HEADER addr=%s port=%d\n", req.Address.String(), req.Port)
		payload := readAllBuf(bodyReader)
		fmt.Printf("PAYLOAD %s\n", hex.EncodeToString(payload))
		var outBuf bytes.Buffer
		bw := buf.NewBufferedWriter(buf.NewWriter(&outBuf))
		respWriter, err := shadowsocks.WriteTCPResponse(req, bw)
		must(err, "write tcp response")
		rb := buf.New()
		rb.Write([]byte("RESP-SS-OK"))
		must(respWriter.WriteMultiBuffer(buf.MultiBuffer{rb}), "write resp body")
		must(bw.Flush(), "flush")
		must(os.WriteFile(outFile, outBuf.Bytes(), 0o644), "write out")
	case "ss-udp-dec":
		cipherName, password := os.Args[2], os.Args[3]
		inFile := os.Args[4]
		validator := &shadowsocks.Validator{}
		acct, err := (&shadowsocks.Account{
			CipherType: cipherByName(cipherName),
			Password:   password,
		}).AsAccount()
		must(err, "ss account")
		must(validator.Add(&protocol.MemoryUser{Account: acct}), "ss validator add")
		data, err := os.ReadFile(inFile)
		must(err, "read in")
		b := buf.New()
		b.Write(data)
		req, payload, err := shadowsocks.DecodeUDPPacket(validator, b)
		must(err, "decode udp packet")
		fmt.Printf("HEADER addr=%s port=%d\n", req.Address.String(), req.Port)
		fmt.Printf("PAYLOAD %s\n", hex.EncodeToString(payload.Bytes()))
	case "ss-udp-enc":
		cipherName, password := os.Args[2], os.Args[3]
		srcIP, srcPortStr, payloadHex, outFile := os.Args[4], os.Args[5], os.Args[6], os.Args[7]
		srcPort, _ := strconv.Atoi(srcPortStr)
		acct, err := (&shadowsocks.Account{
			CipherType: cipherByName(cipherName),
			Password:   password,
		}).AsAccount()
		must(err, "ss account")
		payload, _ := hex.DecodeString(payloadHex)
		req := &protocol.RequestHeader{
			Version: shadowsocks.Version,
			User:    &protocol.MemoryUser{Account: acct},
			Command: protocol.RequestCommandUDP,
			Address: net.ParseAddress(srcIP),
			Port:    net.Port(srcPort),
		}
		pkt, err := shadowsocks.EncodeUDPPacket(req, payload)
		must(err, "encode udp packet")
		must(os.WriteFile(outFile, pkt.Bytes(), 0o644), "write out")
	default:
		fmt.Fprintln(os.Stderr, "unknown mode", mode)
		os.Exit(1)
	}
}

func cipherByName(name string) shadowsocks.CipherType {
	switch name {
	case "aes-128-gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-ietf-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "xchacha20-ietf-poly1305":
		return shadowsocks.CipherType_XCHACHA20_POLY1305
	case "none":
		return shadowsocks.CipherType_NONE
	}
	fmt.Fprintln(os.Stderr, "cipher tidak dikenal:", name)
	os.Exit(1)
	return 0
}
