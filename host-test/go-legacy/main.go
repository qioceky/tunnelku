// Harness referensi VMess LEGACY: server session v2fly v2ray-core v4.45.2
// (xray-core 1.8.3 sudah membuang legacy). Mode: legacy-rt <uuid> <secInt> <inFile> <outFile>
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"github.com/v2fly/v2ray-core/v4/common/buf"
	"github.com/v2fly/v2ray-core/v4/common/protocol"
	"github.com/v2fly/v2ray-core/v4/proxy/vmess"
	vmessenc "github.com/v2fly/v2ray-core/v4/proxy/vmess/encoding"
)

func must(err error, what string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
		os.Exit(1)
	}
}

func readAllBuf(r buf.Reader) []byte {
	var out bytes.Buffer
	mb, err := r.ReadMultiBuffer()
	for err == nil {
		for _, b := range mb {
			out.Write(b.Bytes())
			b.Release()
		}
		mb, err = r.ReadMultiBuffer()
	}
	return out.Bytes()
}

func main() {
	if len(os.Args) < 6 || os.Args[1] != "legacy-rt" {
		fmt.Fprintln(os.Stderr, "usage: legacy-rt <uuid> <secInt> <inFile> <outFile>")
		os.Exit(2)
	}
	uuidStr := os.Args[2]
	secInt, _ := strconv.Atoi(os.Args[3])
	inFile, outFile := os.Args[4], os.Args[5]
	validator := vmess.NewTimedUserValidator(protocol.DefaultIDHash)
	acct, err := (&vmess.Account{
		Id:               uuidStr,
		AlterId:          2,
		SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType(secInt)},
	}).AsAccount()
	must(err, "account")
	must(validator.Add(&protocol.MemoryUser{Account: acct}), "validator add")
	session := vmessenc.NewServerSession(validator, vmessenc.NewSessionHistory())
	data, err := os.ReadFile(inFile)
	must(err, "read in")
	reader := bytes.NewReader(data)
	req, err := session.DecodeRequestHeader(reader)
	must(err, "decode request header")
	fmt.Printf("HEADER cmd=%d addr=%s port=%d security=%d\n", req.Command, req.Address.String(), req.Port, req.Security)
	bodyReader, err := session.DecodeRequestBody(req, reader)
	must(err, "decode request body")
	payload := readAllBuf(bodyReader)
	fmt.Printf("PAYLOAD %s\n", hex.EncodeToString(payload))
	var outBuf bytes.Buffer
	session.EncodeResponseHeader(&protocol.ResponseHeader{}, &outBuf)
	respWriter, err := session.EncodeResponseBody(req, &outBuf)
	must(err, "encode response body")
	rb := buf.New()
	rb.Write([]byte("RESP-OK-12345"))
	must(respWriter.WriteMultiBuffer(buf.MultiBuffer{rb}), "write resp body")
	must(os.WriteFile(outFile, outBuf.Bytes(), 0o644), "write out")
}
