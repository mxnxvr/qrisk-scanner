// DELIBERATELY INSECURE sample code for the QRisk lab. Do not copy.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
)

func main() {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)                 // quantum-vulnerable
	ecKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)      // quantum-vulnerable
	sum := md5.Sum([]byte("password"))                               // critical
	dk, _ := mlkem.GenerateKey768()                                  // post-quantum (Go 1.24+)
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10} // critical x2
	fmt.Println(rsaKey, ecKey, sum, dk, cfg)
}
