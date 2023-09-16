package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func main() {
	issued := time.Now().UTC()
	expires := issued.AddDate(10, 0, 0)

	// generate private key
	privatekey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Printf("Error generating private key: %v\n", err)
		return
	}

	publickey := &privatekey.PublicKey

	serialNumber := new(big.Int).SetInt64(int64(issued.Year()*10000 + int(issued.Month())*100 + issued.Day()))

	// see http://golang.org/pkg/crypto/x509/#Certificate
	// see http://golang.org/pkg/crypto/x509/#KeyUsage
	// see http://golang.org/pkg/crypto/x509/#ExtKeyUsage
	template := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Corporation"},
			CommonName:   "Acme Root CA",
		},
		NotBefore:          issued,
		NotAfter:           expires,
		SignatureAlgorithm: x509.SHA256WithRSA,
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	// create a self-signed certificate. template = parent
	var parent = template
	cert, err := x509.CreateCertificate(rand.Reader, template, parent, publickey, privatekey)

	if err != nil {
		fmt.Printf("Error signing certificate: %v\n", err)
		return
	}

	// this will create binary DER certificate file
	err = os.WriteFile("ca.cer", cert, 0600)
	if err != nil {
		fmt.Printf("Error writting certificate: %v\n", err)
		return
	}

	// this will create plain text PEM certificate file.
	var pemcert = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}
	err = os.WriteFile("ca-cert.pem", pem.EncodeToMemory(pemcert), 0600)
	if err != nil {
		fmt.Printf("Error writting certificate: %v\n", err)
		return
	}

	// this will create plain text PEM key file.
	var pemkey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privatekey),
	}
	err = os.WriteFile("ca-key.pem", pem.EncodeToMemory(pemkey), 0600)
	if err != nil {
		fmt.Printf("Error writting private key: %v\n", err)
		return
	}
}
