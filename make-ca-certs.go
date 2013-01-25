package main

import (
        "crypto/rand"
        "crypto/rsa"
        "crypto/tls"
        "crypto/x509"
        "crypto/x509/pkix"
        "encoding/pem"
        "errors"
        "io"
	//"io/ioutil"
	"os"
        "math/big"
        //"net"
        //"path/filepath"
        //"syscall"
        "time"
	//"log"
)


func main() {
	// Generate a self signed CA cert & key.
	caCert, caKey, err := generateCA("The World's most secure dating site")
	handle(err)
	writePair("datingCA", caCert, caKey)

	// Generate the Key and certificate that sign the client certificates
	localCaCert, localCaKey, err := generateLocalCA("Register at the World's most secure dating site", caCert, caKey)
	handle(err)
	writePair("datingLocalCA", localCaCert, localCaKey)
	
        // Generate an alpha cert signed by our CA cert
        alphaCert, alphaKey, err := generateCert("dating.wtmnd.nl", caCert, caKey)
        handle(err)
	writePair("dating.wtmnd.nl", alphaCert, alphaKey)

        // Generate an beta cert signed by our CA cert
        betaCert, betaKey, err := generateCert("register-dating.wtmnd.nl", caCert, caKey)
        handle(err)
	writePair("register-dating.wtmnd.nl", betaCert, betaKey)
}

func writePair(serverName string, cert *x509.Certificate, key *rsa.PrivateKey) {
	cBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	kBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})	
	err := writeFile(serverName + ".cert.pem", cBytes, 0444)
	handle(err)
	err = writeFile(serverName + ".key.pem", kBytes, 0400)
	handle(err)
}

// writeFile writes data to a file named by filename.
// If the file does not exist, WriteFile creates it with permissions perm;
// It does not overwrite files.
func writeFile(filename string, data []byte, perm os.FileMode) error {
        f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
        if err != nil {
                return err
        }
        n, err := f.Write(data)
        f.Close()
        if err == nil && n < len(data) {
                err = io.ErrShortWrite
        }
        return err
}

func generateCA(serverName string) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	serial := randBigInt()
	keyId := randBytes()

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: serverName,
		},

		SerialNumber:   serial,
		SubjectKeyId:   keyId,
		AuthorityKeyId: keyId,
		NotBefore:      time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:       time.Now().AddDate(5, 0, 0).UTC(),

		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, nil, err
	}

	if len(certs) != 1 {
		return nil, nil, errors.New("Failed to generate a parsable certificate")
	}

	return certs[0], priv, nil
}


func generateLocalCA(localCaName string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, err
	}
	
	serial := randBigInt()
	keyId := randBytes()

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: localCaName,
		},

		SerialNumber:   serial,
		SubjectKeyId:   keyId,
		AuthorityKeyId: caCert.AuthorityKeyId,
		NotBefore:      time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:       time.Now().AddDate(5, 0, 0).UTC(),

		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, nil, err
	}
	if len(certs) != 1 {
		return nil, nil, errors.New("Failed to generate a parsable certificate")
	}

	return certs[0], priv, nil
}

func generateCert(serverName string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	serial := randBigInt()
	keyId := randBytes()

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: serverName,
		},

		SerialNumber:   serial,
		SubjectKeyId:   keyId,
		AuthorityKeyId: caCert.AuthorityKeyId,
		NotBefore:      time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:       time.Now().AddDate(2, 0, 0).UTC(),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, nil, err
	}
	if len(certs) != 1 {
		return nil, nil, errors.New("Failed to generate a parsable certificate")
	}

	return certs[0], priv, nil
}


func generatePair(serverName string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (tls.Certificate, error) {
	cert, key, err := generateCert(serverName, caCert, caKey)
		
	if err != nil {
		return tls.Certificate{}, err
			
		}
	return x509Pair(cert, key)
}

func x509Pair(cert *x509.Certificate, key *rsa.PrivateKey) (tls.Certificate, error) {
	cBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	kBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	
	return tls.X509KeyPair(cBytes, kBytes)
}

var (
        maxInt64 int64 = 0x7FFFFFFFFFFFFFFF
        maxBig64       = big.NewInt(maxInt64)
)


func randBigInt() (value *big.Int) {
	value, _ = rand.Int(rand.Reader, maxBig64)
	return
}

func randBytes() (bytes []byte) {
	bytes = make([]byte, 20)
	rand.Read(bytes)
	return
}

func handle(err error) {
	if err != nil {
		panic(err.Error())
	}
}