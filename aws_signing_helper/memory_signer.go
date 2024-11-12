package aws_signing_helper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"os"
)

type MemorySigner struct {
	bundlePath string
	cert       string
	isPkcs12   bool
	privateKey string
}

func (memorySigner *MemorySigner) Public() crypto.PublicKey {
	privateKey, _, _ := memorySigner.readCertFiles()
	{
		privateKey, ok := privateKey.(ecdsa.PrivateKey)
		if ok {
			return &privateKey.PublicKey
		}
	}
	{
		privateKey, ok := privateKey.(rsa.PrivateKey)
		if ok {
			return &privateKey.PublicKey
		}
	}
	return nil
}

func (memorySigner *MemorySigner) Close() {}

func (memorySigner *MemorySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	privateKey, _, _ := memorySigner.readCertFiles()
	var hash []byte
	switch opts.HashFunc() {
	case crypto.SHA256:
		sum := sha256.Sum256(digest)
		hash = sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(digest)
		hash = sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(digest)
		hash = sum[:]
	default:
		return nil, ErrUnsupportedHash
	}

	ecdsaPrivateKey, ok := privateKey.(ecdsa.PrivateKey)
	if ok {
		sig, err := ecdsa.SignASN1(rand, &ecdsaPrivateKey, hash[:])
		if err == nil {
			return sig, nil
		}
	}

	rsaPrivateKey, ok := privateKey.(rsa.PrivateKey)
	if ok {
		sig, err := rsa.SignPKCS1v15(rand, &rsaPrivateKey, opts.HashFunc(), hash[:])
		if err == nil {
			return sig, nil
		}
	}

	log.Println("unsupported algorithm")
	return nil, errors.New("unsupported algorithm")
}

func (memorySigner *MemorySigner) Certificate() (*x509.Certificate, error) {
	_, cert, _ := memorySigner.readCertFiles()
	return cert, nil
}

func (memorySigner *MemorySigner) CertificateChain() ([]*x509.Certificate, error) {
	_, _, certChain := memorySigner.readCertFiles()
	return certChain, nil
}

// GetMemorySigner returns a MemorySigner, that signs a payload using the private key passed in
func GetMemorySigner(privateKeyPem string, certPem string, bundlePath string, isPkcs12 bool) (signer Signer, signingAlgorithm string, err error) {
	mSigner := &MemorySigner{bundlePath: bundlePath, cert: certPem, isPkcs12: isPkcs12, privateKey: privateKeyPem}
	privateKey, _, _ := mSigner.readCertFiles()
	// Find the signing algorithm
	_, isRsaKey := privateKey.(rsa.PrivateKey)
	if isRsaKey {
		signingAlgorithm = aws4_x509_rsa_sha256
	}
	_, isEcKey := privateKey.(ecdsa.PrivateKey)
	if isEcKey {
		signingAlgorithm = aws4_x509_ecdsa_sha256
	}
	if signingAlgorithm == "" {
		log.Println("unsupported algorithm")
		return nil, "", errors.New("unsupported algorithm")
	}

	return mSigner, signingAlgorithm, nil
}

func (memorySigner *MemorySigner) readCertFiles() (crypto.PrivateKey, *x509.Certificate, []*x509.Certificate) {
	privateKey, err := ReadPrivateKeyDataBytes([]byte(memorySigner.privateKey))
	if err != nil {
		log.Printf("Failed to read private key: %s\n", err)
		os.Exit(1)
	}
	var chain []*x509.Certificate
	if memorySigner.bundlePath != "" {
		chain, err = GetCertChain(memorySigner.bundlePath)
		if err != nil {
			privateKey = nil
			log.Printf("Failed to read certificate bundle: %s\n", err)
			os.Exit(1)
		}
	}
	var cert *x509.Certificate
	if memorySigner.cert != "" {
		_, cert, err = ReadCertificateDataBytes([]byte(memorySigner.cert))
		if err != nil {
			privateKey = nil
			log.Printf("Failed to read certificate: %s\n", err)
			os.Exit(1)
		}
	} else if len(chain) > 0 {
		cert = chain[0]
	} else {
		log.Println("No certificate path or certificate bundle path provided")
		os.Exit(1)
	}

	return privateKey, cert, chain
}
