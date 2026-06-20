package rsautil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

const (
	RsaPriFile = "rsa_private.pem"
	RsaPubFile = "rsa_public.pem"
	RsaEncFile = "rsa_cipher.bin"
)

// 生成RSA 2048公私钥并持久化文件
func GenRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	pri, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	// 私钥PEM
	priDer := x509.MarshalPKCS1PrivateKey(pri)
	priPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: priDer,
	})
	if err := os.WriteFile(RsaPriFile, priPem, 0644); err != nil {
		return nil, nil, err
	}
	// 公钥PEM
	pub := &pri.PublicKey
	pubDer, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	pubPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDer,
	})
	if err := os.WriteFile(RsaPubFile, pubPem, 0644); err != nil {
		return nil, nil, err
	}
	return pri, pub, nil
}

// 读取私钥
func LoadRsaPrivateKey() (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(RsaPriFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("pem decode fail")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// 读取公钥
func LoadRsaPublicKey() (*rsa.PublicKey, error) {
	data, err := os.ReadFile(RsaPubFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("pem decode fail")
	}
	pubIface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := pubIface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not rsa public key")
	}
	return pub, nil
}

// 公钥加密
func RsaEncrypt(pub *rsa.PublicKey, data []byte) ([]byte, error) {
	cipher, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)
	if err != nil {
		return nil, err
	}
	_ = os.WriteFile(RsaEncFile, cipher, 0644)
	return cipher, nil
}

// 私钥解密
func RsaDecrypt(pri *rsa.PrivateKey, cipher []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, pri, cipher, nil)
}
