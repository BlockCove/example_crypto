package rsautil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// 生成RSA 2048公私钥对
func GenRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	pri, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return pri, &pri.PublicKey, nil
}

// 公钥加密
func RsaEncrypt(pub *rsa.PublicKey, data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)
}

// 私钥解密
func RsaDecrypt(pri *rsa.PrivateKey, cipher []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, pri, cipher, nil)
}
