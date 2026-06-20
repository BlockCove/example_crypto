package rsautil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// 私钥生成签名
func RsaSign(pri *rsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	digest := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, pri, crypto.SHA256, digest)
}

// 公钥验证签名
func RsaVerify(pub *rsa.PublicKey, data []byte, sig []byte) bool {
	h := sha256.New()
	h.Write(data)
	digest := h.Sum(nil)
	err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig)
	return err == nil
}
