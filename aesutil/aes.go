package aesutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// PKCS7填充
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	pad := make([]byte, padLen)
	for i := range pad {
		pad[i] = byte(padLen)
	}
	return append(data, pad...)
}

// PKCS7去填充
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padLen := int(data[len(data)-1])
	if padLen <= 0 || padLen > len(data) || padLen > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	// 验证所有填充字节的值都等于 padLen
	for _, b := range data[len(data)-padLen:] {
		if b != byte(padLen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-padLen], nil
}

// AES-CBC加密，返回base64字符串
func AesEncrypt(plainText []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	plainText = pkcs7Pad(plainText, blockSize)
	cipherText := make([]byte, blockSize+len(plainText))
	iv := cipherText[:blockSize]
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[blockSize:], plainText)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// AES-CBC解密
func AesDecrypt(cipherBase64 string, key []byte) ([]byte, error) {
	cipherText, err := base64.StdEncoding.DecodeString(cipherBase64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(cipherText) < blockSize {
		return nil, fmt.Errorf("cipher too short")
	}
	iv := cipherText[:blockSize]
	cipherText = cipherText[blockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)
	return pkcs7Unpad(cipherText)
}

// 生成AES-256密钥
func GenAesKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}
