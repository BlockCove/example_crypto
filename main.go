package main

import (
	"encoding/base64"
	"fmt"

	"example_crypto/aesutil"
	"example_crypto/rsautil"
)

var rawText = []byte("Hello Golang 对称+非对称加密+签名完整演示 测试数据123456")

func main() {
	fmt.Println("===== 一、AES 对称加解密演示 =====")
	aesKey, err := aesutil.GenAndSaveAesKey()
	if err != nil {
		panic(err)
	}
	fmt.Printf("AES密钥文件: %s\n密钥HEX: %x\n", aesutil.AesKeyFile, aesKey)

	encStr, err := aesutil.AesEncrypt(rawText, aesKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("AES加密(base64): %s\n", encStr)

	decBytes, err := aesutil.AesDecrypt(encStr, aesKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("AES解密结果: %s\n\n", string(decBytes))

	fmt.Println("===== 二、RSA 非对称加解密演示（公钥加密、私钥解密） =====")
	pri, pub, err := rsautil.GenRsaKeyPair()
	if err != nil {
		panic(err)
	}
	fmt.Printf("私钥: %s\n公钥: %s\n密文文件: %s\n", rsautil.RsaPriFile, rsautil.RsaPubFile, rsautil.RsaEncFile)

	rsaCipher, err := rsautil.RsaEncrypt(pub, rawText)
	if err != nil {
		panic(err)
	}
	fmt.Printf("RSA密文(base64): %s\n", base64.StdEncoding.EncodeToString(rsaCipher))

	rsaPlain, err := rsautil.RsaDecrypt(pri, rsaCipher)
	if err != nil {
		panic(err)
	}
	fmt.Printf("RSA解密结果: %s\n\n", string(rsaPlain))

	fmt.Println("===== 三、RSA 签名验签演示（私钥签名、公钥验证） =====")
	signBuf, err := rsautil.RsaSign(pri, rawText)
	if err != nil {
		panic(err)
	}
	fmt.Printf("签名文件: %s\n签名HEX: %x\n", rsautil.SignFile, signBuf)

	ok := rsautil.RsaVerify(pub, rawText, signBuf)
	fmt.Printf("正常数据验签: %t\n", ok)

	tamper := []byte("篡改之后的内容")
	ok2 := rsautil.RsaVerify(pub, tamper, signBuf)
	fmt.Printf("篡改数据验签: %t\n", ok2)
}
