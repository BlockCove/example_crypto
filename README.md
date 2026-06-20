# example_crypto

Go 密码学完整演示项目，涵盖对称加密、非对称加解密、数字签名与验签。

## 功能概览

| 模块 | 算法 | 说明 |
|------|------|------|
| AES 对称加解密 | AES-256-CBC + PKCS7 | 随机生成 256 位密钥，IV 随机，输出 Base64 密文 |
| RSA 非对称加解密 | RSA-2048 + OAEP(SHA-256) | 公钥加密 / 私钥解密，密钥对在内存中生成 |
| RSA 签名验签 | RSA-2048 + PKCS1v15(SHA-256) | 私钥签名 / 公钥验证，含篡改检测演示 |

## 项目结构

```
example_crypto/
├── main.go                  # 入口：串联 AES、RSA 加解密及签名验签流程
├── aesutil/
│   └── aes.go               # AES-256-CBC 加解密 + 密钥生成
├── rsautil/
│   ├── rsa_crypto.go        # RSA 密钥对生成、加解密
│   └── rsa_sign.go          # RSA 签名与验签
├── go.mod
└── README.md
```

## 运行

```bash
go run main.go
```

纯 Go 标准库实现，无第三方依赖。所有密钥均在内存中生成，不写入文件。
