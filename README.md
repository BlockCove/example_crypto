# example_encryption

- aes.go — AES 对称加密、解密（含密钥读写文件）
- rsa_crypto.go — RSA 非对称加解密（公钥加密 / 私钥解密）
- rsa_sign.go — RSA 签名、验签（防篡改）

共用同一组 RSA 公私钥文件，main 逻辑统一调用，运行后生成全部密钥 / 密文 / 签名文件。

安全通信标准流程：[点击查看文档](https://my.feishu.cn/wiki/M7tMwJfjViC1fSkTsLHcFvBLnRb?fromScene=spaceOverview)

## 运行

```bash
go run main.go
```