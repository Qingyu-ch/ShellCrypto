#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace crypto {

    using uint8_t = std::uint8_t;

    // AES 加密结果
    struct AesResult {
        std::vector<uint8_t> iv;
        std::vector<uint8_t> ciphertext;
    };

    // 加密包（二进制格式）
    struct EncryptedPackage {
        std::vector<uint8_t> enc_aes_key;   // RSA 加密后的 AES 密钥
        std::vector<uint8_t> iv;            // AES CBC IV
        std::vector<uint8_t> hmac;          // HMAC-SHA256
        std::vector<uint8_t> ciphertext;    // AES 密文
    };

    // 密钥对
    struct KeyPair {
        std::string private_pem;
        std::string public_pem;
    };

    // 编译时注入的内置密钥
    struct EmbeddedKey {
        std::string rsa_private_pem;   // 解密私钥
        std::string sign_public_pem;   // 验签公钥
    };

    // ---------- Base64 ----------
    std::string base64_encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> base64_decode(const std::string& b64);

    // ---------- 随机数 ----------
    std::vector<uint8_t> random_bytes(size_t len);

    // ---------- AES-256-CBC ----------
    AesResult aes256_encrypt(const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key);
    std::vector<uint8_t> aes256_decrypt(const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& key);

    // ---------- RSA ----------
    std::vector<uint8_t> rsa_encrypt(const std::vector<uint8_t>& plaintext,
        const std::string& pem_public_key);
    std::vector<uint8_t> rsa_decrypt(const std::vector<uint8_t>& ciphertext,
        const std::string& pem_private_key);

    // ---------- HMAC-SHA256 ----------
    std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& key);

    // ---------- 密钥对生成 ----------
    KeyPair generate_rsa_keypair(int bits = 2048);

    // ---------- 打包 / 解包 ----------
    std::vector<uint8_t> pack_package(const EncryptedPackage& pkg);
    EncryptedPackage unpack_package(const std::vector<uint8_t>& data);

    // ---------- 内置密钥（由 embedded_keys.cpp 提供常量） ----------
    EmbeddedKey get_embedded_key();

} // namespace crypto