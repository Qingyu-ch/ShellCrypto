#include "crypto_util.h"

#include <mbedtls/aes.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>
#include <mbedtls/base64.h>
#include <mbedtls/error.h>

#include <stdexcept>
#include <cstring>

namespace crypto {

    // mbedtls 错误码转异常
    static void throw_on_error(int ret, const char* ctx) {
        if (ret == 0) return;
        char buf[256];
        mbedtls_strerror(ret, buf, sizeof(buf));
        throw std::runtime_error(std::string(ctx) + " failed: " + buf);
    }

    std::string base64_encode(const std::vector<uint8_t>& data) {
        size_t olen = 0;
        mbedtls_base64_encode(nullptr, 0, &olen, data.data(), data.size());
        std::string out(olen, '\0');
        int ret = mbedtls_base64_encode(
            reinterpret_cast<unsigned char*>(out.data()), out.size(), &olen,
            data.data(), data.size());
        throw_on_error(ret, "base64_encode");
        out.resize(olen);
        return out;
    }

    std::vector<uint8_t> base64_decode(const std::string& b64) {
        size_t olen = 0;
        mbedtls_base64_decode(nullptr, 0, &olen,
            reinterpret_cast<const unsigned char*>(b64.data()), b64.size());
        std::vector<uint8_t> out(olen);
        int ret = mbedtls_base64_decode(
            out.data(), out.size(), &olen,
            reinterpret_cast<const unsigned char*>(b64.data()), b64.size());
        throw_on_error(ret, "base64_decode");
        out.resize(olen);
        return out;
    }

    // 基于 CTR-DRBG 的安全随机数
    std::vector<uint8_t> random_bytes(size_t len) {
        std::vector<uint8_t> buf(len);
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);

        const char* pers = "android_shell_crypto";
        int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
            reinterpret_cast<const unsigned char*>(pers), strlen(pers));
        throw_on_error(ret, "ctr_drbg_seed");

        ret = mbedtls_ctr_drbg_random(&ctr_drbg, buf.data(), buf.size());
        throw_on_error(ret, "ctr_drbg_random");

        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return buf;
    }

    // AES-256-CBC 加密，PKCS#7 填充，IV 随机生成
    AesResult aes256_encrypt(const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key) {
        if (key.size() != 32) throw std::runtime_error("AES-256 key must be 32 bytes");

        AesResult result;
        result.iv = random_bytes(16);

        size_t pad_len = 16 - (plaintext.size() % 16);
        std::vector<uint8_t> padded = plaintext;
        padded.insert(padded.end(), pad_len, static_cast<uint8_t>(pad_len));

        result.ciphertext.resize(padded.size());

        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        int ret = mbedtls_aes_setkey_enc(&aes, key.data(), 256);
        throw_on_error(ret, "aes_setkey_enc");

        // mbedtls_aes_crypt_cbc 会改写 IV，用副本保护原始 IV
        std::vector<uint8_t> iv_copy = result.iv;
        ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT,
            padded.size(), iv_copy.data(),
            padded.data(), result.ciphertext.data());
        throw_on_error(ret, "aes_crypt_cbc encrypt");

        mbedtls_aes_free(&aes);
        return result;
    }

    std::vector<uint8_t> aes256_decrypt(const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& key) {
        if (key.size() != 32) throw std::runtime_error("AES-256 key must be 32 bytes");
        if (ciphertext.size() % 16 != 0) throw std::runtime_error("Ciphertext not 16-byte aligned");

        std::vector<uint8_t> padded(ciphertext.size());
        std::vector<uint8_t> iv_copy = iv;

        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        int ret = mbedtls_aes_setkey_dec(&aes, key.data(), 256);
        throw_on_error(ret, "aes_setkey_dec");

        ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT,
            ciphertext.size(), iv_copy.data(),
            ciphertext.data(), padded.data());
        throw_on_error(ret, "aes_crypt_cbc decrypt");

        mbedtls_aes_free(&aes);

        uint8_t pad_len = padded.back();
        if (pad_len < 1 || pad_len > 16) throw std::runtime_error("Invalid PKCS#7 padding");
        padded.resize(padded.size() - pad_len);
        return padded;
    }

    // RSA 公钥加密
    std::vector<uint8_t> rsa_encrypt(const std::vector<uint8_t>& plaintext,
        const std::string& pem_public_key) {
        mbedtls_pk_context pk;
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;

        mbedtls_pk_init(&pk);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);

        const char* pers = "rsa_encrypt";
        int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
            reinterpret_cast<const unsigned char*>(pers), strlen(pers));
        throw_on_error(ret, "ctr_drbg_seed");

        ret = mbedtls_pk_parse_public_key(&pk,
            reinterpret_cast<const unsigned char*>(pem_public_key.data()),
            pem_public_key.size() + 1);
        throw_on_error(ret, "pk_parse_public_key");

        std::vector<uint8_t> out(mbedtls_pk_get_len(&pk));
        size_t olen = 0;
        ret = mbedtls_pk_encrypt(&pk, plaintext.data(), plaintext.size(),
            out.data(), &olen, out.size(),
            mbedtls_ctr_drbg_random, &ctr_drbg);
        throw_on_error(ret, "pk_encrypt");

        out.resize(olen);
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return out;
    }

    // RSA 私钥解密
    std::vector<uint8_t> rsa_decrypt(const std::vector<uint8_t>& ciphertext,
        const std::string& pem_private_key) {
        mbedtls_pk_context pk;
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;

        mbedtls_pk_init(&pk);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);

        const char* pers = "rsa_decrypt";
        int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
            reinterpret_cast<const unsigned char*>(pers), strlen(pers));
        throw_on_error(ret, "ctr_drbg_seed");

        ret = mbedtls_pk_parse_key(&pk,
            reinterpret_cast<const unsigned char*>(pem_private_key.data()),
            pem_private_key.size() + 1,
            nullptr, 0,
            mbedtls_ctr_drbg_random, &ctr_drbg);
        throw_on_error(ret, "pk_parse_key");

        std::vector<uint8_t> out(mbedtls_pk_get_len(&pk));
        size_t olen = 0;
        ret = mbedtls_pk_decrypt(&pk, ciphertext.data(), ciphertext.size(),
            out.data(), &olen, out.size(),
            mbedtls_ctr_drbg_random, &ctr_drbg);
        throw_on_error(ret, "pk_decrypt");

        out.resize(olen);
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return out;
    }

    std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& key) {
        const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        if (!md_info) throw std::runtime_error("SHA256 not available");

        std::vector<uint8_t> mac(mbedtls_md_get_size(md_info));
        int ret = mbedtls_md_hmac(md_info, key.data(), key.size(),
            data.data(), data.size(), mac.data());
        throw_on_error(ret, "hmac_sha256");
        return mac;
    }

    // 生成 RSA 密钥对，返回 PEM 字符串
    KeyPair generate_rsa_keypair(int bits) {
        mbedtls_pk_context pk;
        mbedtls_pk_init(&pk);

        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);

        const char* pers = "keygen";
        int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
            reinterpret_cast<const unsigned char*>(pers), strlen(pers));
        throw_on_error(ret, "ctr_drbg_seed");

        ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
        throw_on_error(ret, "pk_setup");

        ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk),
            mbedtls_ctr_drbg_random, &ctr_drbg, bits, 65537);
        throw_on_error(ret, "rsa_gen_key");

        std::vector<uint8_t> priv_buf(4096);
        size_t priv_len = 0;
        ret = mbedtls_pk_write_key_pem(&pk, priv_buf.data(), priv_buf.size());
        throw_on_error(ret, "write_key_pem");
        priv_len = strlen(reinterpret_cast<char*>(priv_buf.data()));
        std::string priv_pem(reinterpret_cast<char*>(priv_buf.data()), priv_len);

        std::vector<uint8_t> pub_buf(4096);
        size_t pub_len = 0;
        ret = mbedtls_pk_write_pubkey_pem(&pk, pub_buf.data(), pub_buf.size());
        throw_on_error(ret, "write_pubkey_pem");
        pub_len = strlen(reinterpret_cast<char*>(pub_buf.data()));
        std::string pub_pem(reinterpret_cast<char*>(pub_buf.data()), pub_len);

        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);

        return { priv_pem, pub_pem };
    }

    // 二进制包格式: magic(4) + version(1) + reserved(3) + klen(2) + enc_aes_key(klen) + iv(16) + hmac(32) + clen(4) + ciphertext(clen)
    std::vector<uint8_t> pack_package(const EncryptedPackage& pkg) {
        std::vector<uint8_t> out;
        const char magic[4] = { 'A','S','C','E' };
        out.insert(out.end(), magic, magic + 4);
        out.push_back(0x01);                       // version
        out.push_back(0x00); out.push_back(0x00); out.push_back(0x00); // reserved

        uint16_t klen = (uint16_t)pkg.enc_aes_key.size();
        out.push_back((klen >> 8) & 0xFF);
        out.push_back(klen & 0xFF);
        out.insert(out.end(), pkg.enc_aes_key.begin(), pkg.enc_aes_key.end());

        out.insert(out.end(), pkg.iv.begin(), pkg.iv.end());

        out.insert(out.end(), pkg.hmac.begin(), pkg.hmac.end());

        uint32_t clen = (uint32_t)pkg.ciphertext.size();
        for (int i = 3; i >= 0; --i) out.push_back((clen >> (i * 8)) & 0xFF);
        out.insert(out.end(), pkg.ciphertext.begin(), pkg.ciphertext.end());

        return out;
    }

    EncryptedPackage unpack_package(const std::vector<uint8_t>& data) {
        EncryptedPackage pkg;
        if (data.size() < 8 || memcmp(data.data(), "ASCE", 4) != 0)
            throw std::runtime_error("Invalid magic header");
        size_t pos = 4;
        uint8_t ver = data[pos++];
        if (ver != 0x01) throw std::runtime_error("Unsupported version");
        pos += 3;

        if (pos + 2 > data.size()) throw std::runtime_error("Truncated: klen");
        uint16_t klen = (data[pos] << 8) | data[pos + 1];
        pos += 2;
        if (pos + klen > data.size()) throw std::runtime_error("Truncated: enc_aes_key");
        pkg.enc_aes_key.assign(data.begin() + pos, data.begin() + pos + klen);
        pos += klen;

        if (pos + 16 > data.size()) throw std::runtime_error("Truncated: iv");
        pkg.iv.assign(data.begin() + pos, data.begin() + pos + 16);
        pos += 16;

        if (pos + 32 > data.size()) throw std::runtime_error("Truncated: hmac");
        pkg.hmac.assign(data.begin() + pos, data.begin() + pos + 32);
        pos += 32;

        if (pos + 4 > data.size()) throw std::runtime_error("Truncated: clen");
        uint32_t clen = 0;
        for (int i = 0; i < 4; ++i) clen = (clen << 8) | data[pos + i];
        pos += 4;

        if (pos + clen != data.size())
            throw std::runtime_error("Length mismatch: ciphertext");
        if (clen % 16 != 0)
            throw std::runtime_error("Ciphertext not 16-byte aligned");

        pkg.ciphertext.assign(data.begin() + pos, data.begin() + pos + clen);
        return pkg;
    }

    // 内置密钥由 CMake configure_file 注入
    extern const char* EMBEDDED_DECRYPT_PRIVATE_KEY;
    extern const char* EMBEDDED_SIGN_PUBLIC_KEY;

    EmbeddedKey get_embedded_key() {
        return { EMBEDDED_DECRYPT_PRIVATE_KEY, EMBEDDED_SIGN_PUBLIC_KEY };
    }

} // namespace crypto