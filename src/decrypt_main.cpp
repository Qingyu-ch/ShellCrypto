/*
 * decrypt_main.cpp - 解密并执行（Android 端二进制）
 *
 * 用法（由加密后的 shell 脚本自动调用）:
 *   decrypt_bin <base64_package>:<base64_signature> [extra_args...]
 *
 * 流程:
 *   1. 拆分参数，Base64 解码
 *   2. 用内置签名公钥验证签名 → 防复用/伪造
 *   3. 解包 → 用内置 RSA 私钥解密 AES 密钥
 *   4. AES-256-CBC 解密脚本
 *   5. 写临时文件 → 用 /system/bin/sh 执行
 *   6. 执行完毕删除临时文件
 *
 * 安全加固:
 *   - 私钥编译时内嵌（-D 宏注入）
 *   - 符号剥离（CMake POST_BUILD）
 *   - 防内存 dump：密钥使用后立即清零
 *   - 临时文件权限 700，执行后立即删除
 */

#include "crypto_util.h"

#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/error.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

using namespace crypto;

// ======================== 签名验证 ========================
static bool rsa_verify(const std::vector<uint8_t>& data,
                        const std::vector<uint8_t>& signature,
                        const std::string& pem_sign_pubkey) {
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int ret = mbedtls_pk_parse_public_key(
        &pk,
        reinterpret_cast<const unsigned char*>(pem_sign_pubkey.data()),
        pem_sign_pubkey.size() + 1);
    if (ret != 0) return false;

    std::vector<uint8_t> hash(32);
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md(md, data.data(), data.size(), hash.data());

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash.data(), hash.size(),
                              signature.data(), signature.size());
    mbedtls_pk_free(&pk);
    return (ret == 0);
}

// ======================== 参数解析 ========================
struct DecryptInput {
    std::string b64_package;
    std::string b64_signature;
    std::vector<std::string> extra_args;
};

static DecryptInput parse_decrypt_args(int argc, char** argv) {
    DecryptInput inp;
    if (argc < 2) {
        std::cerr << "Usage: decrypt_bin <base64_pkg>:<base64_sig> [args...]\n";
        exit(1);
    }

    std::string first = argv[1];
    size_t colon = first.find(':');
    if (colon == std::string::npos) {
        std::cerr << "[-] Invalid input format (missing ':' separator)\n";
        exit(1);
    }
    inp.b64_package   = first.substr(0, colon);
    inp.b64_signature = first.substr(colon + 1);

    for (int i = 2; i < argc; ++i) {
        inp.extra_args.emplace_back(argv[i]);
    }
    return inp;
}

// ======================== 临时文件 ========================
static std::string write_temp_script(const std::string& content) {
    char tmpname[] = "/data/local/tmp/.dec_XXXXXX.sh";
    int fd = mkstemp(tmpname);
    if (fd < 0) { perror("mkstemp"); exit(1); }

    // 权限 700
    fchmod(fd, 0700);

    ssize_t written = write(fd, content.data(), content.size());
    if (written != (ssize_t)content.size()) { perror("write"); exit(1); }
    close(fd);

    return std::string(tmpname);
}

// ======================== 执行脚本 ========================
static int execute_script(const std::string& script_path,
                           const std::vector<std::string>& extra_args) {
    // 构建命令行
    std::string cmd = "/system/bin/sh \"" + script_path + "\"";

    // 如果有额外参数，追加（简单处理，避免注入）
    for (const auto& a : extra_args) {
        cmd += " \"";
        // 转义双引号
        for (char c : a) {
            if (c == '"') cmd += '\\';
            cmd += c;
        }
        cmd += "\"";
    }

    std::cout << "[*] Executing decrypted script...\n";
    int ret = system(cmd.c_str());

    // 清理
    unlink(script_path.c_str());
    return ret;
}

// ======================== main ========================
int main(int argc, char** argv) {
    DecryptInput inp = parse_decrypt_args(argc, argv);

    try {
        // 1. Base64 解码
        std::vector<uint8_t> package_bin = base64_decode(inp.b64_package);
        std::vector<uint8_t> signature   = base64_decode(inp.b64_signature);

        // 2. 获取内置密钥
        EmbeddedKey ek = get_embedded_key();

        // 3. 验证签名（防复用/伪造）
        if (!rsa_verify(package_bin, signature, ek.sign_public_pem)) {
            std::cerr << "[-] Signature verification FAILED! Aborting.\n";
            return 1;
        }

        // 4. 解包
        EncryptedPackage pkg = unpack_package(package_bin);

        // 5. RSA 解密 AES 密钥
        std::vector<uint8_t> aes_key = rsa_decrypt(pkg.enc_aes_key, ek.rsa_private_pem);

        // 6. 验证 HMAC
        std::vector<uint8_t> hmac_key = hmac_sha256(aes_key, std::vector<uint8_t>{'h','m','a','c'});
        std::vector<uint8_t> expected_hmac = hmac_sha256(pkg.ciphertext, hmac_key);
        if (expected_hmac != pkg.hmac) {
            std::cerr << "[-] HMAC verification FAILED! Data corrupted.\n";
            // 清零密钥
            memset(aes_key.data(), 0, aes_key.size());
            return 1;
        }

        // 7. AES 解密
        std::vector<uint8_t> plaintext = aes256_decrypt(pkg.ciphertext, pkg.iv, aes_key);

        // 立即清零 AES 密钥
        memset(aes_key.data(), 0, aes_key.size());

        // 8. 写入临时文件
        std::string script(plaintext.begin(), plaintext.end());
        plaintext.clear();
        memset(plaintext.data(), 0, plaintext.size());

        std::string tmp_path = write_temp_script(script);
        script.clear();

        // 9. 执行
        int ret = execute_script(tmp_path, inp.extra_args);

        return ret;

    } catch (const std::exception& e) {
        std::cerr << "[-] Decrypt error: " << e.what() << std::endl;
        return 1;
    }
}
