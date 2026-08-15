/*
 * encrypt_main.cpp - 加密工具（PC / WSL 端使用）
 *
 * 用法:
 *   encrypt_bin <script.sh> <decrypt_public.pem> <sign_private.pem> [options]
 *
 * 选项:
 *   --output <file>    输出文件路径 (默认: ./out.sh)
 *   --param <kv>       附加参数，可重复，格式 key=value
 *                      这些参数会写入明文脚本头部作为元数据
 *
 * 输出:
 *   一个 Base64 编码的密文文件（可直接作为 decrypt_bin 的第一个参数）
 *
 * 安全模型:
 *   1. decrypt_public.pem  -> RSA加密AES密钥（只有decrypt_bin能解）
 *   2. sign_private.pem    -> 对HMAC做RSA签名（防止他人复用加密流程）
 *   3. 每次随机AES密钥 + IV（语义安全）
 */

#include "crypto_util.h"

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/error.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <map>

using namespace crypto;

// ======================== 参数解析 ========================
struct EncryptOptions {
    std::string script_path;
    std::string decrypt_pubkey_path;
    std::string sign_privkey_path;
    std::string output_path = "./out.sh";
    std::map<std::string, std::string> extra_params;
};

static void print_usage(const char* prog) {
    std::cerr <<
        "Usage: " << prog << " <script.sh> <decrypt_public.pem> <sign_private.pem> [options]\n"
        "Options:\n"
        "  --output <file>      Output file (default: ./out.sh)\n"
        "  --param <key=value>  Extra parameter (repeatable)\n"
        "  --help               Show this help\n";
}

static EncryptOptions parse_args(int argc, char** argv) {
    EncryptOptions opt;
    int positional = 0;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--output") == 0 && i+1 < argc) {
            opt.output_path = argv[++i];
        } else if (strcmp(argv[i], "--param") == 0 && i+1 < argc) {
            std::string kv = argv[++i];
            size_t eq = kv.find('=');
            if (eq != std::string::npos)
                opt.extra_params[kv.substr(0, eq)] = kv.substr(eq + 1);
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]); exit(0);
        } else {
            if (positional == 0) opt.script_path = argv[i];
            else if (positional == 1) opt.decrypt_pubkey_path = argv[i];
            else if (positional == 2) opt.sign_privkey_path = argv[i];
            ++positional;
        }
    }
    if (positional < 3) { print_usage(argv[0]); exit(1); }
    return opt;
}

// ======================== 文件读取 ========================
static std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cerr << "Cannot read: " << path << std::endl; exit(1); }
    std::stringstream ss; ss << f.rdbuf(); return ss.str();
}

static std::vector<uint8_t> read_file_bin(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cerr << "Cannot read: " << path << std::endl; exit(1); }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
}

// ======================== 签名 ========================
static std::vector<uint8_t> rsa_sign(const std::vector<uint8_t>& data,
    const std::string& pem_sign_privkey) {
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char* pers = "encrypt_sign";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
        (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        char buf[256]; mbedtls_strerror(ret, buf, sizeof(buf));
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        throw std::runtime_error(std::string("ctr_drbg_seed: ") + buf);
    }

    // 注意：mbedtls 3.x 的 pk_parse_key 需要 f_rng 和 p_rng 参数
    ret = mbedtls_pk_parse_key(&pk,
        reinterpret_cast<const unsigned char*>(pem_sign_privkey.data()),
        pem_sign_privkey.size() + 1,
        nullptr, 0,                     // 无密码
        mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        char buf[256]; mbedtls_strerror(ret, buf, sizeof(buf));
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        throw std::runtime_error(std::string("parse sign key: ") + buf);
    }

    std::vector<uint8_t> hash(32);
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md(md, data.data(), data.size(), hash.data());

    std::vector<uint8_t> sig(mbedtls_pk_get_len(&pk));
    size_t sig_len = 0;
    // 注意：第 6 个参数是 sig_size（缓冲区大小），第 7 个是 &sig_len（输出实际长度）
    ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash.data(), hash.size(),
        sig.data(), sig.size(), &sig_len,
        mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        char buf[256]; mbedtls_strerror(ret, buf, sizeof(buf));
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        throw std::runtime_error(std::string("sign: ") + buf);
    }

    sig.resize(sig_len);
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return sig;
}

// ======================== 构建输出 ========================
/*
 * 最终输出格式（写入 out.sh，纯文本 Base64）：
 *
 *   [line 1]  #!ASCE:<base64(package)>:<base64(signature)>
 *
 * 其中 package 是 pack_package() 的二进制结果
 * signature 是对 package 的 HMAC 字段+密文 做 RSA 签名
 */
static void write_output(const std::string& out_path,
                          const std::string& b64_package,
                          const std::string& b64_signature) {
    std::ofstream f(out_path);
    if (!f) { std::cerr << "Cannot write: " << out_path << std::endl; exit(1); }

    // 写入一个可直接在 Android shell 中 source/exec 的包装
    f << "#!/system/bin/sh\n";
    f << "# ─── Android Shell Crypto Encrypted Script ───\n";
    f << "# 解密并自执行：将本文件第一个非空参数传给 decrypt_bin\n\n";

    f << "exec \"$(dirname \"$0\")/decrypt_bin\" \"";
    f << b64_package << ":" << b64_signature;
    f << "\" \"$@\"\n";

    std::cout << "[+] Encrypted script written to: " << out_path << "\n";
    std::cout << "    Package size: " << b64_package.size() << " bytes (base64)\n";
    std::cout << "    Signature size: " << b64_signature.size() << " bytes (base64)\n";
}

// ======================== main ========================
int main(int argc, char** argv) {
    EncryptOptions opt = parse_args(argc, argv);

    try {
        // 1. 读取脚本原文
        std::string script_src = read_file(opt.script_path);
        std::vector<uint8_t> plaintext(script_src.begin(), script_src.end());

        // 2. 读取密钥
        std::string decrypt_pub = read_file(opt.decrypt_pubkey_path);
        std::string sign_priv   = read_file(opt.sign_privkey_path);

        // 3. 生成随机 AES-256 密钥
        std::vector<uint8_t> aes_key = random_bytes(32);

        // 4. AES-256-CBC 加密脚本
        AesResult aes_res = aes256_encrypt(plaintext, aes_key);

        // 5. RSA 加密 AES 密钥
        std::vector<uint8_t> enc_aes_key = rsa_encrypt(aes_key, decrypt_pub);

        // 6. HMAC-SHA256（密钥 = AES密钥派生）
        std::vector<uint8_t> hmac_key = hmac_sha256(aes_key, std::vector<uint8_t>{'h','m','a','c'});
        std::vector<uint8_t> hmac = hmac_sha256(aes_res.ciphertext, hmac_key);

        // 7. 打包
        EncryptedPackage pkg;
        pkg.enc_aes_key = enc_aes_key;
        pkg.iv = aes_res.iv;
        pkg.hmac = hmac;
        pkg.ciphertext = aes_res.ciphertext;

        std::vector<uint8_t> package_bin = pack_package(pkg);
        std::string b64_package = base64_encode(package_bin);

        // 8. 用签名私钥对 package 做 RSA 签名（防复用）
        std::vector<uint8_t> signature = rsa_sign(package_bin, sign_priv);
        std::string b64_signature = base64_encode(signature);

        // 9. 写入输出
        write_output(opt.output_path, b64_package, b64_signature);

        // 清理内存中的密钥
        memset(aes_key.data(), 0, aes_key.size());

    } catch (const std::exception& e) {
        std::cerr << "[-] Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
