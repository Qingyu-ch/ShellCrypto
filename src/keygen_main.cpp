/*
 * keygen_main.cpp - 密钥生成工具
 *
 * 用法:
 *   keygen_bin [--bits 2048] [--out-dir ./keys]
 *
 * 生成 4 个文件：
 *   decrypt_private.pem   -> 放入解密端（编译内置）
 *   decrypt_public.pem    -> 给加密端使用
 *   sign_private.pem      -> 给加密端使用（签名）
 *   sign_public.pem       -> 放入解密端（编译内置）
 */

#include "crypto_util.h"

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>

using namespace crypto;

static void write_file(const std::string& path, const std::string& content) {
    std::ofstream f(path);
    if (!f) { std::cerr << "Cannot write: " << path << std::endl; exit(1); }
    f << content;
}

int main(int argc, char** argv) {
    int bits = 2048;
    std::string out_dir = "./keys";

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--bits") == 0 && i+1 < argc) {
            bits = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--out-dir") == 0 && i+1 < argc) {
            out_dir = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            std::cout << "Usage: keygen_bin [--bits 2048] [--out-dir ./keys]\n";
            return 0;
        }
    }

    std::cout << "[*] Generating " << bits << "-bit RSA keypair for DECRYPT (AES key unwrap)...\n";
    KeyPair decrypt_kp = generate_rsa_keypair(bits);

    std::cout << "[*] Generating " << bits << "-bit RSA keypair for SIGN (anti-reuse)...\n";
    KeyPair sign_kp = generate_rsa_keypair(bits);

    write_file(out_dir + "/decrypt_private.pem", decrypt_kp.private_pem);
    write_file(out_dir + "/decrypt_public.pem",  decrypt_kp.public_pem);
    write_file(out_dir + "/sign_private.pem",    sign_kp.private_pem);
    write_file(out_dir + "/sign_public.pem",     sign_kp.public_pem);

    std::cout << "[+] Keys generated in " << out_dir << "/\n";
    std::cout << "    decrypt_private.pem  -> embed in decrypt_bin (CMake)\n";
    std::cout << "    decrypt_public.pem   -> use with encrypt_bin --pubkey\n";
    std::cout << "    sign_private.pem     -> use with encrypt_bin --signkey\n";
    std::cout << "    sign_public.pem      -> embed in decrypt_bin (CMake)\n";
    return 0;
}
