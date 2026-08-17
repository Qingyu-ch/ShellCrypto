/*
 * Android 端解密执行程序
 * 用法: decrypt_bin <base64_package>:<base64_signature> [extra_args...]
 *   or: decrypt_bin @<payload_file> [extra_args...]
 *   or: 环境变量 DECRYPT_DATA=<base64_package>:<base64_signature>
 * 新增: --output <file>  将解密后的脚本写入文件而非直接执行
 */

#include "crypto_util.h"

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

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
#include <sys/stat.h>
#include <fcntl.h>
#include <algorithm>
#include <cctype>
#include <sys/types.h>
#include <errno.h>
#include <string.h>

constexpr bool kDebugMode = true;

using namespace crypto;

// bionic 自带的 mkstemp 经常失败，这里自己实现一版
extern "C" int mkstemp(char* tmpl) {
    char* xxx = strstr(tmpl, "XXXXXX");
    if (!xxx) {
        errno = EINVAL;
        return -1;
    }

    static int counter = 0;
    for (int attempt = 0; attempt < 1000; ++attempt) {
        snprintf(xxx, 7, "%05d", (counter++ % 100000));
        int fd = open(tmpl, O_CREAT | O_EXCL | O_RDWR, 0600);
        if (fd >= 0) {
            return fd;
        }
        if (errno != EEXIST) {
            return -1;
        }
    }
    errno = EEXIST;
    return -1;
}

struct DecryptInput {
    std::string b64_package;
    std::string b64_signature;
    std::vector<std::string> extra_args;
    std::string output_path;   // 新增：输出文件路径，为空则不输出文件
};

// 只保留 Base64 合法字符
static std::string clean_b64(const std::string& raw) {
    std::string result;
    for (unsigned char c : raw) {
        if (std::isalnum(c) || c == '+' || c == '/' || c == '=') {
            result.push_back(c);
        }
    }
    return result;
}

static DecryptInput parse_decrypt_args(int argc, char** argv) {
    DecryptInput inp;
    std::string first;

    // 新增：解析 --output 参数
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            inp.output_path = argv[++i];
            // 标记该参数已被消费，后续不再作为 payload 或 extra_args
            argv[i - 1] = nullptr;
            argv[i] = nullptr;
        }
    }

    // 收集剩余的非空参数
    std::vector<char*> remaining;
    for (int i = 1; i < argc; ++i) {
        if (argv[i] != nullptr) {
            remaining.push_back(argv[i]);
        }
    }
    int remaining_argc = (int)remaining.size();
    char** remaining_argv = remaining.data();

    if (remaining_argc >= 1) {
        std::string arg = remaining_argv[0];
        // @file 语法：从文件读取 payload
        if (arg.rfind("@", 0) == 0) {
            std::string filepath = arg.substr(1);
            std::ifstream f(filepath);
            if (!f) {
                std::cerr << "[-] Cannot read payload file: " << filepath << "\n";
                exit(1);
            }
            std::stringstream ss;
            ss << f.rdbuf();
            first = ss.str();
            while (!first.empty() && (first.back() == '\n' || first.back() == '\r'))
                first.pop_back();
            while (!first.empty() && (first.front() == '\n' || first.front() == '\r'))
                first.erase(0, 1);
        }
        else {
            first = arg;
        }
    }
    else {
        char* env = getenv("DECRYPT_DATA");
        if (env) {
            first = env;
        }
        else {
            std::cerr << "Usage: decrypt_bin <base64_pkg>:<base64_sig> [args...]\n";
            std::cerr << "   or decrypt_bin @<payload_file>\n";
            std::cerr << "   or set env DECRYPT_DATA=<base64_pkg>:<base64_sig>\n";
            std::cerr << "Options:\n";
            std::cerr << "  --output <file>   Write decrypted script to file instead of executing\n";
            exit(1);
        }
    }

    size_t colon = first.find(':');
    if (colon == std::string::npos) {
        std::cerr << "[-] Invalid input format (missing ':' separator)\n";
        exit(1);
    }
    inp.b64_package = clean_b64(first.substr(0, colon));
    inp.b64_signature = clean_b64(first.substr(colon + 1));

    // Base64 长度需为 4 的倍数，不足补 '='
    auto pad_base64 = [](std::string& s) {
        size_t rem = s.size() % 4;
        if (rem > 0) {
            s.append(4 - rem, '=');
        }
        };
    pad_base64(inp.b64_package);
    pad_base64(inp.b64_signature);

    // 剩余参数作为 extra_args（跳过第一个 payload 参数）
    int arg_start = (remaining_argc >= 1) ? 1 : 0;
    for (int i = arg_start; i < remaining_argc; ++i) {
        inp.extra_args.emplace_back(remaining_argv[i]);
    }
    return inp;
}

// RSA 验签（SHA256）
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

// fork + pipe：把解密后的脚本内容经 stdin 喂给 sh，避免写临时文件
static int execute_script_via_pipe(const std::string& script_content,
    const std::vector<std::string>& extra_args) {

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        perror("pipe");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        // 子进程：管道读端接 stdin，执行 sh
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);

        std::vector<char*> args;
        args.push_back(const_cast<char*>("/system/bin/sh"));
        for (const auto& a : extra_args) {
            args.push_back(const_cast<char*>(a.c_str()));
        }
        args.push_back(nullptr);

        std::cout << "[*] Executing decrypted script...\n";
        execv("/system/bin/sh", args.data());

        perror("execv");
        _exit(127);
    }
    else {
        // 父进程：脚本内容写入管道
        close(pipefd[0]);

        const char* data = script_content.data();
        ssize_t total = script_content.size();
        ssize_t written = 0;
        while (written < total) {
            ssize_t w = write(pipefd[1], data + written, total - written);
            if (w < 0) {
                perror("write");
                break;
            }
            written += w;
        }
        close(pipefd[1]);

        int status;
        waitpid(pid, &status, 0);
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }
}

int main(int argc, char** argv) {
    DecryptInput inp = parse_decrypt_args(argc, argv);

    try {
        EmbeddedKey ek = get_embedded_key();

        // 1. Base64 解码
        std::vector<uint8_t> package_bin, signature;
        try {
            package_bin = base64_decode(inp.b64_package);
            signature = base64_decode(inp.b64_signature);
        }
        catch (...) {
            std::cerr << "[-] base64_decode failed\n";
            return 1;
        }

        if (kDebugMode) {
            std::cerr << "[DEBUG] package_bin size: " << package_bin.size() << "\n";
            std::cerr << "[DEBUG] package_bin hex: ";
            for (auto b : package_bin) printf("%02x", b);
            std::cerr << "\n";
            std::cerr << "[DEBUG] signature size: " << signature.size() << "\n";
        }

        // 2. 验签
        if (!rsa_verify(package_bin, signature, ek.sign_public_pem)) {
            std::cerr << "[-] Signature verification FAILED\n";
            return 1;
        }

        if (kDebugMode) {
            std::cerr << "[DEBUG] Signature verification OK\n";
        }

        // 3. 解包
        EncryptedPackage pkg = unpack_package(package_bin);
        if (kDebugMode) {
            std::cerr << "[DEBUG] pkg.iv size: " << pkg.iv.size() << " hex: ";
            for (auto b : pkg.iv) printf("%02x", b);
            std::cerr << "\n";
            std::cerr << "[DEBUG] pkg.ciphertext size: " << pkg.ciphertext.size() << "\n";
            std::cerr << "[DEBUG] pkg.hmac size: " << pkg.hmac.size() << " hex: ";
            for (auto b : pkg.hmac) printf("%02x", b);
            std::cerr << "\n";
            std::cerr << "[DEBUG] pkg.enc_aes_key size: " << pkg.enc_aes_key.size() << "\n";
        }

        // 4. RSA 解密 AES 密钥
        std::vector<uint8_t> aes_key = rsa_decrypt(pkg.enc_aes_key, ek.rsa_private_pem);
        if (kDebugMode) {
            std::cerr << "[DEBUG] aes_key size: " << aes_key.size() << " hex: ";
            for (auto b : aes_key) printf("%02x", b);
            std::cerr << "\n";
        }

        // 5. HMAC 校验
        auto hmac_key = hmac_sha256(aes_key, { 'h','m','a','c' });
        auto calc_hmac = hmac_sha256(pkg.ciphertext, hmac_key);
        if (kDebugMode) {
            std::cerr << "[DEBUG] calc_hmac hex: ";
            for (auto b : calc_hmac) printf("%02x", b);
            std::cerr << "\n";
            std::cerr << "[DEBUG] expected hmac hex: ";
            for (auto b : pkg.hmac) printf("%02x", b);
            std::cerr << "\n";
        }

        if (calc_hmac != pkg.hmac) {
            std::cerr << "[-] HMAC verification FAILED\n";
            return 1;
        }

        if (kDebugMode) {
            std::cerr << "[DEBUG] HMAC verification OK\n";
        }

        // 6. AES 解密
        std::vector<uint8_t> plaintext = aes256_decrypt(pkg.ciphertext, pkg.iv, aes_key);
        if (kDebugMode) {
            std::cerr << "[DEBUG] plaintext size: " << plaintext.size() << "\n";
            std::cerr << "[DEBUG] plaintext hex: ";
            for (auto b : plaintext) printf("%02x", b);
            std::cerr << "\n";
        }

        // 7. 解密结果即 shell 脚本原文
        std::string script(plaintext.begin(), plaintext.end());

        if (kDebugMode) {
            std::cerr << "=== DECRYPTED SCRIPT BEGIN ===\n";
            std::cerr << script;
            std::cerr << "\n=== DECRYPTED SCRIPT END ===\n";
        }

        // 8. 根据是否指定 --output 决定写入文件还是管道执行
        if (!inp.output_path.empty()) {
            // 写入文件
            std::ofstream out(inp.output_path, std::ios::binary);
            if (!out) {
                std::cerr << "[-] Cannot write output file: " << inp.output_path << "\n";
                return 1;
            }
            out << script;
            out.close();
            std::cout << "[+] Decrypted script saved to: " << inp.output_path << "\n";
            return 0;
        }
        else {
            // 管道方式直接交给 sh 执行
            int pipefd[2];
            if (pipe(pipefd) != 0) {
                perror("pipe");
                return 1;
            }

            pid_t pid = fork();
            if (pid < 0) {
                perror("fork");
                return 1;
            }

            if (pid == 0) {
                close(pipefd[1]);
                dup2(pipefd[0], STDIN_FILENO);
                close(pipefd[0]);

                std::vector<char*> args;
                args.push_back(const_cast<char*>("/system/bin/sh"));
                for (const auto& a : inp.extra_args) {
                    args.push_back(const_cast<char*>(a.c_str()));
                }
                args.push_back(nullptr);

                std::cout << "[*] Executing decrypted script...\n";
                execv("/system/bin/sh", args.data());
                perror("execv");
                _exit(127);
            }
            else {
                close(pipefd[0]);

                const char* data = script.data();
                ssize_t total = script.size();
                ssize_t written = 0;
                while (written < total) {
                    ssize_t w = write(pipefd[1], data + written, total - written);
                    if (w < 0) {
                        perror("write");
                        break;
                    }
                    written += w;
                }
                close(pipefd[1]);

                int status;
                waitpid(pid, &status, 0);
                return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
            }
        }

    }
    catch (const std::exception& e) {
        std::cerr << "[-] Decrypt error: " << e.what() << std::endl;
        return 1;
    }
}