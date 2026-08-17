# Android Shell Crypto
[!]目前项目Release全部在安卓端运行，暂纯Linux解密需要自行编译运行，结尾增加参数保证输出正确：
decrypt_bin <input> [extra_args...] [--output <file>]

[!]目前项目处于开发模式，可能有bug，请提交Issues        
[!]包含AI生成的代码，遇到问题请立即提交Issues


通过 C++ 二进制保护 Android shell 脚本，防止他人轻易查看/篡改脚本原文

## 架构

```
┌───────────────────────────────────┐
│                    PC / WSL 端 (开发)                      │
│                                                           │
│  example_script.sh ──► encrypt_bin ──► out.sh          │
│       │                    │                             │
│       │                    ├─ decrypt_public.pem  (RSA) │
│       │                    └─ sign_private.pem    (RSA) │
│       │                                                  │
│       ▼                                                  │
│  ┌────────────────────┐                    │
│  │ out.sh (加密后)                  │                    │
│  │  #!/system/bin/sh               │                    │
│  │  exec decrypt_bin <base64>:<sig>│                    │
│  └────────────┬───────┘                    │ 
└──────────────┼────────────────────┘
                adb push │ 
                         ▼
┌───────────────────────────────────┐
│                    Android 端 (运行)                       │
│                                                           │
│  out.sh ──► decrypt_bin (C++ 二进制)                     │
│                  │                                       │
│                  ├─ 验证签名 (内置 sign_public.pem)        │
│                  ├─ RSA 解密 AES 密钥 (内置 decrypt_priv)  │
│                  ├─ AES-256-CBC 解密脚本                  │
│                  ├─ 写入 /data/local/tmp/.dec_XXXXXX.sh   │
│                  ├─ /system/bin/sh 执行                   │
│                  └─ 删除临时文件                           │
│                                                           │
│  内置密钥 (编译时嵌入):                                      │
│    - decrypt_private.pem  → 解密 AES 密钥                  │
│    - sign_public.pem      → 验证签名                       │
└────────────────────────────────────┘
```

## 安全模型

| 威胁 | 防御手段 |
|------|----------|
| 查看脚本原文 | AES-256-CBC 加密，密钥 RSA 加密，私钥编译内置 |
| 篡改加密脚本 | HMAC-SHA256 完整性校验 |
| 复用加密流程 | RSA 签名验证（sign 私钥不公开） |
| 提取内置密钥 | 符号剥离 + `-fvisibility=hidden` + 密钥清零 |
| 内存 dump | 密钥使用后立即 `memset(0)` |

## 快速开始

### 1. 准备环境 (WSL)

```bash
sudo apt update
sudo apt install -y build-essential cmake git

# Android NDK（交叉编译需要）
# 从 https://developer.android.com/ndk 下载
export ANDROID_NDK=$HOME/Android/Sdk/ndk/26.1.10909125
```

### 2. 生成密钥对

```bash
cd androidshellcrypto
chmod +x build.sh
./build.sh keys
```

生成 4 个文件到 `keys/` 目录：
- `decrypt_private.pem` — **编译嵌入** decrypt_bin
- `decrypt_public.pem`  — 给 encrypt_bin 用
- `sign_private.pem`    — 给 encrypt_bin 用（**不公开**）
- `sign_public.pem`     — **编译嵌入** decrypt_bin

### 3. 构建 Host 工具 + Android 二进制

```bash
# 构建 Linux 端工具
./build.sh

# 交叉编译 Android 端（需要 NDK）
./build.sh android
```

### 4. 加密脚本

```bash
./build-host/encrypt_bin \
    example_script.sh \
    keys/decrypt_public.pem \
    keys/sign_private.pem \
    --output out.sh
```

### 5. 部署到 Android

```bash
adb push build-android/decrypt_bin /data/local/tmp/
adb push out.sh /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/decrypt_bin /data/local/tmp/out.sh"
```

### 6. 运行

```bash
adb shell "cd /data/local/tmp && ./out.sh"
```

## 文件结构

```
androidshellcrypto/
├── CMakeLists.txt              # 主构建配置
├── build.sh                    # 一键构建脚本
├── README.md
├── example_script.sh           # 示例脚本
├── cmake/
│   └── embed_keys.cmake       # 密钥注入 CMake 脚本
├── include/
│   └── crypto_util.h          # 公共头文件
├── src/
│   ├── crypto_util.cpp        # 加密工具实现
│   ├── encrypt_main.cpp       # 加密端 main
│   ├── decrypt_main.cpp       # 解密端 main
│   ├── keygen_main.cpp        # 密钥生成
│   └── embedded_keys.cpp.in   # 密钥嵌入模板
└── keys/                       # 生成的密钥（不提交 git）
    ├── decrypt_private.pem
    ├── decrypt_public.pem
    ├── sign_private.pem
    └── sign_public.pem
```

## 加密包格式

```
┌─────────────────────────────────────────────────────┐
│ Magic (4B): "ASCE"                                  │
│ Version (1B): 0x01                                  │
│ Reserved (3B): 0x000000                             │
│ Enc AES Key Len (2B BE)                             │
│ Enc AES Key (RSA-2048 encrypted, ~256B)             │
│ IV (16B)                                            │
│ HMAC-SHA256 (32B)                                   │
│ Ciphertext Len (4B BE)                              │
│ Ciphertext (AES-256-CBC, PKCS#7 padded)             │
└─────────────────────────────────────────────────────┘
```

外层再 Base64 编码，与 RSA 签名一起拼成 `b64_pkg:b64_sig`。

## 安全建议

1. **不要提交 `keys/` 到公开仓库** — 加入 `.gitignore`
2. **定期轮换密钥** — 重新生成 + 重新编译 decrypt_bin
3. **sign_private.pem 只在开发机保留** — 丢失后无法加密新脚本
4. **Android 端 decrypt_bin 放 `/data/local/tmp/`** — 普通 app 无法读取
5. **考虑加反调试** — 检测 `gdb`/`strace` 附加（进阶）
6. **考虑加 root 检测** — 防止 rooted 设备 dump 内存

## 编译选项说明

| 选项 | 作用 |
|------|------|
| `-O3` | 最高优化 |
| `-fvisibility=hidden` | 隐藏符号 |
| `-ffunction-sections -fdata-sections` | 配合 `--gc-sections` 删除无用代码 |
| `--strip-all` | 剥离所有符号表 |
| `-s` (链接) | 隐藏导入表 |

## License

Apache-2.0 license
