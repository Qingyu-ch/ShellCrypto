#!/bin/bash
# ============================================================================
# build.sh - 一键构建脚本（在 WSL / Linux 中运行）
#
# 用法:
#   ./build.sh              # 默认构建 host (Linux) 工具
#   ./build.sh android      # 交叉编译 Android 端 decrypt_bin
#   ./build.sh keys         # 仅生成密钥对
#   ./build.sh clean        # 清理构建目录
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 颜色
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERR ]${NC} $*"; exit 1; }

# ======================== 清理 ========================
if [[ "$1" == "clean" ]]; then
    info "Cleaning build directories..."
    rm -rf build-host build-android
    exit 0
fi

# ======================== 仅生成密钥 ========================
if [[ "$1" == "keys" ]]; then
    info "Generating keys..."
    mkdir -p build-host && cd build-host
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j$(nproc) keygen_bin
    mkdir -p "$SCRIPT_DIR/keys"
    "$SCRIPT_DIR/build-host/keygen_bin" --out-dir "$SCRIPT_DIR/keys"
    info "Keys generated in ./keys/"
    exit 0
fi

# ======================== 构建 Host 工具 ========================
info "Building HOST tools (encrypt_bin, decrypt_bin, keygen_bin)..."
mkdir -p build-host && cd build-host
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd "$SCRIPT_DIR"

# ======================== 交叉编译 Android ========================
if [[ "$1" == "android" ]]; then
    ANDROID_NDK="${ANDROID_NDK:-$HOME/Android/Sdk/ndk/26.1.10909125}"
    ANDROID_ABI="${ANDROID_ABI:-arm64-v8a}"

    [[ -d "$ANDROID_NDK" ]] || error "Android NDK not found at $ANDROID_NDK. Set \$ANDROID_NDK."

    info "Cross-compiling for Android ($ANDROID_ABI)..."
    mkdir -p build-android && cd build-android

    cmake .. \
        -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI="$ANDROID_ABI" \
        -DANDROID_PLATFORM=android-24 \
        -DCMAKE_BUILD_TYPE=Release

    make -j$(nproc) decrypt_bin
    cd "$SCRIPT_DIR"

    info "Android decrypt_bin built: build-android/decrypt_bin"
fi

# ======================== 安装密钥到源码 ========================
if [[ -d "$SCRIPT_DIR/keys" ]]; then
    info "Keys already exist in ./keys/"
    info "Run CMake again to embed them: cd build-host && cmake .. && make"
else
    warn "No keys found. Run: $0 keys"
fi

echo ""
info "Build complete!"
echo "  Host tools:    build-host/encrypt_bin, build-host/decrypt_bin, build-host/keygen_bin"
[[ "$1" == "android" ]] && echo "  Android binary: build-android/decrypt_bin"
echo ""
echo "Next steps:"
echo "  1. Generate keys:    $0 keys"
echo "  2. Rebuild with keys: cd build-host && cmake .. && make"
echo "  3. Encrypt a script:  build-host/encrypt_bin myscript.sh keys/decrypt_public.pem keys/sign_private.pem --output out.sh"
echo "  4. Push to Android:   adb push build-android/decrypt_bin /data/local/tmp/"
echo "                        adb push out.sh /data/local/tmp/"
echo "  5. Run on Android:    adb shell 'cd /data/local/tmp && sh out.sh'"
