#!/bin/bash
set -e

cd /tmp/androidshellcrypto

# 1. Android x86_64
echo "=== Building Android x86_64 ==="
rm -rf build-android-x86_64 && mkdir build-android-x86_64 && cd build-android-x86_64
cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=x86_64 -DANDROID_PLATFORM=android-21 \
    -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd ..

# 2. Android arm64-v8a
echo "=== Building Android arm64-v8a ==="
rm -rf build-android-arm64 && mkdir build-android-arm64 && cd build-android-arm64
cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-21 \
    -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd ..

# 3. Linux arm64
echo "=== Building Linux arm64 ==="
rm -rf build-linux-arm64 && mkdir build-linux-arm64 && cd build-linux-arm64
cmake .. \
  -DCMAKE_TOOLCHAIN_FILE=/tmp/androidshellcrypto/aarch64-toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd ..

# 4. Linux x86_64 (本机原生)
echo "=== Building Linux x86_64 (native) ==="
rm -rf build-linux-x86_64 && mkdir build-linux-x86_64 && cd build-linux-x86_64
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd ..

echo "=== All builds complete ==="
ls -lh build-*/{decrypt_bin,encrypt_bin} 2>/dev/null