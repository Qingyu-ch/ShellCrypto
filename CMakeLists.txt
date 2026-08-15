cmake_minimum_required(VERSION 3.13)
project(AndroidShellCrypto C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# ============================================================================
# 编译选项
# ============================================================================
if(CMAKE_SYSTEM_NAME STREQUAL "Android")
    message(STATUS "Target: Android")
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -O3 -fvisibility=hidden -ffunction-sections -fdata-sections -fstack-protector-strong")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -fvisibility=hidden -ffunction-sections -fdata-sections -fstack-protector-strong")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections,--strip-all")
    set(CMAKE_EXE_LINKER_FLAGS    "${CMAKE_EXE_LINKER_FLAGS}    -Wl,--gc-sections,--strip-all -s")
else()
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -O3")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
endif()

# ============================================================================
# mbedtls (FetchContent)
# ============================================================================
include(FetchContent)
set(MBEDTLS_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS        OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING         OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON  CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v3.6.0
)

add_subdirectory(${CMAKE_SOURCE_DIR}/third_party/mbedtls)

# ============================================================================
# 密钥嵌入（decrypt 端）
# ============================================================================
include(${CMAKE_SOURCE_DIR}/cmake/embed_keys.cmake)

# embedded_keys.cpp 生成路径
set(EMBEDDED_KEYS_SRC "${CMAKE_BINARY_DIR}/src/embedded_keys.cpp")

# ============================================================================
# 解密端（Android shell 调用）
# ============================================================================
add_executable(decrypt_bin
    src/decrypt_main.cpp
    src/crypto_util.cpp
    ${EMBEDDED_KEYS_SRC}
)
target_link_libraries(decrypt_bin PRIVATE mbedtls mbedx509 mbedcrypto)
target_include_directories(decrypt_bin PRIVATE ${CMAKE_SOURCE_DIR}/include)
set_source_files_properties(${EMBEDDED_KEYS_SRC} PROPERTIES GENERATED TRUE)

# 剥离符号
if(CMAKE_SYSTEM_NAME STREQUAL "Android")
    add_custom_command(TARGET decrypt_bin POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-all $<TARGET_FILE:decrypt_bin>
        COMMENT "Stripping symbols from decrypt_bin"
    )
endif()

# ============================================================================
# 加密端（PC 端 / WSL 端）
# ============================================================================
add_executable(encrypt_bin
    src/encrypt_main.cpp
    src/crypto_util.cpp
    ${EMBEDDED_KEYS_SRC}
)
target_link_libraries(encrypt_bin PRIVATE mbedtls mbedx509 mbedcrypto)
target_include_directories(encrypt_bin PRIVATE ${CMAKE_SOURCE_DIR}/include)

# ============================================================================
# 密钥生成
# ============================================================================
add_executable(keygen_bin
    src/keygen_main.cpp
    src/crypto_util.cpp
    ${EMBEDDED_KEYS_SRC}  
)
target_link_libraries(keygen_bin PRIVATE mbedtls mbedx509 mbedcrypto)
target_include_directories(keygen_bin PRIVATE ${CMAKE_SOURCE_DIR}/include)

# ============================================================================
# 安装
# ============================================================================
install(TARGETS decrypt_bin encrypt_bin keygen_bin
    RUNTIME DESTINATION bin
)
