cmake_minimum_required(VERSION 3.13)
project(AndroidShellCrypto C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

if(CMAKE_SYSTEM_NAME STREQUAL "Android")
    message(STATUS "Target: Android")
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -O3 -fvisibility=hidden -ffunction-sections -fdata-sections -fstack-protector-strong")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -fvisibility=hidden -ffunction-sections -fdata-sections -fstack-protector-strong")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections,--strip-all")
    set(CMAKE_EXE_LINKER_FLAGS    "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections,--strip-all -s")
elseif(MSVC)
    add_compile_options(/utf-8 /permissive- /W3)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    set(CMAKE_C_FLAGS_RELEASE "/O2")
    set(CMAKE_CXX_FLAGS_RELEASE "/O2")
else()
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -O3 -Wall -Wextra -Wno-error=stringop-overflow -Wno-error=array-bounds")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -Wextra")
endif()

set(MBEDTLS_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS        OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING         OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON  CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)

add_subdirectory(${CMAKE_SOURCE_DIR}/third_party/mbedtls)

include(${CMAKE_SOURCE_DIR}/cmake/embed_keys.cmake)
set(EMBEDDED_KEYS_SRC "${CMAKE_BINARY_DIR}/src/embedded_keys.cpp")

set(COMMON_SOURCES
    src/crypto_util.cpp
    ${EMBEDDED_KEYS_SRC}
)

add_executable(encrypt_bin
    src/encrypt_main.cpp
    ${COMMON_SOURCES}
)
target_link_libraries(encrypt_bin PRIVATE mbedcrypto mbedx509 mbedtls)
target_include_directories(encrypt_bin PRIVATE ${CMAKE_SOURCE_DIR}/include)

add_executable(keygen_bin
    src/keygen_main.cpp
    ${COMMON_SOURCES}
)
target_link_libraries(keygen_bin PRIVATE mbedcrypto mbedx509 mbedtls)
target_include_directories(keygen_bin PRIVATE ${CMAKE_SOURCE_DIR}/include)

if(NOT WIN32)
    add_executable(decrypt_bin
        src/decrypt_main.cpp
        ${COMMON_SOURCES}
    )
    target_link_libraries(decrypt_bin PRIVATE mbedcrypto mbedx509 mbedtls)
    target_include_directories(decrypt_bin PRIVATE ${CMAKE_SOURCE_DIR}/include)

    if(CMAKE_SYSTEM_NAME STREQUAL "Android")
        add_custom_command(TARGET decrypt_bin POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all $<TARGET_FILE:decrypt_bin>
            COMMENT "Stripping symbols from decrypt_bin"
        )
    endif()
endif()