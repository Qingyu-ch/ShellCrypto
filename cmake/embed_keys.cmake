set(DECRYPT_PRIV_KEY_FILE "${CMAKE_SOURCE_DIR}/keys/decrypt_private.pem")
set(SIGN_PUB_KEY_FILE     "${CMAKE_SOURCE_DIR}/keys/sign_public.pem")

if(EXISTS "${DECRYPT_PRIV_KEY_FILE}" AND EXISTS "${SIGN_PUB_KEY_FILE}")
    file(READ "${DECRYPT_PRIV_KEY_FILE}" DECRYPT_PRIVATE_KEY)
    file(READ "${SIGN_PUB_KEY_FILE}"     SIGN_PUBLIC_KEY)

    configure_file(
        "${CMAKE_SOURCE_DIR}/src/embedded_keys.cpp.in"
        "${CMAKE_BINARY_DIR}/src/embedded_keys.cpp"
        @ONLY
    )
    message(STATUS "✅ Keys embedded successfully")
else()
    message(WARNING "⚠ Keys not found, using placeholders.")
    message(WARNING "  Run: ./build-host/keygen_bin --out-dir ./keys")
    set(DECRYPT_PRIVATE_KEY "PLACEHOLDER")
    set(SIGN_PUBLIC_KEY     "PLACEHOLDER")
    configure_file(
        "${CMAKE_SOURCE_DIR}/src/embedded_keys.cpp.in"
        "${CMAKE_BINARY_DIR}/src/embedded_keys.cpp"
        @ONLY
    )
endif()

set(EMBEDDED_KEYS_SRC "${CMAKE_BINARY_DIR}/src/embedded_keys.cpp")