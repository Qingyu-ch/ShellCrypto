// 由 CMake 在编译时注入
namespace crypto {
    extern const char* EMBEDDED_DECRYPT_PRIVATE_KEY;
    extern const char* EMBEDDED_SIGN_PUBLIC_KEY;

    const char* EMBEDDED_DECRYPT_PRIVATE_KEY =
R"(PLACEHOLDER)";

    const char* EMBEDDED_SIGN_PUBLIC_KEY =
R"(PLACEHOLDER)";
}
