# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file LICENSE.rst or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "E:/Class/androidshellcrypto/out/build/x64-Debug/_deps/mbedtls-src")
  file(MAKE_DIRECTORY "E:/Class/androidshellcrypto/out/build/x64-Debug/_deps/mbedtls-src")
endif()
file(MAKE_DIRECTORY
  "E:/Class/androidshellcrypto/out/build/x64-Debug/_deps/mbedtls-build"
  "E:/Class/androidshellcrypto/out/build/x64-Debug/_deps/mbedtls-subbuild/mbedtls-populate-prefix"
  "E:/Class/androidshellcrypto/out/build/x64-Debug/_deps/mbedtls-subbuild/mbedtls-populate-prefix/tmp"
  "E:/Class/androidshellcrypto/out/build/x64-Debug/_deps/mbedtls-subbuild/mbedtls-populate-prefix/src/mbedtls-populate-stamp"
  "E:/Class/androidshellcrypto/out/build/x64-Debug/_deps/mbedtls-subbuild/mbedtls-populate-prefix/src"
  "E:/Class/androidshellcrypto/out/build/x64-Debug/_deps/mbedtls-subbuild/mbedtls-populate-prefix/src/mbedtls-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "E:/Class/androidshellcrypto/out/build/x64-Debug/_deps/mbedtls-subbuild/mbedtls-populate-prefix/src/mbedtls-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "E:/Class/androidshellcrypto/out/build/x64-Debug/_deps/mbedtls-subbuild/mbedtls-populate-prefix/src/mbedtls-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
