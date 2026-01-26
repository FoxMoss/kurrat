cmake_minimum_required(VERSION ${CMAKE_VERSION})
set(CMAKE_CXX_STANDARD 20)

project(Kurrat)

# set(CMAKE_CXX_FLAGS_DEBUG  "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address")
# set(CMAKE_C_FLAGS_DEBUG  "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address")

option(KURRAT_BUILD_STATIC "Will the binary be built as a self contained static executable" OFF)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")


if(KURRAT_BUILD_STATIC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static -static-libgcc")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static -static-libgcc -static-libstdc++")
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
  set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

  set(BUILD_SHARED_LIBS ON CACHE BOOL "" FORCE)
  set(BUILD_STATIC_LIBS OFF CACHE BOOL "" FORCE)
endif()


set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


set(CMAKE_INSTALL_RPATH "/usr/local/lib")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_SKIP_BUILD_RPATH FALSE)

# libraries
set(ENABLE_TESTING CACHE INTERNAL OFF)
set(ENABLE_PROGRAMS CACHE INTERNAL OFF)

include(FetchContent)
FetchContent_Declare(
    mbedtls 
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls
    GIT_TAG master 
    GIT_SHALLOW TRUE
    GIT_PROGRESS TRUE
)
FetchContent_MakeAvailable(mbedtls)

set(MBEDTLS_INCLUDE_DIR ${mbedtls_SOURCE_DIR}/include)
set(MBEDTLS_LIBRARY mbedtls)
set(MBEDX509_LIBRARY mbedx509)
set(MBEDCRYPTO_LIBRARY mbedcrypto)
set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})
set(MBEDTLS_LIBRARIES ${MBEDTLS_LIBRARY} ${MBEDX509_LIBRARY} ${MBEDCRYPTO_LIBRARY})

include(FetchContent)
FetchContent_Declare(
    cli11_proj
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG v2.6.1
    GIT_PROGRESS TRUE
)

FetchContent_MakeAvailable(cli11_proj)

include(FetchContent)
FetchContent_Declare(
    expected
    GIT_REPOSITORY https://github.com/TartanLlama/expected
    GIT_TAG v1.3.1
    GIT_PROGRESS TRUE
)

FetchContent_MakeAvailable(expected)

set(CURL_USE_MBEDTLS ON CACHE BOOL "" FORCE)
set(CURL_USE_OPENSSL OFF CACHE BOOL "" FORCE)
set(CURL_USE_LIBPSL OFF CACHE BOOL "" FORCE)
set(CURL_DISABLE_LDAP ON CACHE BOOL "" FORCE)
set(CURL_DISABLE_LDAPS ON CACHE BOOL "" FORCE)
set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)
set(CURL_ZLIB OFF CACHE BOOL "" FORCE)
set(CURL_BROTLI OFF CACHE BOOL "" FORCE)
set(CURL_USE_LIBPSL OFF CACHE BOOL "" FORCE)


find_package(CURL)
set(LIBCURL_TARGET curl)
if(NOT CURL_FOUND)
  FetchContent_Declare(
    CURL 
    URL https://github.com/curl/curl/releases/download/curl-8_18_0/curl-8.18.0.tar.xz
  )
  FetchContent_MakeAvailable(CURL)
  set(LIBCURL_TARGET libcurl)
endif()

FetchContent_Declare(
    maxminddb 
    GIT_REPOSITORY https://github.com/maxmind/libmaxminddb
    GIT_TAG 1.12.2
    GIT_PROGRESS TRUE
)

FetchContent_MakeAvailable(maxminddb)

include(FetchContent)
FetchContent_Declare(
    libsodium 
    GIT_REPOSITORY https://github.com/jedisct1/libsodium
    GIT_TAG 1.0.20-RELEASE
    GIT_PROGRESS TRUE
)

FetchContent_MakeAvailable(libsodium)

include(FindSodium.cmake)

add_subdirectory(src)
add_subdirectory(keygrubber)
