cmake_minimum_required(VERSION 4.0)
set(CMAKE_CXX_STANDARD 20)

project(Kurrat)

set(CMAKE_CXX_FLAGS_DEBUG  "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address")
set(CMAKE_C_FLAGS_DEBUG  "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# libraries
include(FindSodium.cmake)

set(ENABLE_TESTING OFF)
include(FetchContent)
FetchContent_Declare(
    mbedtls 
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls
    GIT_TAG master 
    GIT_SHALLOW TRUE
    GIT_PROGRESS TRUE
)
FetchContent_MakeAvailable(mbedtls)

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

find_package(CURL REQUIRED)

if(NOT CURL_FOUND)
  FetchContent_Declare(
    CURL 
    GIT_REPOSITORY https://github.com/curl/curl.git
    GIT_PROGRESS TRUE
    GIT_SHALLOW TURE
  )
  FetchContent_MakeAvailable(CURL)
endif()

add_subdirectory(src)
add_subdirectory(keygrubber)
