cmake_minimum_required(VERSION 4.0)
set(CMAKE_CXX_STANDARD 20)

project(TorVPN)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(src)
add_subdirectory(keygrubber)
