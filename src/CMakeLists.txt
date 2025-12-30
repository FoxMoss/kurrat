

include(FetchContent)
FetchContent_Declare(
    mbedtls 
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls
    GIT_TAG master 
    GIT_SHALLOW true
    GIT_PROGRESS TRUE
)
FetchContent_MakeAvailable(mbedtls)

# add_compile_options(-std=c++23)
set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -std=c++23 -fsanitize=address")

add_executable(torvpn
 main.cpp
 tor.hpp
 donna/ed25519_tor.c
)

target_link_libraries(torvpn mbedtls sodium)

add_custom_command(TARGET torvpn POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_BINARY_DIR}/compile_commands.json
        ${CMAKE_SOURCE_DIR}/compile_commands.json
    COMMENT "Add clangd to the base directory")

install(TARGETS torvpn DESTINATION bin)
