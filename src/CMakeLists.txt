add_executable(kurrat
 main.cpp
 tor.cpp
 pipe.cpp
 keys.cpp
 make_tor.cpp
 exitnodes.cpp
 donna/ed25519_tor.c
 microsocks/sockssrv.c
 microsocks/server.c
 microsocks/sblist.c
 microsocks/sblist_delete.c
)

target_link_libraries(kurrat PRIVATE mbedtls sodium expected CLI11::CLI11 curl)

add_custom_command(TARGET kurrat POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_BINARY_DIR}/compile_commands.json
        ${CMAKE_SOURCE_DIR}/compile_commands.json
    COMMENT "Add clangd to the base directory")

install(TARGETS kurrat DESTINATION bin)
