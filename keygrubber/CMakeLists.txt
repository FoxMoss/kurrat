add_executable(keygrubber
 main.cpp
)

target_link_libraries(keygrubber mbedtls sodium)

add_custom_command(TARGET keygrubber POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_BINARY_DIR}/compile_commands.json
        ${CMAKE_SOURCE_DIR}/compile_commands.json
    COMMENT "Add clangd to the base directory")
