cmake_minimum_required(VERSION 3.13)
set(ZEPHYR_TOOLCHAIN_VARIANT gnuarmemb)
set(BOARD mps2/an385)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(homo-os C ASM)

file(GLOB DRV_SRCS ./src/drivers/*.c)
file(GLOB FS_SRCS ./homo-fs/lib/*.c)

zephyr_include_directories(./homo-fs/lib/)
add_subdirectory(tiny-AES-c)

# build homo os pack tools
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/homo_pack
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/homo-fs/build
    COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_SOURCE_DIR}/homo-fs/build ${CMAKE_COMMAND} ..
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_CURRENT_SOURCE_DIR}/homo-fs/build
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_SOURCE_DIR}/homo-fs/build/homo_pack
        ${CMAKE_CURRENT_BINARY_DIR}/homo_pack
    COMMENT "Building and copying homo_pack tool"
)

# build fs
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/homo_fs_data
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/homo_pack
    COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR} && ${CMAKE_CURRENT_BINARY_DIR}/homo_pack fe ${CMAKE_CURRENT_BINARY_DIR}/homo_fs_data
)

# build homo_fs_data to object
get_filename_component(INPUT_BIN_ABS "${CMAKE_CURRENT_BINARY_DIR}/homo_fs_data" ABSOLUTE)

## Generate symbol name from path
## Replace '/', '.', and '-' with '_'
string(REPLACE "/" "_" BIN_SYM_BASE "${INPUT_BIN_ABS}")
string(REPLACE "." "_" BIN_SYM_BASE "${BIN_SYM_BASE}")
string(REPLACE "-" "_" BIN_SYM_BASE "${BIN_SYM_BASE}")

set(SYM_START "_binary_${BIN_SYM_BASE}_start")
set(SYM_END   "_binary_${BIN_SYM_BASE}_end")
set(SYM_SIZE  "_binary_${BIN_SYM_BASE}_size")

message(STATUS "Embedding binary: ${INPUT_BIN}")
message(STATUS "  ${SYM_START} → fs data start")
message(STATUS "  ${SYM_END}   → fs data end  ")
message(STATUS "  ${SYM_SIZE}  → fs data size ")

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/homo_fs_data.o
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/homo_fs_data
    COMMAND ${CMAKE_OBJCOPY}
            -I binary 
            -O elf32-littlearm 
            -B arm
            --redefine-sym ${SYM_START}=homo_fs_data_start
            --redefine-sym ${SYM_END}=homo_fs_data_end
            --redefine-sym ${SYM_SIZE}=homo_fs_data_size
            ${CMAKE_CURRENT_BINARY_DIR}/homo_fs_data
            ${CMAKE_CURRENT_BINARY_DIR}/homo_fs_data.o
    
    COMMENT "Embedding raw binary file into firmware"
)


# The target "app" is defined within the Zephyr package by "find_package(Zephyr ...)".
target_sources(
    app
    PRIVATE
    src/main.c ${DRV_SRCS} ${FS_SRCS}
    ${CMAKE_CURRENT_BINARY_DIR}/homo_fs_data.o
)

zephyr_link_libraries(tiny-aes)