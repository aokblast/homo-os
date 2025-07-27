cmake_minimum_required(VERSION 3.13)
set(ZEPHYR_TOOLCHAIN_VARIANT gnuarmemb)
set(BOARD mps2/an385)

set_property(GLOBAL APPEND PROPERTY extra_post_build_commands
  COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/script/mod_section.py
        ${CMAKE_CURRENT_BINARY_DIR}/zephyr/zephyr.elf
        ${CMAKE_CURRENT_BINARY_DIR}/homo_final.elf
)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(homo-os C ASM)

zephyr_linker_sources(SECTIONS sections-rom.ld)
zephyr_linker_section(NAME
                http_resource_desc_homo
				KVMA RAM_REGION GROUP RODATA_REGION
				SUBALIGN ${CONFIG_LINKER_ITERABLE_SUBALIGN})

# The target "app" is defined within the Zephyr package by "find_package(Zephyr ...)".
target_sources(
    app
    PRIVATE
    src/main.c
    src/decode_data.c
    src/chacha20.c
)