cmake_minimum_required(VERSION 3.13)
set(ZEPHYR_TOOLCHAIN_VARIANT gnuarmemb)
set(BOARD mps2/an385)

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
)