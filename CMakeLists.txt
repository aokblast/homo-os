cmake_minimum_required(VERSION 3.13)
set(ZEPHYR_TOOLCHAIN_VARIANT gnuarmemb)
set(GNUARMEMB_TOOLCHAIN_PATH /usr)
set(BOARD mps2/an385)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(homo-os C ASM)

# The target "app" is defined within the Zephyr package by "find_package(Zephyr ...)".
target_sources(
    app
    PRIVATE
    src/main.c
)