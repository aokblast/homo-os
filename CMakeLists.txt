cmake_minimum_required(VERSION 3.13)
project(homo-os C ASM)

message(STATUS "Using Toolchain File: ${CMAKE_TOOLCHAIN_FILE}")

set(__THREAD_LOCAL_STORAGE_API TRUE)

# Include picolibc
add_subdirectory(picolibc crt)

# Include ThreadX as a subdirectory
add_subdirectory(threadx tx)

# Include your application source
include_directories(
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/bsp/drivers/
)

if (NOT ${THREADX_ARCH} STREQUAL "linux")
    set(LINKER_SCRIPT "${CMAKE_SOURCE_DIR}/src/bsp/${THREADX_ARCH}/${BOARD_NAME}/ldscripts.ld")
    file(GLOB BSP_PLAT_SRC CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/bsp/${THREADX_ARCH}/*.S")
    file(GLOB BSP_PLAT_BRD_SRC CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/bsp/${THREADX_ARCH}/${BOARD_NAME}/*.S")
    file(GLOB CRT_BRD_SRC CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/crt/${BOARD_NAME}/*.c")
endif ()

file(GLOB BSP_SRC CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/bsp/drivers/*.c")

file(GLOB CRT_SRC CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/crt/*.c")

file(GLOB APP_SRC CONFIGURE_DEPENDS "src/*.c")

add_executable(${PROJECT_NAME}.elf ${APP_SRC} ${BSP_SRC} ${BSP_PLAT_SRC} ${BSP_PLAT_BRD_SRC} ${CRT_SRC} ${CRT_BRD_SRC})

set_property(TARGET ${PROJECT_NAME}.elf PROPERTY LINK_DEPENDS ${LINKER_SCRIPT})

target_link_libraries(${PROJECT_NAME}.elf threadx c -Wl,--script -Wl,${LINKER_SCRIPT} gcc)

# Optional: generate .bin and .hex files
add_custom_command(TARGET ${PROJECT_NAME}.elf POST_BUILD
        COMMAND arm-none-eabi-objcopy -O binary ${PROJECT_NAME}.elf ${PROJECT_NAME}.bin
        COMMAND arm-none-eabi-objcopy -O ihex ${PROJECT_NAME}.elf ${PROJECT_NAME}.hex
)