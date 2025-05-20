cmake_minimum_required(VERSION 3.13)
project(homo-os C ASM)

message(STATUS "Using Toolchain File: ${CMAKE_TOOLCHAIN_FILE}")
# Include ThreadX as a subdirectory
add_subdirectory(threadx lib)
# Include your application source
include_directories(
        ${CMAKE_SOURCE_DIR}/src
)

if (NOT ${THREADX_ARCH} STREQUAL "linux")
    set(LINKER_SCRIPT "${CMAKE_SOURCE_DIR}/src/${THREADX_ARCH}/sample_threadx.ld")
    file(GLOB DEP_SRC CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/${THREADX_ARCH}/*.S")
endif ()


file(GLOB APP_SRC CONFIGURE_DEPENDS "src/*.c")

add_executable(${PROJECT_NAME}.elf ${APP_SRC} ${DEP_SRC})

set_property(TARGET ${PROJECT_NAME}.elf PROPERTY LINK_DEPENDS ${LINKER_SCRIPT})

target_link_libraries(${PROJECT_NAME}.elf threadx -nostartfiles -ereset_handler -Wl,--script -Wl,${LINKER_SCRIPT})

# Optional: generate .bin and .hex files
add_custom_command(TARGET ${PROJECT_NAME}.elf POST_BUILD
        COMMAND arm-none-eabi-objcopy -O binary ${PROJECT_NAME}.elf ${PROJECT_NAME}.bin
        COMMAND arm-none-eabi-objcopy -O ihex ${PROJECT_NAME}.elf ${PROJECT_NAME}.hex
)