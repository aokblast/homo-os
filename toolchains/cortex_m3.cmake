# Name of the target
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR cortex-m3)

set(THREADX_ARCH "cortex_m3")
set(THREADX_TOOLCHAIN "gnu")

set(MCPU_FLAGS "-mthumb -mcpu=cortex-m3")
set(VFP_FLAGS "")
set(SPEC_FLAGS "--specs=nosys.specs")
# set(LD_FLAGS "-nostartfiles")
add_compile_options(-ffreestanding)
add_link_options(-nostdlib -nostartfiles -ereset_handler)

include_directories(
        ${CMAKE_SOURCE_DIR}/picolibc/include
)

include(${CMAKE_CURRENT_LIST_DIR}/../threadx/cmake/arm-none-eabi.cmake)