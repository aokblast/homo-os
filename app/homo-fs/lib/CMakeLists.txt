FILE(GLOB LIB_SRCS *.c)

add_library(homofs STATIC ${LIB_SRCS})
target_compile_options(homofs PUBLIC "-DHOMOFS_HOST_BUILD=1")
target_include_directories(homofs PUBLIC ./)
