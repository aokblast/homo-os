FILE(GLOB LIB_SRCS *.c)

add_library(homofs STATIC ${LIB_SRCS})
target_include_directories(homofs PUBLIC ./)