cmake_minimum_required(VERSION 3.10)
project(homo_tester)

add_subdirectory(./lib)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../tiny-AES-c ${CMAKE_CURRENT_BINARY_DIR}/tiny-AES-c)

add_executable(homo_example ./example.c)
target_link_libraries(homo_example homofs)
add_executable(homo_pack ./homo_pack.c)
target_link_libraries(homo_pack homofs tiny-aes)

