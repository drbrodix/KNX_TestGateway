cmake_minimum_required(VERSION 4.0)
project(KNX_TestGateway)

set(CMAKE_C_STANDARD 11)

add_executable(KNX_TestGateway main.c)

target_link_libraries(KNX_TestGateway ws2_32) # Need to explicitly link against this winsocket library