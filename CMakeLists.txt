cmake_minimum_required(VERSION 4.0)
project(KNX_TestGateway)

set(CMAKE_C_STANDARD 99)

add_subdirectory(KNXnetIP_Lib)

add_executable(KNX_TestGateway main.c)

target_link_libraries(KNX_TestGateway KNXnetIP_Lib)