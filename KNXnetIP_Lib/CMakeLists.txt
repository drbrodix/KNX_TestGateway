add_library(KNXnetIP_Lib OBJECT
        src/KNXnetIP.c
        includes/KNXnetIP.h)

target_include_directories(KNXnetIP_Lib PUBLIC includes)

target_link_libraries(KNXnetIP_Lib ws2_32) # Need to explicitly link against this winsocket library