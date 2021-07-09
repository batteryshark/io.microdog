cmake_minimum_required(VERSION 3.17)

set(CMAKE_C_STANDARD 99)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  "~/")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY  "~/")
set(CMAKE_SHARED_LIBRARY_PREFIX  "")
set(CMAKE_C_FLAGS_RELEASE "-O0")
project(emulator_linux C)
add_library(emulator_linux SHARED
        ../common/target.h
        ../common/aes.c
        ../common/md5.c
        ../common/ini.c
        ../common/utils.c
        ../common/memutils.c
        ../protocol/protocol.c
        emulator_config.c
        server_emulator.c
        emulator_linux.c
)
set_target_properties(emulator_linux PROPERTIES OUTPUT_NAME "io.microdog.emulator")
set_target_properties(emulator_linux PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
target_link_libraries(emulator_linux dl)