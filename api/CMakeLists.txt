cmake_minimum_required(VERSION 3.17)

set(CMAKE_C_STANDARD 99)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY  "~/")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "~/")


project(gsmh C)

add_library(gsmh STATIC ../protocol/protocol.c ../common/utils.c ../common/md5.c ../common/aes.c gsmh.c)
set_target_properties(gsmh PROPERTIES PREFIX "")
set_target_properties(gsmh PROPERTIES SUFFIX ".o")


set_target_properties(gsmh PROPERTIES OUTPUT_NAME "mhlinuxc")

set_target_properties(gsmh PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
