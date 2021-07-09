cmake_minimum_required(VERSION 3.7)
project(io.microdog)

add_subdirectory("${PROJECT_SOURCE_DIR}/emulator" "${PROJECT_SOURCE_DIR}/obj/emulator")
add_subdirectory("${PROJECT_SOURCE_DIR}/api" "${PROJECT_SOURCE_DIR}/obj/api")
