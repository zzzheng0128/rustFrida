cmake_minimum_required(VERSION 3.22.1)
project(compatdemo C)

add_library(compatdemo SHARED
        syscalls.c
        native_demo.c)

target_compile_options(compatdemo PRIVATE -O2 -Wall -Wextra)
find_library(log-lib log)
target_link_libraries(compatdemo ${log-lib} android)
