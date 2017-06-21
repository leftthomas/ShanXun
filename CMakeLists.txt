cmake_minimum_required(VERSION 3.7)
project(shanxun)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        dialer/CMakeLists.txt
        dialer/main.cpp
        dialer/md5.h
        adsl
        DialConfig.txt)

include_directories(.)
include_directories(dialer)

add_executable(shanxun ${SOURCE_FILES})