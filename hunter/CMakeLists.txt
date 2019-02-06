cmake_minimum_required(VERSION 3.1)
include("cmake/include/init.cmake")
project(hunter-libevhtp)

if (NOT TARGET libevhtp::evhtp)
    hunter_add_package(libevhtp)
    find_package(libevhtp CONFIG REQUIRED)
endif()

add_executable(main main.c)
target_link_libraries(main libevhtp::evhtp)
