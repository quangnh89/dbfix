cmake_minimum_required(VERSION 3.10.2)
project (dbfix)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message("Please switch to x64 build.")
    return()
endif()

set (DBFIX dbfix)

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Od /MTd")
SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Oi /MT")

add_library(${DBFIX} SHARED dbfix.cpp)
