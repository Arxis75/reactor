cmake_minimum_required(VERSION 3.0.0)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_GLIBCXX_DEBUG")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(myProject VERSION 1.0)

include_directories(${CMAKE_SOURCE_DIR}/src)

enable_testing()

add_subdirectory(src)