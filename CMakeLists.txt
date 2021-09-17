cmake_minimum_required(VERSION 3.17)
project(shadow_inspector)

set(CMAKE_CXX_STANDARD 14)

include_directories(include)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

include(cmake/ELFIO.cmake)

add_library(shadow_inspector SHARED library.cpp)
target_link_libraries(shadow_inspector elfio)