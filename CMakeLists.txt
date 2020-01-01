cmake_minimum_required (VERSION 3.0)
project (cdns)
set(CMAKE_BUILD_TYPE Release)

# find libuv
find_path(LIBUV_INCLUDE_DIRS uv.h)
find_library(LibUV_LIBRARIES uv)
if(NOT LIBUV_INCLUDE_DIRS OR NOT LibUV_LIBRARIES)
    message(FATAL_ERROR "libuv not found")
endif()

# build
add_executable(cdns main.cpp)
set_property(TARGET cdns PROPERTY CXX_STANDARD 17)
target_include_directories(cdns PRIVATE ${LIBUV_INCLUDE_DIRS})
target_link_libraries (cdns ${LibUV_LIBRARIES})

# install (default to /usr/local/bin)
install (TARGETS cdns DESTINATION bin)