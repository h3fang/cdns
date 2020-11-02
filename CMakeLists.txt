cmake_minimum_required (VERSION 3.0)
project (cdns)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# find libuv
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUV REQUIRED libuv)

# build
add_executable(cdns main.cpp)
set_property(TARGET cdns PROPERTY CXX_STANDARD 11)
target_include_directories(cdns PRIVATE ${LIBUV_INCLUDE_DIRS})
target_link_libraries (cdns ${LIBUV_LIBRARIES})

# install (default to /usr/local/bin)
install (TARGETS cdns DESTINATION bin)