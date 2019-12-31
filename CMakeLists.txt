cmake_minimum_required (VERSION 3.0)
project (cdns)
set(CMAKE_BUILD_TYPE Release)
add_executable(cdns main.cpp)
set_property(TARGET cdns PROPERTY CXX_STANDARD 17)
target_link_libraries (cdns uv)
# installs to /usr/local/bin as intended
install (TARGETS cdns DESTINATION bin)
