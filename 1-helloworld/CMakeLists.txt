# Minimum CMake version
cmake_minimum_required(VERSION 3.5)

# Project name
project(helloworld)

# Find DPDK using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

# Include DPDK headers
include_directories(${DPDK_INCLUDE_DIRS})

# Add executable
add_executable(helloworld main.c)

# Set compile flags using target_compile_options
target_compile_options(helloworld PRIVATE ${DPDK_CFLAGS_OTHER})
target_compile_definitions(helloworld PRIVATE ALLOW_EXPERIMENTAL_API)

# Link with DPDK libraries
target_link_libraries(helloworld ${DPDK_LIBRARIES})

# Set target properties
set_target_properties(helloworld PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
)