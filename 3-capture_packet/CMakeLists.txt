# Minimum CMake version
cmake_minimum_required(VERSION 3.5)

# Project name
project(hash_usage)

# Find DPDK using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

# Include DPDK headers
include_directories(${DPDK_INCLUDE_DIRS})

# 3-capture_packet executable
add_executable(capture_packet main.c)

# Set compile flags using target_compile_options
target_compile_options(capture_packet PRIVATE ${DPDK_CFLAGS_OTHER})
target_compile_definitions(capture_packet PRIVATE ALLOW_EXPERIMENTAL_API)

# Link with DPDK libraries
target_link_libraries(capture_packet ${DPDK_LIBRARIES})

# Set target properties
set_target_properties(capture_packet PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
)