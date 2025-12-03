# Minimum CMake version
cmake_minimum_required(VERSION 3.5)

# Project name
project(hash_usage)

# Find DPDK using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

# Include DPDK headers
include_directories(${DPDK_INCLUDE_DIRS})

# Add executable
add_executable(hash_usage main.c)

# Set compile flags using target_compile_options
target_compile_options(hash_usage PRIVATE ${DPDK_CFLAGS_OTHER})
target_compile_definitions(hash_usage PRIVATE ALLOW_EXPERIMENTAL_API)

# Link with DPDK libraries
target_link_libraries(hash_usage ${DPDK_LIBRARIES})

# Set target properties
set_target_properties(hash_usage PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
)