cmake_minimum_required(VERSION 3.10)
project(cybersec-tools CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall -Wextra")

# Find required packages
find_package(Threads REQUIRED)

# Add C++ tools
add_executable(crypto_tools tools/cpp/crypto_tools.cpp)
add_executable(port_scanner tools/cpp/port_scanner.cpp)

# Link libraries
target_link_libraries(port_scanner PRIVATE Threads::Threads)

# Set output directories
set_target_properties(crypto_tools port_scanner
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Installation
install(TARGETS crypto_tools port_scanner DESTINATION bin)
