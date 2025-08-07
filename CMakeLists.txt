cmake_minimum_required(VERSION 3.10)
project(CybersecurityTool)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(CURL REQUIRED)

# Include directories
include_directories(include)

# Source files
add_executable(cybertool
    src/main.cpp
    src/LogParser.cpp
    src/OllamaClient.cpp
    src/SecurityAnalyzer.cpp
    src/utils.cpp
)

# Link libraries
target_link_libraries(cybertool PRIVATE ${CURL_LIBRARIES})