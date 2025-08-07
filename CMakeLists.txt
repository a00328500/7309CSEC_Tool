# ===================================================
# Cybersecurity Log Summarizer Bot - CMake Configuration
# ===================================================

# [1] Minimum CMake version and project setup
cmake_minimum_required(VERSION 3.12)
project(CyberLogSummarizer VERSION 1.0.0 LANGUAGES CXX)

# [8] Configure source files with absolute paths
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/logParser.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ollamaClient.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/reportGenerator.cpp
)

set(HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/include/logParser.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/ollamaClient.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/reportGenerator.h
)

# [2] C++ standard and compiler options
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# [3] Project options
option(BUILD_TESTS "Build test cases" OFF)
option(ENABLE_WINDOWS_EVTX "Enable Windows Event Log support" OFF)

# [4] Compiler warnings
if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -pedantic -Werror)
endif()

# [5] Attempt to find system ZLIB first
set(ZLIB_ROOT "C:/msys64/ucrt64" CACHE PATH "Path to ZLIB installation") # Adjust for your system
find_package(ZLIB QUIET)

if(NOT ZLIB_FOUND)
    # [6] Fallback: Bundle ZLIB from source
    message(STATUS "System ZLIB not found - using bundled version")
    include(FetchContent)
    
    FetchContent_Declare(
        zlib
        URL https://zlib.net/zlib-1.3.1.tar.gz
        URL_HASH SHA256=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
    )
    
    FetchContent_MakeAvailable(zlib)
    set(ZLIB_INCLUDE_DIRS ${zlib_SOURCE_DIR} ${zlib_BINARY_DIR})
    set(ZLIB_LIBRARIES zlibstatic)
endif()

# [7] Find JsonCpp - Modified version with better compatibility
find_package(Jsoncpp REQUIRED)

# Handle different JsonCpp target names across versions
if(TARGET jsoncpp_lib)
    # Older versions use this target name
    set(JSONCPP_TARGET jsoncpp_lib)
elseif(TARGET JsonCpp::JsonCpp)
    # Some versions use this capitalization
    set(JSONCPP_TARGET JsonCpp::JsonCpp)
elseif(TARGET Jsoncpp::Jsoncpp)
    # Modern versions use this
    set(JSONCPP_TARGET Jsoncpp::Jsoncpp)
else()
    message(FATAL_ERROR "Could not determine JsonCpp target name")
endif()

# [9] Debug print to verify files
message(STATUS "Source files:")
foreach(src ${SOURCES})
    if(EXISTS ${src})
        message(STATUS "Found: ${src}")
    else()
        message(WARNING "Missing: ${src}")
    endif()
endforeach()

# [10] Only proceed if sources exist
list(LENGTH SOURCES NUM_SOURCES)
if(NUM_SOURCES GREATER 0)
    add_executable(logsummarizer ${SOURCES} ${HEADERS})
else()
    message(FATAL_ERROR "No valid source files found")
endif()

# [11] Install targets
install(TARGETS logsummarizer
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

# [12] Testing (optional)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()