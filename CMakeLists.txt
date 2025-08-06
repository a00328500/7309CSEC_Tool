cmake_minimum_required(VERSION 3.12)
project(CyberLogSummarizer VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard and compiler options
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Project options
option(BUILD_TESTS "Build test cases" OFF)
option(ENABLE_WINDOWS_EVTX "Enable Windows Event Log support" OFF)

# Compiler warnings
if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -pedantic -Werror)
endif()

# Find required packages
find_package(CURL REQUIRED)
find_package(Jsoncpp REQUIRED)

# Windows Event Log support
if(ENABLE_WINDOWS_EVTX)
    find_package(LibEvtx REQUIRED)
    add_definitions(-DENABLE_EVTX_SUPPORT)
endif()

# Configure source files
set(SOURCES
    src/main.cpp
    src/logParser.cpp
    src/ollamaClient.cpp
    src/reportGenerator.cpp
)

set(HEADERS
    include/logParser.h
    include/ollamaClient.h
    include/reportGenerator.h
)

# Create executable
add_executable(logsummarizer ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(logsummarizer PRIVATE
    CURL::libcurl
    Jsoncpp::Jsoncpp
)

if(ENABLE_WINDOWS_EVTX)
    target_link_libraries(logsummarizer PRIVATE LibEvtx::LibEvtx)
endif()

# Install targets
install(TARGETS logsummarizer
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

# Testing
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Package configuration
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/CyberLogSummarizerConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CyberLogSummarizerConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/CyberLogSummarizerConfig.cmake"
    INSTALL_DESTINATION lib/cmake/CyberLogSummarizer
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/CyberLogSummarizerConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/CyberLogSummarizerConfigVersion.cmake"
    DESTINATION lib/cmake/CyberLogSummarizer
)