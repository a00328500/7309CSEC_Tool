# ==============================================
# Cybersecurity Log Summarizer - Minimal Build Configuration
# ==============================================

# [1] Minimum CMake version and project setup
cmake_minimum_required(VERSION 3.12)
project(CyberLogSummarizer VERSION 1.0.0 LANGUAGES CXX)

# [2] Compiler settings
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# [3] Source files (relative paths)
set(SOURCES
    src/main.cpp
    src/logParser.cpp
    src/ollamaClient.cpp
    src/reportGenerator.cpp
)

# [4] Header files (relative paths)
set(HEADERS
    include/logParser.h
    include/ollamaClient.h
    include/reportGenerator.h
)

# [5] Create executable
add_executable(logsummarizer ${SOURCES} ${HEADERS})

# [6] Include directories
target_include_directories(logsummarizer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# [7] Find dependencies
find_package(CURL REQUIRED)
find_package(Jsoncpp REQUIRED)
find_package(ZLIB REQUIRED)

# [8] Link libraries
target_link_libraries(logsummarizer PRIVATE
    CURL::libcurl
    Jsoncpp::Jsoncpp
    ZLIB::ZLIB
)

# [9] Basic installation (optional)
install(TARGETS logsummarizer
    RUNTIME DESTINATION bin
    ARCHIVE DESTINATION lib
)

# [10] Optional: Add tests if needed
option(BUILD_TESTS "Build test cases" OFF)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()