# ==============================================
# Cybersecurity Log Summarizer - CMake Configuration
# ==============================================

cmake_minimum_required(VERSION 3.12)
project(CyberLogSummarizer VERSION 1.0.0 LANGUAGES CXX)

# [1] Compiler settings
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# [2] Source files
set(SOURCES
    src/main.cpp
    src/logParser.cpp
    src/ollamaClient.cpp
    src/reportGenerator.cpp
)

# [3] Header files
set(HEADERS
    include/logParser.h
    include/ollamaClient.h
    include/reportGenerator.h
)

# [4] Create executable
add_executable(logsummarizer ${SOURCES} ${HEADERS})

# [5] Include directories
target_include_directories(logsummarizer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# [6] Dependency Configuration ========================================

# --- ZLIB ---
find_package(ZLIB REQUIRED)

# --- CURL ---
find_package(CURL REQUIRED)

# --- JsonCpp (Updated Step 3) ---
find_package(Jsoncpp REQUIRED)

# Handle different JsonCpp target names
if(TARGET Jsoncpp::Jsoncpp)
    set(JSONCPP_TARGET Jsoncpp::Jsoncpp)
elseif(TARGET jsoncpp_lib)
    set(JSONCPP_TARGET jsoncpp_lib)
elseif(TARGET JsonCpp::JsonCpp)
    set(JSONCPP_TARGET JsonCpp::JsonCpp)
else()
    message(FATAL_ERROR "JsonCpp package found but no valid target detected")
endif()

message(STATUS "Using JsonCpp target: ${JSONCPP_TARGET}")

# [7] Link libraries
target_link_libraries(logsummarizer PRIVATE
    CURL::libcurl
    ${JSONCPP_TARGET}  # Uses the detected target name
    ZLIB::ZLIB
)