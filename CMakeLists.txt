# ==============================================
# Cybersecurity Log Summarizer - CMake Configuration
# ==============================================

# [STEP 1] Set minimum CMake version and project name
cmake_minimum_required(VERSION 3.12)
project(CyberLogSummarizer VERSION 1.0.0 LANGUAGES CXX)

# [STEP 2] Configure compiler options
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
option(BUILD_TESTS "Build test cases" OFF)  # Optional test flag

# [STEP 3] Set source files (relative paths)
set(SOURCES
    src/main.cpp
    src/logParser.cpp
    src/ollamaClient.cpp
    src/reportGenerator.cpp
)

# [STEP 4] Set header files (relative paths)
set(HEADERS
    include/logParser.h
    include/ollamaClient.h
    include/reportGenerator.h
)

# [STEP 5] Create the executable target
add_executable(logsummarizer ${SOURCES} ${HEADERS})

# [STEP 6] Add include directories
target_include_directories(logsummarizer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include  # For project headers
)

# [STEP 7] Find and link dependencies
find_package(CURL REQUIRED)
find_package(Jsoncpp REQUIRED)
find_package(ZLIB REQUIRED)

target_link_libraries(logsummarizer PRIVATE
    CURL::libcurl
    Jsoncpp::Jsoncpp
    ZLIB::ZLIB
)

# [STEP 8] Install configuration (optional)
install(TARGETS logsummarizer
    RUNTIME DESTINATION bin
    ARCHIVE DESTINATION lib
)

# [STEP 9] Testing configuration (optional)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# [STEP 10] Package configuration (optional)
include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/CyberLogSummarizerConfig.cmake
    INSTALL_DESTINATION lib/cmake/CyberLogSummarizer
)