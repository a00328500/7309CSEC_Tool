cmake_minimum_required(VERSION 3.12)
project(CyberLogSummarizer)

# [1] Source files
set(SOURCES
    src/main.cpp
    src/logParser.cpp
    src/ollamaClient.cpp
    src/reportGenerator.cpp
)

# [2] Headers
set(HEADERS
    include/logParser.h
    include/ollamaClient.h
    include/reportGenerator.h
)

# [3] Create executable
add_executable(logsummarizer ${SOURCES} ${HEADERS})

# [4] Include directories (CRITICAL for header files)
target_include_directories(logsummarizer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# [5] Find and link dependencies
find_package(CURL REQUIRED)
find_package(jsoncpp REQUIRED)
find_package(ZLIB REQUIRED)

target_link_libraries(logsummarizer PRIVATE
    CURL::libcurl
    JsonCpp::JsonCpp
    ZLIB::ZLIB
)