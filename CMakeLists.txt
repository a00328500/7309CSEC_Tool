cmake_minimum_required(VERSION 3.10)
project(LogSummarizer)

set(CMAKE_CXX_STANDARD 17)

find_package(CURL REQUIRED)
find_package(JSONCPP REQUIRED)

include_directories(
    include
    ${CURL_INCLUDE_DIRS}
    ${JSONCPP_INCLUDE_DIRS}
)

add_executable(log_summarizer
    src/main.cpp
    src/log_parser.cpp
    src/ollama_client.cpp
    src/security_analyzer.cpp
    src/summarizer.cpp
)

target_link_libraries(log_summarizer
    ${CURL_LIBRARIES}
    ${JSONCPP_LIBRARIES}
)