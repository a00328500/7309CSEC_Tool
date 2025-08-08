# 7309CSEC_Tool
# Cybersecurity Log Analyzer

A tool for analyzing system logs with the help of a local LLM via OLLAMA to identify and summarize potential security threats.

## Features

- Parses system logs and identifies security-relevant events
- Counts different types of events (logins, errors, warnings, etc.)
- Uses OLLAMA with a local LLM (default: llama3) to analyze potential threats
- Generates comprehensive security reports

## Requirements

- C++17 compatible compiler
- CMake (version 3.10 or higher)
- libcurl
- OLLAMA installed and running locally (default: http://localhost:11434)
- An LLM model downloaded in OLLAMA (e.g., `ollama pull llama3`)
- zlib

- Cmake, libcurl, zlib, must be installed in the same directory C:/dev/vcpkg

## How to build
1. mkdir build
2. cd build
3. cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE="C:\dev\vcpkg\scripts\buildsystems\vcpkg.cmake"
4. cmake --build . --config Release

## How to run
1. Make sure you are in the path ~\7309CSEC_Tool\build\Release
2. Run the following: ./logsummarizer "path where the log file is saved" --output "title".txt