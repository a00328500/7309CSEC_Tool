#include <iostream>
#include <fstream>
#include "logParser.h"
#include "securityAnalyzer.h"
#include "summarizer.h"
#include "ollamaClient.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <log_file_path>" << std::endl;
        return 1;
    }

    try {
        // Initialize components
        LogParser parser;
        OllamaClient ollama;
        SecurityAnalyzer analyzer;
        Summarizer summarizer(ollama);

        // Load and parse log file
        if (!parser.loadLogFile(argv[1])) {
            std::cerr << "Failed to load log file: " << argv[1] << std::endl;
            return 1;
        }

        std::vector<LogEntry> entries;
        switch (parser.detectLogType()) {
            case LogType::SYSLOG:
                entries = parser.parseSyslog();
                break;
            case LogType::WINDOWS_EVENT:
                entries = parser.parseWindowsEvents();
                break;
            default:
                std::cerr << "Unsupported log format" << std::endl;
                return 1;
        }

        // Analyze security events
        auto securityEvents = analyzer.analyze(entries);

        // Generate and display summary
        std::string report = summarizer.generateReport(securityEvents);
        std::cout << "\n=== SECURITY EVENT SUMMARY ===\n";
        std::cout << report << "\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}