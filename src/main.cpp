#include <iostream>
#include <string>
#include "logParser.h"
#include "ollamaClient.h"
#include "reportGenerator.h"

void printHelp() {
    std::cout << "Log Summarizer Bot - Cybersecurity Analysis Tool\n";
    std::cout << "Usage:\n";
    std::cout << "  logsummarizer <logfile> [--output <file>] [--format <text|json>]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --output    Specify output file (default: console)\n";
    std::cout << "  --format    Output format: text or json (default: text)\n";
    std::cout << "  --help      Show this help message\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2 || std::string(argv[1]) == "--help") {
        printHelp();
        return 0;
    }
    
    try {
        std::string logFile = argv[1];
        std::string outputFile;
        std::string format = "text";
        
        // Parse command line arguments
        for (int i = 2; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "--output" && i + 1 < argc) {
                outputFile = argv[++i];
            } else if (arg == "--format" && i + 1 < argc) {
                format = argv[++i];
            }
        }
        
        // Initialize components
        LogParser parser;
        OllamaClient ollama;
        ReportGenerator reporter;
        
        // Process logs based on file type
        std::vector<LogEvent> events;
        size_t evtxPos = logFile.find(".evtx");
        size_t logPos = logFile.find(".log");
        
        if (evtxPos != std::string::npos && evtxPos == logFile.length() - 5) {
            std::cout << "Processing Windows Event Log..." << std::endl;
            events = parser.parseWindowsEventLog(logFile);
        } else if (logPos != std::string::npos && logPos == logFile.length() - 4) {
            std::cout << "Processing Syslog..." << std::endl;
            events = parser.parseSyslog(logFile);
        } else {
            // Try to auto-detect by attempting syslog first
            try {
                std::cout << "Attempting to parse as Syslog..." << std::endl;
                events = parser.parseSyslog(logFile);
            } catch (const std::exception& e) {
                std::cerr << "Syslog parsing failed: " << e.what() << std::endl;
                std::cerr << "Attempting to parse as Windows Event Log..." << std::endl;
                events = parser.parseWindowsEventLog(logFile);
            }
        }
        
        if (events.empty()) {
            std::cerr << "Warning: No events were parsed from the log file." << std::endl;
        }
        
        // Generate summary and output report
        std::string summary = ollama.generateSummary(events);
        
        if (format == "json") {
            reporter.outputJsonReport(summary, outputFile);
        } else {
            reporter.outputTextReport(summary, outputFile);
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}