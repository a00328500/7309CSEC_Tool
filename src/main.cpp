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
        
        // Process logs
        std::vector<LogEvent> events = parser.parseSyslog(logFile);
        std::string summary = ollama.generateSummary(events);
        
        // Generate output
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