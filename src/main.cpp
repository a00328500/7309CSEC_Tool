#include <iostream>
#include <string>
#include <algorithm>
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
        std::cout << "Initializing components...\n";
        LogParser parser;
        OllamaClient ollama;
        ReportGenerator reporter;
        
        // Process logs
        std::cout << "Attempting to parse log file: " << logFile << "\n";
        std::vector<LogEvent> events = parser.parseSyslog(logFile);
        
        std::cout << "Successfully parsed " << events.size() << " log events\n";
        if (!events.empty()) {
            size_t securityEvents = std::count_if(events.begin(), events.end(), 
                [](const LogEvent& e) { return e.isSecurityRelevant; });
            std::cout << securityEvents << " security-relevant events found\n";
        }
        
        // Generate summary
        std::cout << "Generating summary...\n";
        std::string summary = ollama.generateSummary(events);
        
        // Generate output
        std::cout << "Creating report...\n";
        if (format == "json") {
            reporter.outputJsonReport(summary, outputFile);
        } else {
            reporter.outputTextReport(summary, outputFile);
        }
        
        std::cout << "Report generation complete!\n";
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}