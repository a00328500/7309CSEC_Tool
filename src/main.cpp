#include <iostream>
#include <memory>
#include <string>
#include "LogParser.h"
#include "OllamaClient.h"
#include "SecurityAnalyzer.h"
#include "utils.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <log_file_path> [output_report_path]" << std::endl;
        return 1;
    }
    
    std::string logFilePath = argv[1];
    std::string outputPath = (argc > 2) ? argv[2] : "security_report.txt";
    
    try {
        // Initialize components
        auto parser = std::make_unique<LogParser>(logFilePath);
        auto client = std::make_unique<OllamaClient>();
        SecurityAnalyzer analyzer(std::move(parser), std::move(client));
        
        // Perform analysis
        analyzer.analyze();
        
        // Generate report
        analyzer.generateReport(outputPath);
        
        std::cout << "Analysis completed successfully." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}