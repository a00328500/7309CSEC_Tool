#include "../include/SecurityAnalyzer.h"
#include "../include/utils.h"
#include <iostream>

SecurityAnalyzer::SecurityAnalyzer(std::unique_ptr<LogParser> parser, std::unique_ptr<OllamaClient> client)
    : logParser(std::move(parser)), ollamaClient(std::move(client)) {}

void SecurityAnalyzer::analyze() {
    performInitialAnalysis();
    getLLMAnalysis();
}

void SecurityAnalyzer::performInitialAnalysis() {
    logParser->parse();
    analysisResult = logParser->getLogSummary();
    
    auto securityLogs = logParser->getSecurityRelevantLogs();
    if (!securityLogs.empty()) {
        analysisResult += "\nSecurity-relevant log entries:\n";
        for (const auto& log : securityLogs) {
            analysisResult += "- " + log + "\n";
        }
    }
}

void SecurityAnalyzer::getLLMAnalysis() {
    try {
        auto securityLogs = logParser->getSecurityRelevantLogs();
        if (!securityLogs.empty()) {
            std::string llmResponse = ollamaClient->analyzeThreats(securityLogs);
            analysisResult += "\nLLM Threat Analysis:\n" + llmResponse + "\n";
        }
    } catch (const std::exception& e) {
        analysisResult += "\nError getting LLM analysis: " + std::string(e.what()) + "\n";
    }
}

void SecurityAnalyzer::generateReport(const std::string& outputPath) {
    utils::writeToFile(outputPath, "=== Cybersecurity Log Analysis Report ===");
    utils::writeToFile(outputPath, "Generated at: " + utils::getCurrentTimestamp());
    utils::writeToFile(outputPath, "\n" + analysisResult);
    utils::writeToFile(outputPath, "\n=== End of Report ===");
    
    std::cout << "Report generated at: " << outputPath << std::endl;
}