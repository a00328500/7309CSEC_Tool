#ifndef SECURITY_ANALYZER_H
#define SECURITY_ANALYZER_H

#include <string>
#include <vector>
#include <memory>
#include "OllamaClient.h"
#include "LogParser.h"

class SecurityAnalyzer {
public:
    SecurityAnalyzer(std::unique_ptr<LogParser> parser, std::unique_ptr<OllamaClient> client);
    
    void analyze();
    void generateReport(const std::string& outputPath);
    
private:
    std::unique_ptr<LogParser> logParser;
    std::unique_ptr<OllamaClient> ollamaClient;
    std::string analysisResult;
    
    void performInitialAnalysis();
    void getLLMAnalysis();
};

#endif // SECURITY_ANALYZER_H