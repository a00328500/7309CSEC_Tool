#ifndef OLLAMA_CLIENT_H
#define OLLAMA_CLIENT_H

#include <string>
#include <vector>
#include "logParser.h"

class OllamaClient {
public:
    OllamaClient(const std::string& baseUrl = "http://localhost:11434");
    
    std::string generateSummary(const std::vector<LogEvent>& events);
    std::string analyzeThreats(const std::vector<LogEvent>& events);
    
private:
    std::string baseUrl;
    std::string modelName;
    
    std::string sendPrompt(const std::string& prompt);
    std::string buildSecurityPrompt(const std::vector<LogEvent>& events);
    std::string formatEventsForPrompt(const std::vector<LogEvent>& events);
};

#endif // OLLAMA_CLIENT_H