#ifndef SUMMARIZER_H
#define SUMMARIZER_H

#include <string>
#include <vector>
#include "securityAnalyzer.h"

class Summarizer {
public:
    Summarizer(OllamaClient& ollama);
    std::string generateReport(const std::vector<SecurityAnalyzer::SecurityEvent>& events);

private:
    OllamaClient& ollamaClient;

    std::string formatEventsForPrompt(const std::vector<SecurityAnalyzer::SecurityEvent>& events);
};

#endif // SUMMARIZER_H