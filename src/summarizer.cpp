#include "summarizer.h"
#include <sstream>
#include <iomanip>
#include "ollamaClient.h"

Summarizer::Summarizer(OllamaClient& ollama) : ollamaClient(ollama) {}

std::string Summarizer::generateReport(const std::vector<SecurityAnalyzer::SecurityEvent>& events) {
    if (events.empty()) {
        return "No security events found in the logs.\n";
    }

    // Format events for LLM prompt
    std::string formattedEvents = formatEventsForPrompt(events);

    // Create prompt for LLM
    std::string prompt = R"(
You are a cybersecurity analyst assistant. Below are security events detected in system logs.
Generate a concise security report with the following sections:
1. Critical security events (severity 4-5)
2. Warning events (severity 2-3)
3. Recommendations for each finding

Format the output with clear headings and bullet points.
Focus on actionable insights for a SOC team.

Security Events:
)" + formattedEvents;

    // Get summary from LLM
    return ollamaClient.generateSummary(prompt);
}

std::string Summarizer::formatEventsForPrompt(const std::vector<SecurityAnalyzer::SecurityEvent>& events) {
    std::ostringstream oss;
    
    for (const auto& event : events) {
        oss << "Type: " << event.type << "\n"
            << "Severity: " << event.severity << "/5\n"
            << "Description: " << event.description << "\n";
        
        if (!event.recommendation.empty()) {
            oss << "Initial Recommendation: " << event.recommendation << "\n";
        }
        
        oss << "-----\n";
    }
    
    return oss.str();
}