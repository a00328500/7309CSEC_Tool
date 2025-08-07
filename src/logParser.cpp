#include "../include/LogParser.h"
#include "../include/utils.h"
#include <fstream>
#include <algorithm>

LogParser::LogParser(const std::string& logFilePath) : logFilePath(logFilePath) {}

void LogParser::parse() {
    std::ifstream logFile(logFilePath);
    if (!logFile.is_open()) {
        throw std::runtime_error("Failed to open log file: " + logFilePath);
    }
    
    std::string line;
    while (std::getline(logFile, line)) {
        analyzeLogEntry(line);
        countEventTypes(line);
    }
    
    logFile.close();
}

void LogParser::analyzeLogEntry(const std::string& entry) {
    if (utils::isPotentialThreat(entry)) {
        securityRelevantLogs.push_back(entry);
    }
}

void LogParser::countEventTypes(const std::string& entry) {
    // Simple event type counting - in a real implementation, this would be more sophisticated
    if (entry.find("login") != std::string::npos) {
        eventCounts["login"]++;
    } else if (entry.find("failed") != std::string::npos) {
        eventCounts["failed_attempt"]++;
    } else if (entry.find("error") != std::string::npos) {
        eventCounts["error"]++;
    } else if (entry.find("warning") != std::string::npos) {
        eventCounts["warning"]++;
    } else {
        eventCounts["other"]++;
    }
}

std::vector<std::string> LogParser::getSecurityRelevantLogs() const {
    return securityRelevantLogs;
}

std::map<std::string, int> LogParser::getEventCounts() const {
    return eventCounts;
}

std::string LogParser::getLogSummary() const {
    std::string summary = "Log Analysis Summary:\n";
    summary += "Total security-relevant events: " + std::to_string(securityRelevantLogs.size()) + "\n";
    
    for (const auto& [event, count] : eventCounts) {
        summary += event + ": " + std::to_string(count) + "\n";
    }
    
    return summary;
}