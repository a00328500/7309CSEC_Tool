#include "logParser.h"
#include <regex>
#include <iostream>

LogParser::LogParser() {}
LogParser::~LogParser() {}

std::vector<LogEvent> LogParser::parseSyslog(const std::string& filePath) {
    std::vector<LogEvent> events;
    std::ifstream file(filePath);
    std::string line;
    
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open log file: " + filePath);
    }
    
    std::regex syslogRegex(R"((\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s(\S+)\s(\S+):\s(.*))");
    
    while (std::getline(file, line)) {
        std::smatch matches;
        if (std::regex_match(line, matches, syslogRegex)) {
            LogEvent event;
            event.timestamp = matches[1].str();
            event.host = matches[2].str();
            event.service = matches[3].str();
            event.message = matches[4].str();
            event.eventId = extractEventId(event.message);
            event.isSecurityRelevant = isSecurityRelevant(event.message);
            
            events.push_back(event);
        }
    }
    
    return events;
}

std::vector<LogEvent> LogParser::parseWindowsEventLog(const std::string& filePath) {
    // Implementation would use libevtx in a real project
    std::vector<LogEvent> events;
    // Placeholder for demo purposes
    return events;
}

bool LogParser::isSecurityRelevant(const std::string& message) {
    std::vector<std::string> securityKeywords = {
        "failed", "password", "login", "attack", "malware",
        "intrusion", "breach", "unauthorized", "root", "admin",
        "privilege", "escalation", "injection", "xss", "sql",
        "brute force", "ddos", "exploit"
    };
    
    std::string lowerMsg = message;
    std::transform(lowerMsg.begin(), lowerMsg.end(), lowerMsg.begin(), ::tolower);
    
    for (const auto& keyword : securityKeywords) {
        if (lowerMsg.find(keyword) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

int LogParser::extractEventId(const std::string& message) {
    std::regex idRegex(R"(event id (\d+))", std::regex_constants::icase);
    std::smatch matches;
    
    if (std::regex_search(message, matches, idRegex)) {
        return std::stoi(matches[1].str());
    }
    
    return -1;
}