#include "logParser.h"
#include <regex>
#include <iostream>
#include <algorithm>

LogParser::LogParser() {
    std::cout << "LogParser initialized\n";
}

LogParser::~LogParser() {}

std::vector<LogEvent> LogParser::parseSyslog(const std::string& filePath) {
    std::vector<LogEvent> events;
    std::ifstream file(filePath);
    std::string line;
    
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open log file: " + filePath);
    }
    
    std::cout << "Parsing syslog file: " << filePath << "\n";
    
    // Updated regex pattern for better matching
    std::regex syslogRegex(R"((\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s(\S+)\s(\S+?)(?:\[\d+\])?:\s(.*))");
    size_t lineCount = 0;
    size_t parsedCount = 0;
    
    while (std::getline(file, line)) {
        lineCount++;
        
        // Skip empty lines
        if (line.empty()) continue;
        
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
            parsedCount++;
            
            // Debug output for first few lines
            if (parsedCount <= 3) {
                std::cout << "Sample parsed event [" << parsedCount << "]: "
                          << event.timestamp << " " << event.host << " " 
                          << event.service << ": " << event.message << "\n";
            }
        } else {
            std::cerr << "Warning: Line " << lineCount << " didn't match syslog format\n";
            std::cerr << "Line content: " << line << "\n";
        }
        
        // Progress reporting
        if (lineCount % 1000 == 0) {
            std::cout << "Processed " << lineCount << " lines (" << parsedCount << " parsed)\n";
        }
    }
    
    std::cout << "Finished parsing. Total lines: " << lineCount 
              << ", successfully parsed: " << parsedCount << "\n";
    
    return events;
}

std::vector<LogEvent> LogParser::parseWindowsEventLog(const std::string& filePath) {
    // Implementation would use libevtx in a real project
    std::vector<LogEvent> events;
    std::cout << "Windows Event Log parsing not implemented\n";
    return events;
}

bool LogParser::isSecurityRelevant(const std::string& message) {
    std::vector<std::string> securityKeywords = {
        "fail", "password", "login", "attack", "malware", "invalid",
        "intrusion", "breach", "unauthorized", "root", "admin",
        "privilege", "escalation", "injection", "xss", "sql",
        "brute force", "ddos", "exploit", "su", "auth", "preauth",
        "denied", "alert", "warning", "critical", "error"
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
    std::regex idRegex(R"(event[ _-]?id[ _-]?(\d+))", std::regex_constants::icase);
    std::smatch matches;
    
    if (std::regex_search(message, matches, idRegex)) {
        return std::stoi(matches[1].str());
    }
    
    return -1;
}