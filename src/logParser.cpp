#include "logParser.h"
#include <regex>
#include <iostream>
#include <algorithm>
#include <cctype>

LogParser::LogParser() {}
LogParser::~LogParser() {}

std::vector<LogEvent> LogParser::parseSyslog(const std::string& filePath) {
    std::vector<LogEvent> events;
    std::ifstream file(filePath);
    std::string line;
    
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open log file: " + filePath);
    }
    
    std::regex syslogRegex(R"((\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s(\S+)\s(\S+?)(?:\[\d+\])?:\s(.*))");
    
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
    std::vector<LogEvent> events;
    std::ifstream file(filePath, std::ios::binary);
    
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open Windows Event Log file: " + filePath);
    }

    std::string line;
    int lineCount = 0;
    const int maxLinesForDemo = 1000;
    
    while (std::getline(file, line) && lineCount++ < maxLinesForDemo) {
        if (line.find('\0') != std::string::npos) continue;
        
        size_t eventStart = line.find("<Event");
        if (eventStart == std::string::npos) continue;

        LogEvent event;
        event.timestamp = "N/A";
        event.host = "localhost";
        event.service = "Windows";

        size_t dataStart = line.find("<EventData>");
        size_t dataEnd = line.find("</EventData>");
        
        if (dataStart != std::string::npos && dataEnd != std::string::npos && dataEnd > dataStart) {
            event.message = line.substr(dataStart + 11, dataEnd - dataStart - 11);
            size_t tagPos;
            while ((tagPos = event.message.find('<')) != std::string::npos) {
                size_t endTag = event.message.find('>', tagPos);
                if (endTag != std::string::npos) {
                    event.message.erase(tagPos, endTag - tagPos + 1);
                }
            }
        } else {
            event.message = line.substr(eventStart);
        }

        event.eventId = extractEventId(event.message);
        event.isSecurityRelevant = isSecurityRelevant(event.message);
        
        events.push_back(event);
    }
    
    return events;
}

bool LogParser::isSecurityRelevant(const std::string& message) {
    std::vector<std::string> securityKeywords = {
        "fail", "error", "warning", "password", "login", "attack", "malware", "invalid",
        "intrusion", "breach", "unauthorized", "root", "admin", "privilege", 
        "escalation", "injection", "xss", "sql", "brute force", "ddos", "exploit",
        "su", "auth", "preauth", "audit", "firewall", "blocked", "denied", "virus",
        "trojan", "worm", "spyware", "ransomware", "phishing", "scan", "probe"
    };
    
    std::string lowerMsg = message;
    std::transform(lowerMsg.begin(), lowerMsg.end(), lowerMsg.begin(), 
                  [](unsigned char c){ return std::tolower(c); });
    
    for (const auto& keyword : securityKeywords) {
        if (lowerMsg.find(keyword) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

int LogParser::extractEventId(const std::string& message) {
    // Try Windows Event ID pattern first
    std::regex winIdRegex(R"(event(id|)\s*[:=]?\s*(\d+))", std::regex_constants::icase);
    std::smatch matches;
    
    if (std::regex_search(message, matches, winIdRegex)) {
        return std::stoi(matches[2].str());
    }
    
    // Try Syslog pattern if Windows pattern not found
    std::regex syslogIdRegex(R"(\[(\d+)\])");
    if (std::regex_search(message, matches, syslogIdRegex)) {
        return std::stoi(matches[1].str());
    }
    
    return -1;
}