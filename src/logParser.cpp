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

    // Read the entire file into a buffer
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<char> buffer(fileSize);
    file.read(buffer.data(), fileSize);
    file.close();

    // Convert buffer to string for processing
    std::string content(buffer.begin(), buffer.end());

    // Improved XML parsing for EVTX
    size_t pos = 0;
    while ((pos = content.find("<Event", pos)) != std::string::npos) {
        LogEvent event;
        event.timestamp = "N/A";
        event.host = "localhost";
        event.service = "Windows";

        // Find EventData section
        size_t dataStart = content.find("<EventData>", pos);
        size_t dataEnd = content.find("</EventData>", pos);
        
        if (dataStart != std::string::npos && dataEnd != std::string::npos && dataEnd > dataStart) {
            std::string eventData = content.substr(dataStart + 11, dataEnd - dataStart - 11);
            
            // Extract message data
            std::string message;
            size_t dataPos = 0;
            while ((dataPos = eventData.find("<Data Name=", dataPos)) != std::string::npos) {
                size_t valueStart = eventData.find('>', dataPos) + 1;
                size_t valueEnd = eventData.find("</Data>", valueStart);
                if (valueEnd != std::string::npos) {
                    message += eventData.substr(valueStart, valueEnd - valueStart) + "; ";
                    dataPos = valueEnd;
                }
            }
            
            if (!message.empty()) {
                event.message = message;
            } else {
                // Fallback to raw data if no Data tags found
                event.message = eventData;
            }
        } else {
            // Fallback to raw event if no EventData found
            size_t eventEnd = content.find("</Event>", pos);
            if (eventEnd != std::string::npos) {
                event.message = content.substr(pos, eventEnd - pos);
            }
        }

        event.eventId = extractEventId(event.message);
        event.isSecurityRelevant = isSecurityRelevant(event.message);
        
        events.push_back(event);
        pos = content.find("</Event>", pos);
        if (pos == std::string::npos) break;
        pos += 8; // length of "</Event>"
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