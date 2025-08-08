#include "logParser.h"
#include <regex>
#include <iostream>
#include <algorithm>
#include <sstream>

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

std::vector<LogEvent> LogParser::parseCSV(const std::string& filePath) {
    std::vector<LogEvent> events;
    std::ifstream file(filePath);
    std::string line;
    
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open CSV file: " + filePath);
    }
    
    std::cout << "Parsing CSV file: " << filePath << "\n";
    
    // Read header line to determine column order
    if (!std::getline(file, line)) {
        throw std::runtime_error("CSV file is empty");
    }
    
    std::vector<std::string> headers;
    std::istringstream headerStream(line);
    std::string header;
    
    while (std::getline(headerStream, header, ',')) {
        // Trim whitespace from header
        header.erase(0, header.find_first_not_of(" \t"));
        header.erase(header.find_last_not_of(" \t") + 1);
        headers.push_back(header);
    }
    
    // Find required column indices
    int timestampIdx = -1, hostIdx = -1, serviceIdx = -1, messageIdx = -1;
    for (size_t i = 0; i < headers.size(); ++i) {
        std::string lowerHeader = headers[i];
        std::transform(lowerHeader.begin(), lowerHeader.end(), lowerHeader.begin(), ::tolower);
        
        if (lowerHeader.find("timestamp") != std::string::npos || 
            lowerHeader.find("date") != std::string::npos ||
            lowerHeader.find("time") != std::string::npos) {
            timestampIdx = i;
        }
        else if (lowerHeader.find("host") != std::string::npos || 
                lowerHeader.find("source") != std::string::npos ||
                lowerHeader.find("computer") != std::string::npos) {
            hostIdx = i;
        }
        else if (lowerHeader.find("service") != std::string::npos || 
                lowerHeader.find("application") != std::string::npos ||
                lowerHeader.find("facility") != std::string::npos) {
            serviceIdx = i;
        }
        else if (lowerHeader.find("message") != std::string::npos || 
                lowerHeader.find("description") != std::string::npos ||
                lowerHeader.find("log") != std::string::npos ||
                lowerHeader.find("event") != std::string::npos ||
                lowerHeader.find("details") != std::string::npos) {
            messageIdx = i;
        }
    }
    
    // If we still haven't found a message column, try to use the last column
    if (messageIdx == -1 && !headers.empty()) {
        std::cout << "Warning: No explicit message column found, using last column as message\n";
        messageIdx = headers.size() - 1;
    }
    
    if (messageIdx == -1) {
        std::ostringstream errorMsg;
        errorMsg << "Could not determine message column in CSV file\n";
        errorMsg << "Tried to find columns containing: 'message', 'description', 'log', 'event', or 'details'\n";
        errorMsg << "Available columns: ";
        for (const auto& h : headers) {
            errorMsg << h << ", ";
        }
        throw std::runtime_error(errorMsg.str());
    }
    
    size_t lineCount = 1; // Already read header
    size_t parsedCount = 0;
    
    while (std::getline(file, line)) {
        lineCount++;
        
        // Skip empty lines
        if (line.empty()) continue;
        
        std::vector<std::string> columns;
        std::istringstream lineStream(line);
        std::string column;
        
        while (std::getline(lineStream, column, ',')) {
            // Trim whitespace from column
            column.erase(0, column.find_first_not_of(" \t"));
            column.erase(column.find_last_not_of(" \t") + 1);
            columns.push_back(column);
        }
        
        if (columns.size() <= messageIdx) {
            std::cerr << "Warning: Line " << lineCount << " has insufficient columns (expected at least " 
                      << messageIdx + 1 << ", got " << columns.size() << ")\n";
            continue;
        }
        
        LogEvent event;
        event.timestamp = (timestampIdx != -1 && timestampIdx < (int)columns.size()) ? columns[timestampIdx] : "";
        event.host = (hostIdx != -1 && hostIdx < (int)columns.size()) ? columns[hostIdx] : "";
        event.service = (serviceIdx != -1 && serviceIdx < (int)columns.size()) ? columns[serviceIdx] : "";
        event.message = columns[messageIdx];
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
        
        // Progress reporting
        if (lineCount % 1000 == 0) {
            std::cout << "Processed " << lineCount << " lines (" << parsedCount << " parsed)\n";
        }
    }
    
    std::cout << "Finished parsing. Total lines: " << lineCount 
              << ", successfully parsed: " << parsedCount << "\n";
    
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