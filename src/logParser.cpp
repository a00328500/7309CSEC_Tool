#include "logParser.h"
#include <fstream>
#include <regex>
#include <stdexcept>
#include <sstream>

using namespace std;

LogParser::LogParser() : currentType(LogType::UNKNOWN) {}

LogParser::~LogParser() {}

bool LogParser::loadLogFile(const string& filePath) {
    ifstream file(filePath);
    if (!file.is_open()) {
        throw runtime_error("Failed to open log file: " + filePath);
    }

    logContent.assign((istreambuf_iterator<char>(file)), 
                   istreambuf_iterator<char>());
    
    currentType = detectLogType();
    return !logContent.empty();
}

LogType LogParser::detectLogType() {
    if (isWindowsEventLog(logContent)) {
        return LogType::WINDOWS_EVENT;
    }
    
    const regex syslogPattern(R"(^[A-Za-z]{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}\s\S+)");
    if (regex_search(logContent, syslogPattern)) {
        return LogType::SYSLOG;
    }
    
    return LogType::UNKNOWN;
}

vector<LogEntry> LogParser::parseSyslog() {
    vector<LogEntry> entries;
    istringstream logStream(logContent);
    string line;
    
    while (getline(logStream, line)) {
        if (line.empty()) continue;
        
        vector<string> parts = splitSyslogLine(line);
        if (parts.size() < 4) continue;
        
        LogEntry entry;
        entry.timestamp = parts[0] + " " + parts[1];
        entry.source = parts[2];
        entry.message = parts[3];
        
        const regex severityRegex(R"(priority=(\d+))");
        smatch matches;
        if (regex_search(entry.message, matches, severityRegex)) {
            entry.severity = stoi(matches[1].str());
        } else {
            entry.severity = 3;
        }
        
        extractSyslogDetails(entry);
        entries.push_back(entry);
    }
    
    return entries;
}

vector<string> LogParser::splitSyslogLine(const string& line) {
    vector<string> parts;
    size_t timestampEnd = line.find(' ', line.find(' ') + 1);
    size_t hostEnd = line.find(' ', timestampEnd + 1);
    size_t processEnd = line.find(':', hostEnd + 1);
    
    if (timestampEnd == string::npos || 
        hostEnd == string::npos || 
        processEnd == string::npos) {
        return parts;
    }
    
    parts.push_back(line.substr(0, timestampEnd));
    parts.push_back(line.substr(timestampEnd + 1, hostEnd - timestampEnd - 1));
    parts.push_back(line.substr(hostEnd + 1, processEnd - hostEnd - 1));
    parts.push_back(line.substr(processEnd + 2));
    
    return parts;
}

void LogParser::extractSyslogDetails(LogEntry& entry) {
    const regex ipRegex(R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)");
    smatch matches;
    if (regex_search(entry.message, matches, ipRegex)) {
        entry.details["source_ip"] = matches[0].str();
    }
    
    const regex userRegex(R"((?:user|username)=([^\s]+))");
    if (regex_search(entry.message, matches, userRegex)) {
        entry.details["user"] = matches[1].str();
    }
    
    const regex pidRegex(R"(\[(\d+)\])");
    if (regex_search(entry.source, matches, pidRegex)) {
        entry.details["pid"] = matches[1].str();
    }
}

vector<LogEntry> LogParser::parseWindowsEvents() {
    vector<LogEntry> entries;
    istringstream logStream(logContent);
    string line;
    
    while (getline(logStream, line)) {
        if (line.empty()) continue;
        
        LogEntry entry;
        size_t timeStart = line.find("<TimeCreated SystemTime=\"");
        size_t sourceStart = line.find("<Provider Name=\"");
        size_t messageStart = line.find("<Message>");
        
        if (timeStart != string::npos && sourceStart != string::npos && messageStart != string::npos) {
            entry.timestamp = line.substr(timeStart + 24, 19);
            entry.source = line.substr(sourceStart + 16, 
                                    line.find("\"", sourceStart + 16) - (sourceStart + 16));
            entry.message = line.substr(messageStart + 9, 
                                     line.find("</Message>") - (messageStart + 9));
            
            size_t idStart = line.find("<EventID>");
            if (idStart != string::npos) {
                string idStr = line.substr(idStart + 9, 
                                         line.find("</EventID>") - (idStart + 9));
                entry.severity = estimateWindowsEventSeverity(stoi(idStr));
            }
            
            entries.push_back(entry);
        }
    }
    
    return entries;
}

bool LogParser::isWindowsEventLog(const string& content) {
    return content.find("<Event xmlns=") != string::npos || 
           content.find("<Events>") != string::npos;
}

int LogParser::estimateWindowsEventSeverity(int eventId) {
    switch (eventId) {
        case 4625: return 4; // Failed login
        case 4648: return 5; // Explicit credential
        case 4672: return 4; // Special privileges
        case 6005: return 2; // Event log started
        case 6006: return 2; // Event log stopped
        default: return 3;   // Unknown event
    }
}