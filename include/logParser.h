#ifndef LOG_PARSER_H
#define LOG_PARSER_H

#include <vector>
#include <string>
#include <fstream>

struct LogEvent {
    std::string timestamp;
    std::string host;
    std::string service;
    std::string message;
    int eventId;
    bool isSecurityRelevant;
};

class LogParser {
public:
    LogParser();
    ~LogParser();
    
    std::vector<LogEvent> parseSyslog(const std::string& filePath);
    std::vector<LogEvent> parseWindowsEventLog(const std::string& filePath);
    std::vector<LogEvent> parseCSV(const std::string& filePath);  // New method
    
private:
    void classifyEvent(LogEvent& event);
    bool isSecurityRelevant(const std::string& message);
    int extractEventId(const std::string& message);
};

#endif // LOG_PARSER_H