#ifndef LOG_PARSER_H
#define LOG_PARSER_H

#include <string>
#include <vector>
#include <map>

class LogParser {
public:
    explicit LogParser(const std::string& logFilePath);
    ~LogParser() = default;
    
    void parse();
    std::vector<std::string> getSecurityRelevantLogs() const;
    std::map<std::string, int> getEventCounts() const;
    std::string getLogSummary() const;
    
private:
    std::string logFilePath;
    std::vector<std::string> securityRelevantLogs;
    std::map<std::string, int> eventCounts;
    
    void analyzeLogEntry(const std::string& entry);
    void countEventTypes(const std::string& entry);
};

#endif // LOG_PARSER_H