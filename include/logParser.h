#ifndef LOG_PARSER_H
#define LOG_PARSER_H

#include <string>
#include <vector>
#include <map>

enum class LogType {
    SYSLOG,
    WINDOWS_EVENT,
    UNKNOWN
};

struct LogEntry {
    std::string timestamp;
    std::string source;
    std::string message;
    std::map<std::string, std::string> details;
    int severity;
};

class LogParser {
public:
    LogParser();
    ~LogParser();

    bool loadLogFile(const std::string& filePath);
    LogType detectLogType();
    std::vector<LogEntry> parseSyslog();
    std::vector<LogEntry> parseWindowsEvents();
    
private:
    std::string logContent;
    LogType currentType;

    std::vector<std::string> splitSyslogLine(const std::string& line);
    bool isWindowsEventLog(const std::string& content);
};

#endif // LOG_PARSER_H