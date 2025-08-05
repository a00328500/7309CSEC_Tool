#ifndef SECURITY_ANALYZER_H
#define SECURITY_ANALYZER_H

#include <vector>
#include "logParser.h"

class SecurityAnalyzer {
public:
    struct SecurityEvent {
        std::string type;
        std::string description;
        int severity;
        std::string recommendation;
    };

    std::vector<SecurityEvent> analyze(const std::vector<LogEntry>& entries);

private:
    SecurityEvent detectFailedLogin(const LogEntry& entry);
    SecurityEvent detectPrivilegeEscalation(const LogEntry& entry);
    SecurityEvent detectBruteForce(const std::vector<LogEntry>& entries, size_t& index);
    SecurityEvent detectSuspiciousActivity(const LogEntry& entry);
};

#endif // SECURITY_ANALYZER_H