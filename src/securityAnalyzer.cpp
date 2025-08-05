#include "securityAnalyzer.h"
#include <algorithm>
#include <regex>

using namespace std;

vector<SecurityAnalyzer::SecurityEvent> SecurityAnalyzer::analyze(const vector<LogEntry>& entries) {
    vector<SecurityEvent> events;
    
    for (size_t i = 0; i < entries.size(); i++) {
        // Check for failed logins
        if (entries[i].message.find("authentication failure") != string::npos ||
            entries[i].message.find("Failed password") != string::npos) {
            events.push_back(detectFailedLogin(entries[i]));
            
            // Check for brute force pattern
            if (i + 3 < entries.size()) {
                SecurityEvent bfEvent = detectBruteForce(entries, i);
                if (!bfEvent.type.empty()) {
                    events.push_back(bfEvent);
                    i += 3; // Skip next few entries we've already processed
                }
            }
        }
        
        // Check for privilege escalation
        if (entries[i].message.find("sudo") != string::npos && 
            entries[i].message.find("failed") != string::npos) {
            events.push_back(detectPrivilegeEscalation(entries[i]));
        }
        
        // Other suspicious activity
        SecurityEvent susEvent = detectSuspiciousActivity(entries[i]);
        if (!susEvent.type.empty()) {
            events.push_back(susEvent);
        }
    }
    
    // Sort by severity (highest first)
    sort(events.begin(), events.end(), [](const SecurityEvent& a, const SecurityEvent& b) {
        return a.severity > b.severity;
    });
    
    return events;
}

SecurityAnalyzer::SecurityEvent SecurityAnalyzer::detectFailedLogin(const LogEntry& entry) {
    SecurityEvent event;
    event.type = "Failed Login Attempt";
    event.severity = 3; // Medium severity
    
    // Extract username if available
    smatch matches;
    regex userRegex("user=([^\\s]+)");
    if (regex_search(entry.message, matches, userRegex) && matches.size() > 1) {
        event.description = "Failed login attempt for user: " + matches[1].str();
    } else {
        event.description = "Failed login attempt detected";
    }
    
    // Extract IP if available
    regex ipRegex("from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})");
    if (regex_search(entry.message, matches, ipRegex) && matches.size() > 1) {
        event.description += " from IP: " + matches[1].str();
    }
    
    event.recommendation = "Review authentication logs for this user. Check if this is a legitimate failed attempt or a brute force attack.";
    
    return event;
}

SecurityAnalyzer::SecurityEvent SecurityAnalyzer::detectBruteForce(const vector<LogEntry>& entries, size_t& index) {
    // Need at least 3 failed attempts in short succession
    if (index + 2 >= entries.size()) return SecurityEvent();
    
    // Check if next 2 entries are also failed logins
    bool isBruteForce = true;
    string commonPattern;
    
    // Simple check - in real implementation would be more sophisticated
    for (size_t i = 0; i < 3; i++) {
        if (entries[index + i].message.find("Failed password") == string::npos) {
            isBruteForce = false;
            break;
        }
    }
    
    if (isBruteForce) {
        SecurityEvent event;
        event.type = "Brute Force Attempt";
        event.severity = 5; // High severity
        
        // Extract common IP
        smatch matches;
        regex ipRegex("from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})");
        if (regex_search(entries[index].message, matches, ipRegex) && matches.size() > 1) {
            event.description = "Multiple failed login attempts from IP: " + matches[1].str();
            event.recommendation = "Immediately block this IP address in the firewall. Investigate source of the attacks.";
        } else {
            event.description = "Multiple failed login attempts detected";
            event.recommendation = "Investigate source of these attempts. Consider implementing account lockout policies.";
        }
        
        return event;
    }
    
    return SecurityEvent();
}

SecurityAnalyzer::SecurityEvent SecurityAnalyzer::detectPrivilegeEscalation(const LogEntry& entry) {
    SecurityEvent event;
    event.type = "Privilege Escalation Attempt";
    event.severity = 4; // High severity
    event.description = "Failed attempt to elevate privileges";
    
    // Extract user if available
    smatch matches;
    regex userRegex("user=([^\\s]+)");
    if (regex_search(entry.message, matches, userRegex) && matches.size() > 1) {
        event.description += " by user: " + matches[1].str();
    }
    
    event.recommendation = "Review sudoers configuration. Verify if this was a legitimate failed attempt or an attack.";
    
    return event;
}

SecurityAnalyzer::SecurityEvent SecurityAnalyzer::detectSuspiciousActivity(const LogEntry& entry) {
    // Placeholder for more detection logic
    return SecurityEvent();
}