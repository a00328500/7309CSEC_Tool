#include "../include/utils.h"
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <fstream>

namespace utils {
    std::vector<std::string> splitString(const std::string& input, char delimiter) {
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream tokenStream(input);
        
        while (std::getline(tokenStream, token, delimiter)) {
            tokens.push_back(trim(token));
        }
        
        return tokens;
    }

    std::string trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\n\r");
        if (std::string::npos == first) {
            return "";
        }
        size_t last = str.find_last_not_of(" \t\n\r");
        return str.substr(first, (last - first + 1));
    }

    bool isPotentialThreat(const std::string& logEntry) {
        // Simple heuristic to identify potentially threatening log entries
        std::string lowerEntry = logEntry;
        std::transform(lowerEntry.begin(), lowerEntry.end(), lowerEntry.begin(), ::tolower);
        
        const std::vector<std::string> threatKeywords = {
            "fail", "error", "attack", "intrusion", "breach",
            "malware", "virus", "exploit", "unauthorized", "privilege",
            "escalation", "root", "admin", "password", "brute force",
            "injection", "xss", "sql", "ddos", "phishing"
        };
        
        for (const auto& keyword : threatKeywords) {
            if (lowerEntry.find(keyword) != std::string::npos) {
                return true;
            }
        }
        
        return false;
    }

    void writeToFile(const std::string& filename, const std::string& content) {
        std::ofstream outFile(filename, std::ios::app);
        if (outFile.is_open()) {
            outFile << content << "\n";
            outFile.close();
        }
    }

    std::string getCurrentTimestamp() {
        auto now = std::time(nullptr);
        auto tm = *std::localtime(&now);
        
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }
}