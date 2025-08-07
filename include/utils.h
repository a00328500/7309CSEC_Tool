#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>

namespace utils {
    std::vector<std::string> splitString(const std::string& input, char delimiter);
    std::string trim(const std::string& str);
    bool isPotentialThreat(const std::string& logEntry);
    void writeToFile(const std::string& filename, const std::string& content);
    std::string getCurrentTimestamp();
}

#endif // UTILS_H