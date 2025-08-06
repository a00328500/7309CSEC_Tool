#ifndef REPORT_GENERATOR_H
#define REPORT_GENERATOR_H

#include <string>
#include <vector>

class ReportGenerator {
public:
    void outputTextReport(const std::string& summary, const std::string& outputPath = "");
    void outputJsonReport(const std::string& summary, const std::string& outputPath = "");
    void outputConsoleReport(const std::string& summary);
    
private:
    std::string formatTextReport(const std::string& summary);
    std::string formatJsonReport(const std::string& summary);
};

#endif // REPORT_GENERATOR_H