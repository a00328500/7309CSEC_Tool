#include "reportGenerator.h"
#include <fstream>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <json/json.h>

void ReportGenerator::outputTextReport(const std::string& summary, const std::string& outputPath) {
    std::string formatted = formatTextReport(summary);
    
    if (outputPath.empty()) {
        outputConsoleReport(formatted);
    } else {
        std::ofstream outFile(outputPath);
        if (!outFile.is_open()) {
            throw std::runtime_error("Failed to open output file: " + outputPath);
        }
        outFile << formatted;
        outFile.close();
    }
}

void ReportGenerator::outputJsonReport(const std::string& summary, const std::string& outputPath) {
    std::string formatted = formatJsonReport(summary);
    
    if (outputPath.empty()) {
        outputConsoleReport(formatted);
    } else {
        std::ofstream outFile(outputPath);
        if (!outFile.is_open()) {
            throw std::runtime_error("Failed to open output file: " + outputPath);
        }
        outFile << formatted;
        outFile.close();
    }
}

void ReportGenerator::outputConsoleReport(const std::string& summary) {
    std::cout << summary << std::endl;
}

std::string ReportGenerator::formatTextReport(const std::string& summary) {
    std::time_t now = std::time(nullptr);
    std::tm tm = *std::localtime(&now);
    std::ostringstream oss;
    
    oss << "========================================\n";
    oss << " SECURITY LOG SUMMARY REPORT\n";
    oss << " Generated on: " << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "\n";
    oss << "========================================\n\n";
    oss << summary << "\n";
    oss << "========================================\n";
    oss << " END OF REPORT\n";
    oss << "========================================\n";
    
    return oss.str();
}

std::string ReportGenerator::formatJsonReport(const std::string& summary) {
    Json::Value root;
    std::time_t now = std::time(nullptr);
    
    root["report_type"] = "security_log_summary";
    root["generation_date"] = static_cast<Json::Int64>(now);
    root["content"] = summary;
    
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "  ";
    return Json::writeString(builder, root);
}