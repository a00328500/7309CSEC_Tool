#include "ollamaClient.h"
#include <curl/curl.h>
#include <json/json.h>
#include <sstream>
#include <iostream>

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t newLength = size * nmemb;
    try {
        s->append((char*)contents, newLength);
        return newLength;
    } catch(std::bad_alloc &e) {
        return 0;
    }
}

OllamaClient::OllamaClient(const std::string& baseUrl) : baseUrl(baseUrl), modelName("llama3") {}

std::string OllamaClient::generateSummary(const std::vector<LogEvent>& events) {
    std::string prompt = buildSecurityPrompt(events);
    return sendPrompt(prompt);
}

std::string OllamaClient::analyzeThreats(const std::vector<LogEvent>& events) {
    std::string prompt = "Analyze these security logs and identify potential threats:\n";
    prompt += formatEventsForPrompt(events);
    prompt += "\nProvide a detailed threat analysis with risk ratings.";
    return sendPrompt(prompt);
}

std::string OllamaClient::sendPrompt(const std::string& prompt) {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        Json::Value root;
        root["model"] = modelName;
        root["prompt"] = prompt;
        root["stream"] = false;
        
        Json::StreamWriterBuilder writer;
        std::string jsonPayload = Json::writeString(writer, root);
        
        curl_easy_setopt(curl, CURLOPT_URL, (baseUrl + "/api/generate").c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonPayload.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, jsonPayload.length());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            curl_easy_cleanup(curl);
            throw std::runtime_error("OLLAMA API request failed: " + std::string(curl_easy_strerror(res)));
        }
        
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        
        // Parse response
        Json::CharReaderBuilder jsonReader;
        std::unique_ptr<Json::CharReader> reader(jsonReader.newCharReader());
        Json::Value response;
        std::string errors;
        
        if (!reader->parse(readBuffer.c_str(), readBuffer.c_str() + readBuffer.size(), &response, &errors)) {
            throw std::runtime_error("Failed to parse OLLAMA response: " + errors);
        }
        
        return response["response"].asString();
    }
    
    throw std::runtime_error("Failed to initialize CURL");
}

std::string OllamaClient::buildSecurityPrompt(const std::vector<LogEvent>& events) {
    std::string prompt = "You are a cybersecurity analyst. Analyze these logs and provide a concise summary:\n";
    prompt += "Focus on security-relevant events, potential threats, and notable patterns.\n";
    prompt += "Format your response with these sections: Critical Findings, Suspicious Activity, Recommendations.\n\n";
    prompt += "Log Events:\n";
    prompt += formatEventsForPrompt(events);
    return prompt;
}

std::string OllamaClient::formatEventsForPrompt(const std::vector<LogEvent>& events) {
    std::ostringstream oss;
    for (const auto& event : events) {
        if (event.isSecurityRelevant) {
            oss << "[SECURITY] ";
        }
        oss << event.timestamp << " " << event.host << " " << event.service << ": " << event.message << "\n";
    }
    return oss.str();
}