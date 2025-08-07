#include "../include/OllamaClient.h"
#include "../include/utils.h"
#include <iostream>
#include <sstream>
#include <json/json.h>

OllamaClient::OllamaClient(const std::string& baseUrl) : baseUrl(baseUrl) {
    curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }
}

OllamaClient::~OllamaClient() {
    if (curl) {
        curl_easy_cleanup(curl);
    }
}

size_t OllamaClient::writeCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t totalSize = size * nmemb;
    output->append((char*)contents, totalSize);
    return totalSize;
}

std::string OllamaClient::sendRequest(const std::string& endpoint, const std::string& jsonData) {
    if (!curl) {
        throw std::runtime_error("CURL not initialized");
    }
    
    std::string url = baseUrl + endpoint;
    std::string response;
    
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, jsonData.size());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::string error = "CURL request failed: ";
        error += curl_easy_strerror(res);
        throw std::runtime_error(error);
    }
    
    curl_slist_free_all(headers);
    
    // Parse JSON response
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errors;
    std::istringstream responseStream(response);
    
    if (!Json::parseFromStream(builder, responseStream, &root, &errors)) {
        throw std::runtime_error("Failed to parse JSON response: " + errors);
    }
    
    if (root.isMember("response")) {
        return root["response"].asString();
    }
    
    return response;
}

std::string OllamaClient::buildPrompt(const std::vector<std::string>& threats) {
    std::ostringstream prompt;
    prompt << "You are a cybersecurity analyst. Analyze the following log entries and provide:\n"
           << "1. A summary of potential security issues\n"
           << "2. Severity assessment (Low, Medium, High, Critical)\n"
           << "3. Recommended actions\n\n"
           << "Log entries:\n";
    
    for (size_t i = 0; i < threats.size(); ++i) {
        prompt << i + 1 << ". " << threats[i] << "\n";
    }
    
    return prompt.str();
}

std::string OllamaClient::generateSummary(const std::string& prompt, const std::string& model) {
    Json::Value request;
    request["model"] = model;
    request["prompt"] = prompt;
    request["stream"] = false;
    
    Json::StreamWriterBuilder writer;
    std::string jsonData = Json::writeString(writer, request);
    
    return sendRequest("/api/generate", jsonData);
}

std::string OllamaClient::analyzeThreats(const std::vector<std::string>& threats, const std::string& model) {
    std::string prompt = buildPrompt(threats);
    return generateSummary(prompt, model);
}