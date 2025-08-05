#include "ollamaClient.h"
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

std::string OllamaClient::generateSummary(const std::string& prompt, const std::string& model) {
    Json::Value root;
    root["model"] = model;
    root["prompt"] = prompt;
    root["stream"] = false;

    Json::StreamWriterBuilder writer;
    std::string jsonData = Json::writeString(writer, root);

    std::string response = makeRequest("/api/generate", jsonData);

    // Parse response
    Json::Value responseJson;
    Json::CharReaderBuilder reader;
    std::string errors;
    std::istringstream responseStream(response);

    if (!Json::parseFromStream(reader, responseStream, &responseJson, &errors)) {
        throw std::runtime_error("Failed to parse OLLAMA response: " + errors);
    }

    return responseJson["response"].asString();
}

size_t OllamaClient::writeCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t newLength = size * nmemb;
    try {
        s->append((char*)contents, newLength);
        return newLength;
    } catch (...) {
        return 0;
    }
}

std::string OllamaClient::makeRequest(const std::string& endpoint, const std::string& jsonData) {
    if (!curl) {
        throw std::runtime_error("CURL not initialized");
    }

    std::string url = baseUrl + endpoint;
    std::string responseString;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseString);

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        throw std::runtime_error("CURL request failed: " + std::string(curl_easy_strerror(res)));
    }

    return responseString;
}