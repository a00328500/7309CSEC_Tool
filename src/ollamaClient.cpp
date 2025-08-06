#include "ollamaClient.h"
#include <json/json.h>  // Now properly installed via vcpkg
#include <iostream>
#include <sstream>
#include <stdexcept>

OllamaClient::OllamaClient(const std::string& baseUrl) : baseUrl(baseUrl) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }
}

OllamaClient::~OllamaClient() {
    if (curl) {
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
}

std::string OllamaClient::generateSummary(const std::string& prompt, const std::string& model) {
    Json::Value root;
    root["model"] = model;
    root["prompt"] = prompt;
    root["stream"] = false;
    root["options"] = Json::objectValue;  // Add empty options object

    Json::StreamWriterBuilder writer;
    writer["indentation"] = "";  // Compact JSON output
    std::string jsonData = Json::writeString(writer, root);

    std::cout << "Sending to OLLAMA: " << jsonData << std::endl;  // Debug output
    std::string response = makeRequest("/api/generate", jsonData);
    std::cout << "Received from OLLAMA: " << response << std::endl;  // Debug output

    Json::Value responseJson;
    JSONCPP_STRING errors;
    Json::CharReaderBuilder reader;

    const std::unique_ptr<Json::CharReader> jsonReader(reader.newCharReader());
    if (!jsonReader->parse(response.c_str(), response.c_str() + response.length(), &responseJson, &errors)) {
        throw std::runtime_error("Failed to parse OLLAMA response: " + errors);
    }

    if (!responseJson.isMember("response")) {
        throw std::runtime_error("Invalid OLLAMA response format");
    }

    return responseJson["response"].asString();
}

size_t OllamaClient::writeCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t newLength = size * nmemb;
    try {
        s->append(static_cast<char*>(contents), newLength);
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
    CURLcode res;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, jsonData.length());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseString);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "OllamaClient/1.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);  // 30 second timeout

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    res = curl_easy_perform(curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        std::ostringstream oss;
        oss << "CURL request failed (" << res << "): " << curl_easy_strerror(res);
        throw std::runtime_error(oss.str());
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
        throw std::runtime_error("HTTP request failed with code: " + std::to_string(http_code));
    }

    return responseString;
}