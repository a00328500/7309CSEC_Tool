#ifndef OLLAMA_CLIENT_H
#define OLLAMA_CLIENT_H

#include <string>
#include <vector>
#include <curl/curl.h>

class OllamaClient {
public:
    explicit OllamaClient(const std::string& baseUrl = "http://localhost:11434");
    ~OllamaClient();

    std::string generateSummary(const std::string& prompt, const std::string& model = "llama3");
    std::string analyzeSecurityEvents(const std::vector<std::string>& events);

private:
    std::string baseUrl;
    CURL* curl;

    static size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* s);
    std::string makeRequest(const std::string& endpoint, const std::string& jsonData);
};

#endif // OLLAMA_CLIENT_H