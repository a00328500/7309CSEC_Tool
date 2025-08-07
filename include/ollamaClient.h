#ifndef OLLAMA_CLIENT_H
#define OLLAMA_CLIENT_H

#include <string>
#include <curl/curl.h>

class OllamaClient {
public:
    OllamaClient(const std::string& baseUrl = "http://localhost:11434");
    ~OllamaClient();
    
    std::string generateSummary(const std::string& prompt, const std::string& model = "llama3");
    std::string analyzeThreats(const std::vector<std::string>& threats, const std::string& model = "llama3");
    
private:
    std::string baseUrl;
    CURL* curl;
    
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* output);
    std::string sendRequest(const std::string& endpoint, const std::string& jsonData);
    std::string buildPrompt(const std::vector<std::string>& threats);
};

#endif // OLLAMA_CLIENT_H