#include <arpa/inet.h>
#include <cctype>
#include <cstring>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

using namespace std;

struct Case { string name, method, url, body; bool expectBlocked; };

static string lower(string value) {
    for (size_t i = 0; i < value.size(); ++i) value[i] = static_cast<char>(tolower(static_cast<unsigned char>(value[i])));
    return value;
}

static string encodeQuery(const string& text) {
    ostringstream out;
    out << hex;
    for (size_t i = 0; i < text.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(text[i]);
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') out << static_cast<char>(c);
        else out << '%' << uppercase << (c < 16 ? "0" : "") << static_cast<int>(c) << nouppercase;
    }
    return out.str();
}

static bool sendAll(int fd, const string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t count = send(fd, data.data() + sent, data.size() - sent, 0);
        if (count <= 0) return false;
        sent += static_cast<size_t>(count);
    }
    return true;
}

static string sendRequest(const Case& test, int port, map<string, string>& headers,
                          string& status, string& body) {
    int socketFd = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFd < 0) { cerr << "Cannot create socket: " << strerror(errno) << endl; return ""; }
    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (connect(socketFd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        cerr << "Cannot connect to C++ WAF at 127.0.0.1:" << port << ": " << strerror(errno) << endl;
        close(socketFd); return "";
    }
    ostringstream request;
    request << test.method << ' ' << test.url << " HTTP/1.1\r\n"
            << "Host: demo.local\r\nUser-Agent: Cpp-WAF-Test-Client/1.0\r\n"
            << "Content-Type: " << (test.body.empty() ? "text/plain" : "application/json") << "\r\n"
            << "Content-Length: " << test.body.size() << "\r\nConnection: close\r\n\r\n"
            << test.body;
    if (!sendAll(socketFd, request.str())) { close(socketFd); return ""; }
    shutdown(socketFd, SHUT_WR);
    string result;
    char buffer[4096];
    ssize_t count;
    while ((count = recv(socketFd, buffer, sizeof(buffer), 0)) > 0)
        result.append(buffer, static_cast<size_t>(count));
    close(socketFd);

    size_t separator = result.find("\r\n\r\n");
    string headerBlock = separator == string::npos ? result : result.substr(0, separator);
    body = separator == string::npos ? "" : result.substr(separator + 4);
    istringstream lines(headerBlock);
    getline(lines, status);
    if (!status.empty() && status.back() == '\r') status.pop_back();
    string line;
    while (getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t colon = line.find(':');
        if (colon != string::npos) {
            string key = lower(line.substr(0, colon));
            size_t start = line.find_first_not_of(" \t", colon + 1);
            headers[key] = start == string::npos ? "" : line.substr(start);
        }
    }
    return result;
}

static bool runCase(const Case& test, int port) {
    map<string, string> headers;
    string status, body;
    string raw = sendRequest(test, port, headers, status, body);
    if (raw.empty()) return false;
    const string decision = headers["x-waf-decision"];
    const bool blocked = lower(decision) == "blocked";
    const bool backendReceived = lower(headers["x-waf-backend-received"]) == "yes";
    const bool passed = blocked == test.expectBlocked && backendReceived == !test.expectBlocked;
    cout << "\n=== " << test.name << " ===\n"
         << "Request method and URL: " << test.method << ' ' << test.url << "\n"
         << "Request payload: " << (test.body.empty() ? "(empty)" : test.body) << "\n"
         << "WAF decision: " << (decision.empty() ? "UNKNOWN" : decision) << "\n"
         << "Detected attack category: " << (headers.count("x-waf-attack-category") ? headers["x-waf-attack-category"] : "none") << "\n"
         << "Matched security rule: " << (headers.count("x-waf-matched-rule") ? headers["x-waf-matched-rule"] : "none") << "\n"
         << "HTTP response status: " << status << "\n"
         << "Backend received request: " << (backendReceived ? "yes" : "no") << "\n"
         << "Request ID: " << (headers.count("x-waf-request-id") ? headers["x-waf-request-id"] : "missing") << "\n"
         << "Timestamp: " << (headers.count("x-waf-timestamp") ? headers["x-waf-timestamp"] : "missing") << "\n"
         << "Response body: " << body << "\n"
         << "Test result: " << (passed ? "PASS" : "FAIL") << " (" << (test.expectBlocked ? "expected BLOCK" : "expected ALLOW") << ")\n";
    return passed;
}

int main(int argc, char** argv) {
    int port = 8081;
    if (argc > 2) port = atoi(argv[2]);
    else if (argc > 1 && string(argv[1]) != "--suite") port = atoi(argv[1]);

    if (argc > 1 && string(argv[1]) == "--suite") {
        vector<Case> cases = {
            {"Test 1: Home page", "GET", "/", "", false},
            {"Test 2: Fetch products", "GET", "/api/products", "", false},
            {"Test 3: Search products", "GET", "/api/products?category=books", "", false},
            {"Test 4: Normal JSON request", "POST", "/api/products/search", "{\"query\":\"laptop\"}", false},
            {"Test 5: SQL injection", "GET", "/api/login?username=%27%20OR%201%3D1--", "", true},
            {"Test 6: XSS", "GET", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "", true},
            {"Test 7: Directory traversal", "GET", "/files/../../etc/passwd", "", true},
            {"Test 8: SQL comment", "GET", "/api/products?id=10%27%3B--", "", true},
        };
        unsigned int passed = 0;
        for (size_t i = 0; i < cases.size(); ++i) if (runCase(cases[i], port)) ++passed;
        cout << "\nSuite summary: " << passed << '/' << cases.size() << " passed.\n";
        return passed == cases.size() ? 0 : 1;
    }

    cout << "C++ WAF test client (port " << port << ")\n";
    string method, url, body;
    cout << "Method [GET]: "; getline(cin, method); if (method.empty()) method = "GET";
    cout << "URL path and query [/]: "; getline(cin, url); if (url.empty()) url = "/";
    // If attack text was entered in the method prompt, send it as a URL value so WAF can inspect it.
    if (method != "GET" && method != "POST" && method != "PUT" && method != "DELETE") {
        url = "/search?q=" + encodeQuery(method);
        method = "GET";
        cout << "Input treated as a query value and sent through the WAF.\n";
    }
    if (method == "POST" || method == "PUT") { cout << "Body (optional): "; getline(cin, body); }
    Case request = {"Interactive request", method, url, body, false};
    map<string, string> headers;
    string status, responseBody;
    string raw = sendRequest(request, port, headers, status, responseBody);
    if (raw.empty()) return 1;
    cout << "\nRequest sent to C++ WAF\n"
         << "WAF decision: " << (headers.count("x-waf-decision") ? headers["x-waf-decision"] : "UNKNOWN") << "\n"
         << "HTTP response status: " << status << "\n"
         << "Attack category: " << (headers.count("x-waf-attack-category") ? headers["x-waf-attack-category"] : "none") << "\n"
         << "Matched rule: " << (headers.count("x-waf-matched-rule") ? headers["x-waf-matched-rule"] : "none") << "\n"
         << "Backend received: " << (headers.count("x-waf-backend-received") ? headers["x-waf-backend-received"] : "unknown") << "\n"
         << "Request ID: " << (headers.count("x-waf-request-id") ? headers["x-waf-request-id"] : "missing") << "\n"
         << "Timestamp: " << (headers.count("x-waf-timestamp") ? headers["x-waf-timestamp"] : "missing") << "\n"
         << "Response body: " << responseBody << endl;
    return 0;
}
