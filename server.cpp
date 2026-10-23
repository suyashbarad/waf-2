#include <arpa/inet.h>
#include <algorithm>
#include <cerrno>
#include <cctype>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <netinet/in.h>
#include <regex>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

static string lower(string value) {
    transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(tolower(c)); });
    return value;
}

static string urlDecode(const string& input) {
    string output;
    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '%' && i + 2 < input.size()) {
            char* end = NULL;
            long value = strtol(input.substr(i + 1, 2).c_str(), &end, 16);
            if (end && *end == '\0') { output += static_cast<char>(value); i += 2; continue; }
        }
        output += input[i] == '+' ? ' ' : input[i];
    }
    return output;
}

struct Detection { string category, rule; };

static Detection detectAttack(const string& input) {
    const string decoded = urlDecode(input);
    struct Pattern { const char* category; const char* rule; const char* expression; };
    static const Pattern patterns[] = {
        {"SQL injection", "SQL tautology / OR 1=1", R"((['\"]?\s*or\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+|\bor\s+1\s*=\s*1))"},
        {"SQL injection", "SQL comment / quote followed by --", R"((['\"]\s*;?\s*--|--\s*(?:$|\s)))"},
        {"SQL injection", "UNION SELECT", R"(\bunion\s+(?:all\s+)?select\b)"},
        {"SQL injection", "DROP TABLE", R"(\bdrop\s+table\b)"},
        {"Cross-site scripting (XSS)", "Script tag", R"(<\s*script\b)"},
        {"Cross-site scripting (XSS)", "JavaScript URL", R"(javascript\s*:)"},
        {"Directory traversal", "Parent directory traversal", R"((\.\.[/\\]){1,})"},
    };
    for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); ++i) {
        if (regex_search(decoded, regex(patterns[i].expression, regex_constants::icase)))
            return {patterns[i].category, patterns[i].rule};
    }

    // Keep user-maintained rules.txt active. Invalid regex entries are treated as literal text.
    ifstream rules("rules.txt");
    string rule;
    while (getline(rules, rule)) {
        while (!rule.empty() && isspace(static_cast<unsigned char>(rule.back()))) rule.pop_back();
        if (rule.empty()) continue;
        try {
            if (regex_search(decoded, regex(rule, regex_constants::icase)))
                return {"Custom rule", rule};
        } catch (const regex_error&) {
            if (lower(decoded).find(lower(rule)) != string::npos) return {"Custom rule", rule};
        }
    }
    return {"", ""};
}

static string nowText() {
    time_t now = time(NULL);
    tm* value = localtime(&now);
    char buffer[32];
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S%z", value);
    return buffer;
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

static string response(const string& status, const string& body, const string& decision,
                       const string& requestId, const string& timestamp, const string& category,
                       const string& rule, bool backendReceived) {
    ostringstream out;
    out << "HTTP/1.1 " << status << "\r\n"
        << "Content-Type: text/plain; charset=utf-8\r\n"
        << "X-WAF-Decision: " << decision << "\r\n"
        << "X-WAF-Request-ID: " << requestId << "\r\n"
        << "X-WAF-Timestamp: " << timestamp << "\r\n"
        << "X-WAF-Backend-Received: " << (backendReceived ? "yes" : "no") << "\r\n";
    if (!category.empty()) out << "X-WAF-Attack-Category: " << category << "\r\n";
    if (!rule.empty()) out << "X-WAF-Matched-Rule: " << rule << "\r\n";
    out << "Content-Length: " << body.size() << "\r\nConnection: close\r\n\r\n" << body;
    return out.str();
}

int main(int argc, char** argv) {
    const int listenPort = argc > 1 ? atoi(argv[1]) : 8081;
    const int backendPort = argc > 2 ? atoi(argv[2]) : 9091;
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) { cerr << "Socket creation failed: " << strerror(errno) << endl; return 1; }
    int opt = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(listenPort);
    if (::bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0 || listen(server, 32) < 0) {
        cerr << "Cannot listen on 127.0.0.1:" << listenPort << ": " << strerror(errno) << endl;
        close(server); return 1;
    }
    cout << "C++ WAF listening on 127.0.0.1:" << listenPort
         << "; forwarding allowed requests to 127.0.0.1:" << backendPort << endl;

    unsigned long long requestNumber = 0;
    ofstream log("log.txt", ios::app);
    ofstream audit("backend.txt", ios::app);
    while (true) {
        int client = accept(server, NULL, NULL);
        if (client < 0) { if (errno == EINTR) continue; cerr << "Accept failed: " << strerror(errno) << endl; continue; }
        string raw;
        char buffer[4096];
        ssize_t count;
        while ((count = recv(client, buffer, sizeof(buffer), 0)) > 0) {
            raw.append(buffer, static_cast<size_t>(count));
            if (raw.size() > 16384) break;
        }
        ++requestNumber;
        const string timestamp = nowText();
        ostringstream idBuilder; idBuilder << "WAF-" << time(NULL) << '-' << requestNumber;
        const string requestId = idBuilder.str();
        istringstream firstLine(raw);
        string method, target, version;
        firstLine >> method >> target >> version;
        string peer = "127.0.0.1";
        sockaddr_in peerAddress = {}; socklen_t peerLength = sizeof(peerAddress);
        if (getpeername(client, reinterpret_cast<sockaddr*>(&peerAddress), &peerLength) == 0)
            peer = inet_ntoa(peerAddress.sin_addr);

        // Scan the full request and a decoded copy so attacks in query strings and JSON bodies are caught.
        Detection detected = detectAttack(raw);
        string safeTarget = urlDecode(target);
        if (detected.category.empty() && safeTarget.find("..") != string::npos)
            detected = {"Directory traversal", "Parent directory traversal"};
        if (detected.category.empty()) {
            ifstream blacklist("blacklist.txt"); string token;
            while (getline(blacklist, token)) {
                while (!token.empty() && isspace(static_cast<unsigned char>(token.back()))) token.pop_back();
                if (!token.empty() && lower(target).find(lower(token)) != string::npos) {
                    detected = {"Blacklisted path", token}; break;
                }
            }
        }

        if (raw.empty() || raw.size() > 16384 || method.empty() || target.empty() || version != "HTTP/1.1") {
            const string body = "Request blocked. Error number: WAF-400 (invalid or oversized HTTP request).";
            sendAll(client, response("400 Bad Request", body, "BLOCKED", requestId, timestamp,
                                     "Invalid request", "HTTP/1.1 request syntax and size", false));
            log << timestamp << " id=" << requestId << " decision=BLOCKED category=Invalid request backend=no\n";
            log.flush();
            close(client); continue;
        }
        if (!detected.category.empty()) {
            const string body = "Request blocked by WAF. Error number: WAF-403. Category: " + detected.category +
                                ". Matched rule: " + detected.rule + ".";
            sendAll(client, response("403 Forbidden", body, "BLOCKED", requestId, timestamp,
                                     detected.category, detected.rule, false));
            log << timestamp << " id=" << requestId << " decision=BLOCKED category=" << detected.category
                << " rule=" << detected.rule << " backend=no request=" << target << "\n";
            log.flush();
            cout << "BLOCKED " << requestId << " " << detected.category << " (" << detected.rule << ")" << endl;
            close(client); continue;
        }

        int upstream = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in backendAddress = {};
        backendAddress.sin_family = AF_INET;
        backendAddress.sin_port = htons(backendPort);
        inet_pton(AF_INET, "127.0.0.1", &backendAddress.sin_addr);
        if (upstream < 0 || connect(upstream, reinterpret_cast<sockaddr*>(&backendAddress), sizeof(backendAddress)) < 0) {
            if (upstream >= 0) close(upstream);
            const string body = "WAF allowed the request, but the backend is unavailable. Error number: WAF-502.";
            sendAll(client, response("502 Bad Gateway", body, "ALLOWED", requestId, timestamp, "", "", false));
            log << timestamp << " id=" << requestId << " decision=ALLOWED backend=no error=backend_unavailable\n";
            log.flush();
            close(client); continue;
        }
        sendAll(upstream, raw);
        shutdown(upstream, SHUT_WR);
        string upstreamResponse;
        while ((count = recv(upstream, buffer, sizeof(buffer), 0)) > 0)
            upstreamResponse.append(buffer, static_cast<size_t>(count));
        close(upstream);

        string upstreamStatus = "200 OK", upstreamBody = upstreamResponse;
        size_t headerEnd = upstreamResponse.find("\r\n\r\n");
        if (headerEnd != string::npos) {
            size_t statusEnd = upstreamResponse.find("\r\n");
            if (statusEnd != string::npos && upstreamResponse.compare(0, 9, "HTTP/1.1 ") == 0)
                upstreamStatus = upstreamResponse.substr(9, statusEnd - 9);
            upstreamBody = upstreamResponse.substr(headerEnd + 4);
        }
        string displayBody = "WAF decision: ALLOWED. Request ID: " + requestId + ". Timestamp: " + timestamp +
                             ". Backend received: yes.\n" + upstreamBody;
        sendAll(client, response(upstreamStatus, displayBody, "ALLOWED", requestId, timestamp, "", "", true));
        log << timestamp << " id=" << requestId << " decision=ALLOWED category=none rule=none backend=yes request=" << target << "\n";
        audit << timestamp << " id=" << requestId << " method=" << method << " target=" << target << " backend_received=yes\n";
        log.flush();
        audit.flush();
        cout << "ALLOWED " << requestId << " " << method << " " << target << " backend=yes" << endl;
        close(client);
    }
    close(server);
    return 0;
}
