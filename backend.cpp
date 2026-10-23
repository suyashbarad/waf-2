#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

static bool sendAll(int fd, const string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t count = send(fd, data.data() + sent, data.size() - sent, 0);
        if (count <= 0) return false;
        sent += static_cast<size_t>(count);
    }
    return true;
}

int main(int argc, char** argv) {
    const int port = argc > 1 ? atoi(argv[1]) : 9091;
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) { cerr << "Socket creation failed: " << strerror(errno) << endl; return 1; }
    int opt = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (::bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0 || listen(server, 32) < 0) {
        cerr << "Cannot listen on 127.0.0.1:" << port << ": " << strerror(errno) << endl;
        close(server); return 1;
    }
    cout << "Backend listening on 127.0.0.1:" << port << endl;

    unsigned long long requestCount = 0;
    while (true) {
        int client = accept(server, NULL, NULL);
        if (client < 0) { if (errno == EINTR) continue; cerr << "Accept failed: " << strerror(errno) << endl; continue; }
        string request;
        char buffer[4096];
        ssize_t received;
        while ((received = recv(client, buffer, sizeof(buffer), 0)) > 0)
            request.append(buffer, static_cast<size_t>(received));
        if (!request.empty()) {
            ++requestCount;
            istringstream firstLine(request);
            string requestLine;
            getline(firstLine, requestLine);
            if (!requestLine.empty() && requestLine.back() == '\r') requestLine.pop_back();
            cout << "Backend received request #" << requestCount << ": " << requestLine << endl;
            const string body = "Request sent to backend successfully. Backend request count: " + to_string(requestCount);
            ostringstream output;
            output << "HTTP/1.1 200 OK\r\n"
                   << "Content-Type: text/plain; charset=utf-8\r\n"
                   << "Content-Length: " << body.size() << "\r\n"
                   << "Connection: close\r\n\r\n" << body;
            sendAll(client, output.str());
        }
        close(client);
    }
    close(server);
    return 0;
}
