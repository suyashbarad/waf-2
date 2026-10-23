# Local C++ WAF demo

This project sends real HTTP/1.1 requests through the C++ WAF. Allowed requests are forwarded to the local backend; blocked requests receive HTTP 403 and are never sent upstream.

## Build

```sh
g++ -std=c++11 -Wall -Wextra server.cpp -o server
g++ -std=c++11 -Wall -Wextra backend.cpp -o backend
g++ -std=c++11 -Wall -Wextra client.cpp -o client
```

## Run

Use three terminals from this directory:

```sh
./backend 9091
```

```sh
./server 8081 9091
```

```sh
./client --suite
```

The defaults avoid port 8080, which may already be used by another local server. `./client` also offers an interactive request prompt. The client reports the request ID, timestamp, decision, attack category, matched rule, HTTP status, and whether the backend received the request. The backend response includes its cumulative request count for the current backend process.

The suite contains four safe and four malicious requests. It exits successfully only when every observed WAF decision and backend-received flag matches the expected result. Logs are appended to `log.txt` and `backend.txt`.

The server and backend bind to loopback only. This is a local demonstration WAF, not a production HTTP server.
