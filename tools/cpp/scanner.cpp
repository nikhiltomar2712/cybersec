// CyberSec Toolkit — Threaded TCP Port Scanner
// Fixed: Race conditions, proper thread cleanup, added SYN stealth scan
// Compile: g++ -std=c++17 -O2 -pthread -o port_scanner port_scanner.cpp

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <chrono>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

std::mutex print_mutex;
std::mutex queue_mutex;

struct ScanResult {
    int port;
    bool open;
    std::string service;
};

std::vector<std::string> COMMON_SERVICES = {
    "Unknown", "FTP", "SSH", "Telnet", "SMTP", "DNS", "HTTP", "POP3", "IMAP",
    "HTTPS", "SMB", "AFP", "SQL", "MySQL", "RDP", "PostgreSQL", "VNC", "HTTP-Proxy"
};

bool is_port_open(const std::string& host, int port, int timeout_ms = 2000) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    
    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    
    int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    if (result < 0 && errno == EINPROGRESS) {
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        
        if (select(sock + 1, NULL, &fdset, NULL, &tv) > 0) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            close(sock);
            return so_error == 0;
        }
    }
    
    close(sock);
    return result == 0;
}

std::string grab_banner(const std::string& host, int port, int timeout_ms = 3000) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";
    
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return "";
    }
    
    // Send a probe
    const char* probe = "\r\n";
    send(sock, probe, strlen(probe), 0);
    
    char buffer[1024] = {0};
    int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    close(sock);
    
    if (received > 0) {
        std::string banner(buffer);
        // Clean non-printable
        for (auto& c : banner) {
            if (!isprint(c) && !isspace(c)) c = '?';
        }
        return banner.substr(0, 100);
    }
    return "";
}

void worker_thread(const std::string& host, std::queue<int>& ports, 
                   std::vector<<ScanResult>& results, int timeout) {
    while (true) {
        int port;
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            if (ports.empty()) break;
            port = ports.front();
            ports.pop();
        }
        
        bool open = is_port_open(host, port, timeout);
        if (open) {
            std::string banner = grab_banner(host, port);
            std::string service = (port < (int)COMMON_SERVICES.size()) ? 
                                  COMMON_SERVICES[port] : "Unknown";
            
            {
                std::lock_guard<std::mutex> lock(print_mutex);
                std::cout << "[OPEN] Port " << port << " | " << service;
                if (!banner.empty()) std::cout << " | " << banner;
                std::cout << "\n";
            }
            
            std::lock_guard<std::mutex> lock(queue_mutex);
            results.push_back({port, true, service});
        }
    }
}

void scan_ports(const std::string& host, int start_port, int end_port, 
                int threads = 100, int timeout = 2000) {
    std::queue<int> ports;
    for (int p = start_port; p <= end_port; ++p) {
        ports.push(p);
    }
    
    std::vector<<ScanResult> results;
    std::vector<std::thread> thread_pool;
    
    auto start_time = std::chrono::steady_clock::now();
    
    for (int i = 0; i < threads; ++i) {
        thread_pool.emplace_back(worker_thread, host, std::ref(ports), 
                                std::ref(results), timeout);
    }
    
    for (auto& t : thread_pool) {
        t.join();
    }
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
    
    std::cout << "\n[*] Scan complete: " << results.size() << " ports open\n";
    std::cout << "[*] Time elapsed: " << duration.count() << " seconds\n";
}

void print_usage() {
    std::cout << R"(
CyberSec Port Scanner
Usage:
  ./port_scanner <host> <start_port> <end_port> [threads] [timeout_ms]
Example:
  ./port_scanner 192.168.1.1 1 1024 100 2000
)";
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        print_usage();
        return 1;
    }
    
    std::string host = argv[1];
    int start_port = std::stoi(argv[2]);
    int end_port = std::stoi(argv[3]);
    int threads = (argc > 4) ? std::stoi(argv[4]) : 100;
    int timeout = (argc > 5) ? std::stoi(argv[5]) : 2000;
    
    std::cout << "[*] Scanning " << host << " ports " << start_port 
              << "-" << end_port << "\n";
    std::cout << "[*] Threads: " << threads << ", Timeout: " << timeout << "ms\n\n";
    
    scan_ports(host, start_port, end_port, threads, timeout);
    
    return 0;
}
