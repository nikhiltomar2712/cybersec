/*
 * CyberSec Toolkit — Fast TCP Port Scanner (C++)
 * ================================================
 * Uses POSIX sockets + a fixed thread pool for concurrent scanning.
 * Faster than Python for large port ranges because of less GIL overhead.
 *
 * Compile (Linux / macOS):
 *   g++ -std=c++17 -O2 -pthread -o port_scanner port_scanner.cpp
 *
 * Compile (Windows with MinGW):
 *   g++ -std=c++17 -O2 -o port_scanner.exe port_scanner.cpp -lws2_32
 *
 * Usage:
 *   ./port_scanner <target> [options]
 *   ./port_scanner 192.168.1.1
 *   ./port_scanner scanme.nmap.org --ports 1-1024
 *   ./port_scanner 10.0.0.5 --ports 1-65535 --threads 500 --timeout 1000
 *
 * Educational use only. See ETHICAL_USE.txt before use.
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Service name map
// ─────────────────────────────────────────────────────────────────────────────

static const std::map<uint16_t, std::string> SERVICES = {
    {20,"FTP-Data"},{21,"FTP"},{22,"SSH"},{23,"Telnet"},
    {25,"SMTP"},{53,"DNS"},{67,"DHCP"},{69,"TFTP"},
    {80,"HTTP"},{110,"POP3"},{111,"RPCBind"},{119,"NNTP"},
    {123,"NTP"},{135,"MSRPC"},{137,"NetBIOS"},{139,"NetBIOS-SSN"},
    {143,"IMAP"},{161,"SNMP"},{389,"LDAP"},{443,"HTTPS"},
    {445,"SMB"},{465,"SMTPS"},{514,"Syslog"},{587,"Submission"},
    {631,"IPP"},{636,"LDAPS"},{873,"Rsync"},{902,"VMware"},
    {993,"IMAPS"},{995,"POP3S"},{1080,"SOCKS5"},{1194,"OpenVPN"},
    {1433,"MSSQL"},{1521,"Oracle"},{1723,"PPTP"},{2049,"NFS"},
    {2181,"Zookeeper"},{2375,"Docker"},{2376,"Docker-TLS"},
    {3306,"MySQL"},{3389,"RDP"},{3690,"SVN"},{4444,"Metasploit"},
    {5432,"PostgreSQL"},{5900,"VNC"},{6379,"Redis"},
    {6443,"K8s-API"},{8080,"HTTP-Alt"},{8443,"HTTPS-Alt"},
    {8888,"Jupyter"},{9200,"Elasticsearch"},{27017,"MongoDB"},
};

static std::string service_name(uint16_t port) {
    auto it = SERVICES.find(port);
    return (it != SERVICES.end()) ? it->second : "unknown";
}

// ─────────────────────────────────────────────────────────────────────────────
// ANSI colours
// ─────────────────────────────────────────────────────────────────────────────

namespace Col {
    std::string g(const std::string& s){ return "\033[92m" + s + "\033[0m"; }
    std::string y(const std::string& s){ return "\033[93m" + s + "\033[0m"; }
    std::string c(const std::string& s){ return "\033[96m" + s + "\033[0m"; }
    std::string r(const std::string& s){ return "\033[91m" + s + "\033[0m"; }
    std::string b(const std::string& s){ return "\033[1m"  + s + "\033[0m"; }
    std::string d(const std::string& s){ return "\033[2m"  + s + "\033[0m"; }
}

// ─────────────────────────────────────────────────────────────────────────────
// Thread pool
// ─────────────────────────────────────────────────────────────────────────────

class ThreadPool {
public:
    explicit ThreadPool(size_t n) : stop_(false) {
        for (size_t i = 0; i < n; ++i)
            workers_.emplace_back([this]{ worker_loop(); });
    }
    ~ThreadPool() {
        { std::unique_lock<std::mutex> lk(mtx_); stop_ = true; }
        cv_.notify_all();
        for (auto& t : workers_) if (t.joinable()) t.join();
    }
    void submit(std::function<void()> task) {
        { std::unique_lock<std::mutex> lk(mtx_); tasks_.push(std::move(task)); }
        cv_.notify_one();
    }
    void wait_idle() {
        std::unique_lock<std::mutex> lk(mtx_);
        idle_cv_.wait(lk, [this]{ return tasks_.empty() && active_ == 0; });
    }

private:
    void worker_loop() {
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lk(mtx_);
                cv_.wait(lk, [this]{ return stop_ || !tasks_.empty(); });
                if (stop_ && tasks_.empty()) return;
                task = std::move(tasks_.front());
                tasks_.pop();
                ++active_;
            }
            task();
            {
                std::unique_lock<std::mutex> lk(mtx_);
                --active_;
                if (tasks_.empty() && active_ == 0) idle_cv_.notify_all();
            }
        }
    }
    std::vector<std::thread>      workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex                    mtx_;
    std::condition_variable       cv_, idle_cv_;
    std::atomic<int>              active_{0};
    bool                          stop_;
};

// ─────────────────────────────────────────────────────────────────────────────
// Port probe
// ─────────────────────────────────────────────────────────────────────────────

struct ScanResult {
    uint16_t    port;
    bool        open;
    std::string service;
};

bool probe_tcp(const std::string& ip, uint16_t port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    // Set non-blocking via SO_SNDTIMEO / SO_RCVTIMEO (simpler than fcntl select)
    struct timeval tv;
    tv.tv_sec  =  timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    int ret = connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    close(sock);
    return ret == 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS resolve
// ─────────────────────────────────────────────────────────────────────────────

std::string resolve(const std::string& target) {
    // If already an IP, return as-is
    struct in_addr test;
    if (inet_pton(AF_INET, target.c_str(), &test) == 1) return target;

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    int r = getaddrinfo(target.c_str(), nullptr, &hints, &res);
    if (r != 0 || !res) {
        std::cerr << Col::r("[!] DNS resolution failed for '" + target + "': ")
                  << gai_strerror(r) << "\n";
        std::exit(1);
    }
    char buf[INET_ADDRSTRLEN];
    auto* sin = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
    freeaddrinfo(res);
    return std::string(buf);
}

// ─────────────────────────────────────────────────────────────────────────────
// Port range parser  (e.g. "1-1024", "22,80,443", "1-100,443,8000-8100")
// ─────────────────────────────────────────────────────────────────────────────

std::vector<uint16_t> parse_ports(const std::string& spec) {
    std::vector<uint16_t> ports;
    std::istringstream iss(spec);
    std::string token;
    while (std::getline(iss, token, ',')) {
        auto dash = token.find('-');
        if (dash != std::string::npos) {
            uint16_t lo = static_cast<uint16_t>(std::stoi(token.substr(0, dash)));
            uint16_t hi = static_cast<uint16_t>(std::stoi(token.substr(dash + 1)));
            for (uint16_t p = lo; p <= hi; ++p) ports.push_back(p);
        } else {
            ports.push_back(static_cast<uint16_t>(std::stoi(token)));
        }
    }
    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    return ports;
}

// ─────────────────────────────────────────────────────────────────────────────
// Banner
// ─────────────────────────────────────────────────────────────────────────────

void banner() {
    std::cout << Col::c(R"(
  ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ███████╗██║     ███████║██╔██╗ ██║
  ╚════██║██║     ██╔══██║██║╚██╗██║
  ███████║╚██████╗██║  ██║██║ ╚████║
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
  Port Scanner — CyberSec Toolkit v1.0
  github.com/nikhiltomar2712/cybersec
)") << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Help
// ─────────────────────────────────────────────────────────────────────────────

void help(const char* prog) {
    std::cout << "\n  " << Col::b("Usage:") << "\n"
              << "    " << prog << " <target> [--ports RANGE] [--threads N] [--timeout MS]\n\n"
              << "  " << Col::b("Options:") << "\n"
              << "    --ports    Port spec  (default: 1-1024)  e.g. 1-65535, 22,80,443\n"
              << "    --threads  Thread count  (default: 256)\n"
              << "    --timeout  Timeout in ms (default: 1000)\n\n"
              << "  " << Col::b("Examples:") << "\n"
              << "    " << prog << " 192.168.1.1\n"
              << "    " << prog << " scanme.nmap.org --ports 1-1024\n"
              << "    " << prog << " 10.0.0.5 --ports 1-65535 --threads 500 --timeout 500\n\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    banner();

    if (argc < 2 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
        help(argv[0]); return 0;
    }

    // ── Parse CLI ─────────────────────────────────────────────────────────────
    std::string target     = argv[1];
    std::string port_spec  = "1-1024";
    int         threads    = 256;
    int         timeout_ms = 1000;

    for (int i = 2; i < argc - 1; ++i) {
        std::string flag = argv[i];
        if (flag == "--ports")   port_spec  = argv[++i];
        else if (flag == "--threads") threads    = std::stoi(argv[++i]);
        else if (flag == "--timeout") timeout_ms = std::stoi(argv[++i]);
    }

    std::string ip     = resolve(target);
    auto        ports  = parse_ports(port_spec);
    auto        t0     = std::chrono::steady_clock::now();

    std::cout << "  " << Col::b("Target   :") << " " << target << " (" << ip << ")\n"
              << "  " << Col::b("Ports    :") << " " << ports.front()
                  << "–" << ports.back() << " (" << ports.size() << " ports)\n"
              << "  " << Col::b("Threads  :") << " " << threads << "\n"
              << "  " << Col::b("Timeout  :") << " " << timeout_ms << " ms\n"
              << "  " << std::string(50, '─') << "\n\n";

    // ── Scan ──────────────────────────────────────────────────────────────────
    std::vector<ScanResult> open_ports;
    std::mutex              results_mtx;
    std::atomic<size_t>     done{0};

    {
        ThreadPool pool(static_cast<size_t>(threads));

        for (uint16_t port : ports) {
            pool.submit([&, port]() {
                bool is_open = probe_tcp(ip, port, timeout_ms);
                ++done;
                if (is_open) {
                    std::lock_guard<std::mutex> lk(results_mtx);
                    open_ports.push_back({port, true, service_name(port)});
                }
            });
        }
        pool.wait_idle();
    }

    // ── Results ───────────────────────────────────────────────────────────────
    std::sort(open_ports.begin(), open_ports.end(),
              [](const ScanResult& a, const ScanResult& b){ return a.port < b.port; });

    auto t1 = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(t1 - t0).count();

    if (open_ports.empty()) {
        std::cout << "  " << Col::y("[-] No open ports found.\n");
    } else {
        std::cout << "  " << Col::b("PORT") << std::string(6, ' ')
                  << Col::b("STATE") << std::string(5, ' ')
                  << Col::b("SERVICE") << "\n"
                  << "  " << std::string(40, '─') << "\n";
        for (const auto& r : open_ports) {
            std::cout << "  " << std::left << std::setw(10) << r.port
                      << Col::g(std::string(10, ' ').replace(0, 4, "open"))
                      << r.service << "\n";
        }
    }

    std::cout << "\n  " << Col::b("Scanned") << " " << ports.size() << " port(s)  |  "
              << Col::g(std::to_string(open_ports.size()) + " open")
              << "  |  " << std::fixed << std::setprecision(2) << elapsed << "s\n\n";

    return 0;
}
