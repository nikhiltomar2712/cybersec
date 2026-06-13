// CyberSec Toolkit — Linux Process Memory Scanner
// Scans process memory for patterns (strings, hex sequences)
// Compile: g++ -std=c++17 -O2 -o memory_scanner memory_scanner.cpp

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <regex>
#include <iomanip>

namespace fs = std::filesystem;

class MemoryScanner {
public:
    bool scanProcess(pid_t pid, const std::string& pattern) {
        std::string mapsPath = "/proc/" + std::to_string(pid) + "/maps";
        std::string memPath = "/proc/" + std::to_string(pid) + "/mem";
        
        std::ifstream maps(mapsPath);
        if (!maps) {
            std::cerr << "[!] Cannot open process maps. Run as root?\n";
            return false;
        }
        
        std::ifstream mem(memPath, std::ios::binary);
        if (!mem) {
            std::cerr << "[!] Cannot open process memory\n";
            return false;
        }
        
        std::string line;
        int matches = 0;
        
        while (std::getline(maps, line)) {
            // Parse memory region
            size_t dashPos = line.find('-');
            if (dashPos == std::string::npos) continue;
            
            std::string startStr = line.substr(0, dashPos);
            size_t spacePos = line.find(' ', dashPos);
            std::string endStr = line.substr(dashPos + 1, spacePos - dashPos - 1);
            
            unsigned long start = std::stoul(startStr, nullptr, 16);
            unsigned long end = std::stoul(endStr, nullptr, 16);
            
            // Check permissions (r--)
            if (line.find('r') == std::string::npos) continue;
            
            // Read memory region
            mem.seekg(start);
            size_t size = end - start;
            std::vector<char> buffer(size);
            mem.read(buffer.data(), size);
            
            // Search for pattern
            std::string content(buffer.data(), mem.gcount());
            size_t pos = 0;
            while ((pos = content.find(pattern, pos)) != std::string::npos) {
                std::cout << "[MATCH] Found at offset 0x" << std::hex 
                          << (start + pos) << std::dec << "\n";
                // Print context
                size_t ctxStart = (pos > 20) ? pos - 20 : 0;
                size_t ctxLen = std::min(pattern.length() + 40, content.length() - ctxStart);
                std::string context = content.substr(ctxStart, ctxLen);
                
                // Clean non-printable
                for (auto& c : context) {
                    if (!isprint(c)) c = '.';
                }
                std::cout << "  Context: ..." << context << "...\n";
                
                pos += 1;
                matches++;
                if (matches >= 100) {
                    std::cout << "[!] Limit reached (100 matches)\n";
                    return true;
                }
            }
        }
        
        std::cout << "[*] Total matches: " << matches << "\n";
        return true;
    }
    
    void listProcesses() {
        std::cout << "[Running Processes]\n";
        for (const auto& entry : fs::directory_iterator("/proc")) {
            if (fs::is_directory(entry)) {
                std::string name = entry.path().filename().string();
                if (std::all_of(name.begin(), name.end(), ::isdigit)) {
                    std::string cmdlinePath = entry.path().string() + "/cmdline";
                    std::ifstream cmdline(cmdlinePath);
                    std::string cmd;
                    if (cmdline && std::getline(cmdline, cmd)) {
                        // Replace null chars with spaces
                        std::replace(cmd.begin(), cmd.end(), '\0', ' ');
                        std::cout << "  PID " << name << ": " << cmd << "\n";
                    }
                }
            }
        }
    }
};

void print_usage() {
    std::cout << R"(
CyberSec Memory Scanner (Linux)
Usage:
  sudo ./memory_scanner list                  - List processes
  sudo ./memory_scanner scan <pid> <pattern>  - Scan process memory
  sudo ./memory_scanner hex <pid> <hex>       - Scan for hex sequence
)";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }
    
    MemoryScanner scanner;
    std::string command = argv[1];
    
    if (command == "list") {
        scanner.listProcesses();
    } else if (command == "scan" && argc == 4) {
        pid_t pid = std::stoi(argv[2]);
        scanner.scanProcess(pid, argv[3]);
    } else if (command == "hex" && argc == 4) {
        // Convert hex string to bytes
        std::string hex = argv[3];
        std::string bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            bytes += static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16));
        }
        pid_t pid = std::stoi(argv[2]);
        scanner.scanProcess(pid, bytes);
    } else {
        print_usage();
        return 1;
    }
    
    return 0;
}
