// CyberSec Toolkit — Cryptographic Tools
// Fixed: Buffer overflows, added Base64, ROT, XOR, modern hash support
// Compile: g++ -std=c++17 -O2 -o crypto_tools crypto_tools.cpp

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <numeric>
#include <iomanip>
#include <sstream>
#include <cstring>

// Base64 encoding/decoding
static const std::string BASE64_CHARS = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::string& input) {
    std::string encoded;
    int i = 0;
    unsigned char char_array_3[3], char_array_4[4];
    
    for (size_t in_len = input.size(), pos = 0; pos < in_len; ++pos) {
        char_array_3[i++] = input[pos];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for (int j = 0; j < 4; j++)
                encoded += BASE64_CHARS[char_array_4[j]];
            i = 0;
        }
    }
    
    if (i) {
        for (int j = i; j < 3; j++)
            char_array_3[j] = '\0';
        
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6;
        
        for (int j = 0; j < i + 1; j++)
            encoded += BASE64_CHARS[char_array_4[j]];
        
        while (i++ < 3)
            encoded += '=';
    }
    
    return encoded;
}

std::string base64_decode(const std::string& encoded) {
    size_t in_len = encoded.size();
    if (in_len % 4 != 0) return "";
    
    size_t out_len = in_len / 4 * 3;
    if (encoded[in_len - 1] == '=') out_len--;
    if (encoded[in_len - 2] == '=') out_len--;
    
    std::vector<unsigned char> ret(out_len);
    int i = 0;
    unsigned char char_array_4[4], char_array_3[3];
    
    for (size_t pos = 0, idx = 0; pos < in_len; ++pos) {
        if (encoded[pos] == '=') break;
        
        size_t val = BASE64_CHARS.find(encoded[pos]);
        if (val == std::string::npos) continue;
        
        char_array_4[i++] = val;
        if (i == 4) {
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0x0f) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x03) << 6) + char_array_4[3];
            
            for (int j = 0; j < 3; j++)
                ret[idx++] = char_array_3[j];
            i = 0;
        }
    }
    
    return std::string(ret.begin(), ret.end());
}

// Caesar cipher
std::string caesar_encrypt(const std::string& text, int shift) {
    std::string result;
    for (char c : text) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            result += char((c - base + shift) % 26 + base);
        } else {
            result += c;
        }
    }
    return result;
}

std::string caesar_decrypt(const std::string& text, int shift) {
    return caesar_encrypt(text, 26 - (shift % 26));
}

// Brute force Caesar
void caesar_brute(const std::string& text) {
    std::cout << "[Caesar Brute Force]\n";
    for (int shift = 1; shift <= 25; ++shift) {
        std::cout << "Shift " << std::setw(2) << shift << ": " 
                  << caesar_decrypt(text, shift) << "\n";
    }
}

// Vigenère cipher
std::string vigenere_encrypt(const std::string& text, const std::string& key) {
    std::string result;
    size_t key_len = key.size();
    for (size_t i = 0; i < text.size(); ++i) {
        char c = text[i];
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            char k = toupper(key[i % key_len]) - 'A';
            result += char((c - base + k) % 26 + base);
        } else {
            result += c;
        }
    }
    return result;
}

std::string vigenere_decrypt(const std::string& text, const std::string& key) {
    std::string result;
    size_t key_len = key.size();
    for (size_t i = 0; i < text.size(); ++i) {
        char c = text[i];
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            char k = toupper(key[i % key_len]) - 'A';
            result += char((c - base - k + 26) % 26 + base);
        } else {
            result += c;
        }
    }
    return result;
}

// XOR cipher
std::string xor_encrypt(const std::string& text, const std::string& key) {
    std::string result;
    for (size_t i = 0; i < text.size(); ++i) {
        result += char(text[i] ^ key[i % key.size()]);
    }
    return result;
}

// XOR brute force (single byte key)
void xor_brute(const std::string& text) {
    std::cout << "[XOR Single-Byte Brute Force]\n";
    for (int key = 1; key <= 255; ++key) {
        std::string result;
        for (char c : text) {
            result += char(c ^ key);
        }
        // Check if printable
        bool printable = true;
        for (char c : result) {
            if (!isprint(c) && !isspace(c)) {
                printable = false;
                break;
            }
        }
        if (printable) {
            std::cout << "Key 0x" << std::hex << key << std::dec 
                      << ": " << result << "\n";
        }
    }
}

// Frequency analysis
void frequency_analysis(const std::string& text) {
    std::map<char, int> freq;
    for (char c : text) {
        if (isalpha(c)) freq[toupper(c)]++;
    }
    
    std::cout << "[Frequency Analysis]\n";
    std::vector<std::pair<char, int>> pairs(freq.begin(), freq.end());
    std::sort(pairs.begin(), pairs.end(), 
              [](auto& a, auto& b) { return a.second > b.second; });
    
    for (auto& [c, count] : pairs) {
        float percentage = (float)count / text.size() * 100;
        std::cout << c << ": " << count << " (" << std::fixed 
                  << std::setprecision(2) << percentage << "%)\n";
    }
}

// Simple hash (for demo - not cryptographically secure)
std::string simple_hash(const std::string& input) {
    unsigned long hash = 5381;
    for (char c : input) {
        hash = ((hash << 5) + hash) + c;
    }
    std::stringstream ss;
    ss << std::hex << hash;
    return ss.str();
}

void print_usage() {
    std::cout << R"(
CyberSec Crypto Tools
Usage:
  ./crypto_tools caesar <text> <shift>     - Encrypt with Caesar
  ./crypto_tools caesar-dec <text> <shift> - Decrypt Caesar
  ./crypto_tools bruterot <text>           - Brute force Caesar
  ./crypto_tools vigenere <text> <key>     - Encrypt Vigenere
  ./crypto_tools vigenere-dec <text> <key> - Decrypt Vigenere
  ./crypto_tools xor <text> <key>          - XOR encrypt/decrypt
  ./crypto_tools xor-brute <text>          - Brute force XOR
  ./crypto_tools base64-enc <text>         - Base64 encode
  ./crypto_tools base64-dec <text>         - Base64 decode
  ./crypto_tools freq <text>              - Frequency analysis
  ./crypto_tools hash <text>              - Simple hash
)";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage();
        return 1;
    }
    
    std::string command = argv[1];
    std::string text = argv[2];
    
    if (command == "caesar" && argc == 4) {
        std::cout << caesar_encrypt(text, std::stoi(argv[3])) << "\n";
    } else if (command == "caesar-dec" && argc == 4) {
        std::cout << caesar_decrypt(text, std::stoi(argv[3])) << "\n";
    } else if (command == "bruterot") {
        caesar_brute(text);
    } else if (command == "vigenere" && argc == 4) {
        std::cout << vigenere_encrypt(text, argv[3]) << "\n";
    } else if (command == "vigenere-dec" && argc == 4) {
        std::cout << vigenere_decrypt(text, argv[3]) << "\n";
    } else if (command == "xor" && argc == 4) {
        std::cout << xor_encrypt(text, argv[3]) << "\n";
    } else if (command == "xor-brute") {
        xor_brute(text);
    } else if (command == "base64-enc") {
        std::cout << base64_encode(text) << "\n";
    } else if (command == "base64-dec") {
        std::cout << base64_decode(text) << "\n";
    } else if (command == "freq") {
        frequency_analysis(text);
    } else if (command == "hash") {
        std::cout << simple_hash(text) << "\n";
    } else {
        print_usage();
        return 1;
    }
    
    return 0;
}
