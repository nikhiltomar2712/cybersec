/*
 * CyberSec Toolkit — Crypto & Encoding Tools (C++)
 * =================================================
 * A collection of classic cryptography and encoding algorithms
 * used in CTF challenges, penetration testing, and security study.
 *
 * Tools included:
 *   1. Caesar Cipher      — encrypt / decrypt with configurable shift
 *   2. ROT13              — symmetric letter rotation
 *   3. Vigenere Cipher    — polyalphabetic substitution
 *   4. XOR Cipher         — byte-level XOR with a key
 *   5. Base64             — encode / decode (RFC 4648)
 *   6. Frequency Analysis — letter frequency for cipher-text analysis
 *
 * Compile:
 *   g++ -std=c++17 -O2 -o crypto_tools crypto_tools.cpp
 *
 * Usage:
 *   ./crypto_tools caesar  enc "Hello World" 13
 *   ./crypto_tools caesar  dec "Uryyb Jbeyq" 13
 *   ./crypto_tools rot13       "Hello World"
 *   ./crypto_tools vigenere enc "HELLO" "KEY"
 *   ./crypto_tools vigenere dec "RIJVS" "KEY"
 *   ./crypto_tools xor     enc "secret" "k"
 *   ./crypto_tools base64  enc "Hello World"
 *   ./crypto_tools base64  dec "SGVsbG8gV29ybGQ="
 *   ./crypto_tools freq        "URYYB JBEYQ"
 *   ./crypto_tools bruterot    "Uryyb Jbeyq"
 *
 * Educational use only. See ETHICAL_USE.txt before use.
 */

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// ANSI colour helpers
// ─────────────────────────────────────────────────────────────────────────────

namespace Col {
    const std::string reset  = "\033[0m";
    const std::string green  = "\033[92m";
    const std::string yellow = "\033[93m";
    const std::string cyan   = "\033[96m";
    const std::string red    = "\033[91m";
    const std::string bold   = "\033[1m";
    const std::string dim    = "\033[2m";

    std::string g(const std::string& s) { return green  + s + reset; }
    std::string y(const std::string& s) { return yellow + s + reset; }
    std::string c(const std::string& s) { return cyan   + s + reset; }
    std::string r(const std::string& s) { return red    + s + reset; }
    std::string b(const std::string& s) { return bold   + s + reset; }
    std::string d(const std::string& s) { return dim    + s + reset; }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Caesar Cipher
// ─────────────────────────────────────────────────────────────────────────────

std::string caesar(const std::string& text, int shift, bool encrypt) {
    // Normalise shift to [0, 25]
    shift = ((shift % 26) + 26) % 26;
    if (!encrypt) shift = (26 - shift) % 26;

    std::string result;
    result.reserve(text.size());

    for (char ch : text) {
        if (std::isalpha(static_cast<unsigned char>(ch))) {
            char base = std::isupper(static_cast<unsigned char>(ch)) ? 'A' : 'a';
            result += static_cast<char>((ch - base + shift) % 26 + base);
        } else {
            result += ch;
        }
    }
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. ROT13  (symmetric — same function for enc/dec)
// ─────────────────────────────────────────────────────────────────────────────

std::string rot13(const std::string& text) {
    return caesar(text, 13, true);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Vigenère Cipher
// ─────────────────────────────────────────────────────────────────────────────

std::string vigenere(const std::string& text, const std::string& key, bool encrypt) {
    if (key.empty()) {
        std::cerr << Col::r("[!] Vigenere key cannot be empty.\n");
        return text;
    }

    std::string k;
    for (char ch : key) {
        if (std::isalpha(static_cast<unsigned char>(ch)))
            k += static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }

    std::string result;
    result.reserve(text.size());
    size_t ki = 0;

    for (char ch : text) {
        if (std::isalpha(static_cast<unsigned char>(ch))) {
            char base = std::isupper(static_cast<unsigned char>(ch)) ? 'A' : 'a';
            int shift = k[ki % k.size()] - 'A';
            if (!encrypt) shift = (26 - shift) % 26;
            result += static_cast<char>((ch - base + shift) % 26 + base);
            ++ki;
        } else {
            result += ch;
        }
    }
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. XOR Cipher
// ─────────────────────────────────────────────────────────────────────────────

std::string xor_cipher(const std::string& text, const std::string& key) {
    if (key.empty()) {
        std::cerr << Col::r("[!] XOR key cannot be empty.\n");
        return text;
    }
    std::string result;
    result.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
        result += static_cast<char>(
            static_cast<unsigned char>(text[i]) ^
            static_cast<unsigned char>(key[i % key.size()])
        );
    }
    return result;
}

/** Convert binary string → hex string for safe display */
std::string to_hex(const std::string& data) {
    std::ostringstream oss;
    for (unsigned char c : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return oss.str();
}

/** Convert hex string → binary string */
std::string from_hex(const std::string& hex) {
    std::string result;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        result += static_cast<char>(
            static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16))
        );
    }
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Base64
// ─────────────────────────────────────────────────────────────────────────────

static const std::string B64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::string& in) {
    std::string out;
    int val = 0, bits = -6;
    for (unsigned char c : in) {
        val  = (val << 8) + c;
        bits += 8;
        while (bits >= 0) {
            out += B64_CHARS[(val >> bits) & 0x3F];
            bits -= 6;
        }
    }
    if (bits > -6)
        out += B64_CHARS[((val << 8) >> (bits + 8)) & 0x3F];
    while (out.size() % 4)
        out += '=';
    return out;
}

std::string base64_decode(const std::string& in) {
    // Build lookup table
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; ++i)
        T[static_cast<unsigned char>(B64_CHARS[i])] = i;

    std::string out;
    int val = 0, bits = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;          // stop at padding / whitespace
        val   = (val << 6) + T[c];
        bits += 6;
        if (bits >= 0) {
            out += static_cast<char>((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Frequency Analysis
// ─────────────────────────────────────────────────────────────────────────────

void frequency_analysis(const std::string& text) {
    std::map<char, int> freq;
    int total = 0;
    for (char ch : text) {
        if (std::isalpha(static_cast<unsigned char>(ch))) {
            ++freq[static_cast<char>(std::toupper(static_cast<unsigned char>(ch)))];
            ++total;
        }
    }
    if (total == 0) {
        std::cout << Col::y("  [!] No alphabetic characters found.\n");
        return;
    }

    // Sort by frequency descending
    std::vector<std::pair<int,char>> ranked;
    for (auto& [ch, cnt] : freq)
        ranked.emplace_back(cnt, ch);
    std::sort(ranked.rbegin(), ranked.rend());

    // English reference
    const std::string ETAOIN = "ETAOINSHRDLCUMWFGYPBVKJXQZ";

    std::cout << "\n  " << Col::b("Letter  Count  Frequency  English Ref");
    std::cout << "\n  " << std::string(42, '-') << "\n";
    for (size_t i = 0; i < ranked.size(); ++i) {
        auto [cnt, ch] = ranked[i];
        double pct = 100.0 * cnt / total;
        std::string bar(static_cast<int>(pct * 1.5), '█');
        std::cout << "  " << Col::g(std::string(1, ch)) << "       "
                  << std::setw(4) << cnt << "   "
                  << std::setw(5) << std::fixed << std::setprecision(1) << pct << "%  "
                  << Col::d(std::string(1, ETAOIN[i]))
                  << "  " << Col::cyan << bar << Col::reset << "\n";
    }
    std::cout << "\n  [i] Compare your cipher's top letters against English (ETAOIN) "
              << "to guess shifts.\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Brute-force all 26 Caesar rotations
// ─────────────────────────────────────────────────────────────────────────────

void brute_rot(const std::string& text) {
    std::cout << "\n  " << Col::b("Shift   Plaintext") << "\n  " << std::string(55, '-') << "\n";
    for (int shift = 0; shift < 26; ++shift) {
        std::string decoded = caesar(text, shift, false);
        std::cout << "  " << std::setw(2) << shift << "      " << Col::g(decoded) << "\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Banner
// ─────────────────────────────────────────────────────────────────────────────

void banner() {
    std::cout << Col::cyan << R"(
  ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗
  ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗
  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║
  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║
  ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝
   ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝
  Crypto Tools — CyberSec Toolkit v1.0
  github.com/nikhiltomar2712/cybersec
)" << Col::reset;
}

// ─────────────────────────────────────────────────────────────────────────────
// Help
// ─────────────────────────────────────────────────────────────────────────────

void help(const std::string& prog) {
    std::cout << "\n  " << Col::b("Usage:") << "\n"
              << "    " << prog << " <tool> [enc|dec] <text> [key/shift]\n\n"
              << "  " << Col::b("Tools:") << "\n"
              << "    caesar   enc|dec  \"text\" <shift>    Caesar cipher\n"
              << "    rot13            \"text\"             ROT-13\n"
              << "    vigenere enc|dec  \"text\" <key>      Vigenere cipher\n"
              << "    xor      enc      \"text\" <key>      XOR cipher (outputs hex)\n"
              << "    xor      dec      \"hexdata\" <key>   XOR decode from hex\n"
              << "    base64   enc|dec  \"text\"            Base64\n"
              << "    freq             \"text\"             Frequency analysis\n"
              << "    bruterot         \"ciphertext\"       Try all 26 rotations\n\n"
              << "  " << Col::b("Examples:") << "\n"
              << "    " << prog << " caesar enc \"Hello World\" 13\n"
              << "    " << prog << " caesar dec \"Uryyb Jbeyq\" 13\n"
              << "    " << prog << " rot13 \"Hello World\"\n"
              << "    " << prog << " vigenere enc \"HELLO\" \"KEY\"\n"
              << "    " << prog << " xor enc \"secret\" \"k\"\n"
              << "    " << prog << " base64 enc \"Hello World\"\n"
              << "    " << prog << " base64 dec \"SGVsbG8gV29ybGQ=\"\n"
              << "    " << prog << " freq \"URYYB JBEYQ\"\n"
              << "    " << prog << " bruterot \"Uryyb Jbeyq\"\n\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    banner();

    if (argc < 2) { help(argv[0]); return 0; }

    std::string tool = argv[1];
    std::transform(tool.begin(), tool.end(), tool.begin(), ::tolower);

    auto require = [&](int n) {
        if (argc < n + 1) {
            std::cerr << Col::r("[!] Too few arguments for '" + tool + "'.\n");
            help(argv[0]);
            std::exit(1);
        }
    };

    // ── caesar ───────────────────────────────────────────────────────────────
    if (tool == "caesar") {
        require(4);
        std::string mode = argv[2], text = argv[3];
        int shift = (argc >= 5) ? std::stoi(argv[4]) : 13;
        bool enc = (mode != "dec");
        std::string result = caesar(text, shift, enc);
        std::cout << "\n  " << Col::b("Mode  :") << " " << (enc ? "encrypt" : "decrypt") << "\n"
                  << "  " << Col::b("Shift :") << " " << shift << "\n"
                  << "  " << Col::b("Input :") << " " << text << "\n"
                  << "  " << Col::b("Output:") << " " << Col::g(result) << "\n\n";

    // ── rot13 ─────────────────────────────────────────────────────────────────
    } else if (tool == "rot13") {
        require(2);
        std::string text = argv[2];
        std::cout << "\n  " << Col::b("Input :") << " " << text << "\n"
                  << "  " << Col::b("ROT-13:") << " " << Col::g(rot13(text)) << "\n\n";

    // ── vigenere ──────────────────────────────────────────────────────────────
    } else if (tool == "vigenere") {
        require(4);
        std::string mode = argv[2], text = argv[3];
        std::string key  = (argc >= 5) ? argv[4] : "KEY";
        bool enc = (mode != "dec");
        std::cout << "\n  " << Col::b("Mode  :") << " " << (enc ? "encrypt" : "decrypt") << "\n"
                  << "  " << Col::b("Key   :") << " " << key << "\n"
                  << "  " << Col::b("Input :") << " " << text << "\n"
                  << "  " << Col::b("Output:") << " " << Col::g(vigenere(text, key, enc)) << "\n\n";

    // ── xor ───────────────────────────────────────────────────────────────────
    } else if (tool == "xor") {
        require(4);
        std::string mode = argv[2], text = argv[3];
        std::string key  = (argc >= 5) ? argv[4] : "";
        if (key.empty()) { std::cerr << Col::r("[!] XOR requires a key argument.\n"); return 1; }
        if (mode == "dec") {
            // Decode: input is hex → decode to binary → XOR
            std::string bin = from_hex(text);
            std::cout << "\n  " << Col::b("Key   :") << " " << key << "\n"
                      << "  " << Col::b("Hex In:") << " " << text << "\n"
                      << "  " << Col::b("Output:") << " " << Col::g(xor_cipher(bin, key)) << "\n\n";
        } else {
            std::string result = xor_cipher(text, key);
            std::cout << "\n  " << Col::b("Key   :") << " " << key << "\n"
                      << "  " << Col::b("Input :") << " " << text << "\n"
                      << "  " << Col::b("Hex   :") << " " << Col::g(to_hex(result)) << "\n"
                      << "  " << Col::y("[i] Use hex output with 'xor dec' to reverse.") << "\n\n";
        }

    // ── base64 ────────────────────────────────────────────────────────────────
    } else if (tool == "base64") {
        require(3);
        std::string mode = argv[2], text = argv[3];
        std::string result = (mode == "dec") ? base64_decode(text) : base64_encode(text);
        std::cout << "\n  " << Col::b("Mode  :") << " " << mode << "\n"
                  << "  " << Col::b("Input :") << " " << text << "\n"
                  << "  " << Col::b("Output:") << " " << Col::g(result) << "\n\n";

    // ── freq ──────────────────────────────────────────────────────────────────
    } else if (tool == "freq") {
        require(2);
        frequency_analysis(argv[2]);

    // ── bruterot ──────────────────────────────────────────────────────────────
    } else if (tool == "bruterot") {
        require(2);
        brute_rot(argv[2]);

    } else {
        std::cerr << Col::r("[!] Unknown tool: '" + tool + "'\n");
        help(argv[0]);
        return 1;
    }

    return 0;
}
