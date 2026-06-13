# Security Policy

## Vulnerability Reporting

If you discover a security vulnerability, please email security@example.com instead of using the public issue tracker.

**Do not publicly disclose security vulnerabilities.**

### Reporting Template

Subject: [SECURITY] Vulnerability Report

Vulnerability Type:
Affected Component:
Severity Level:
Description:
Proof of Concept:
Suggested Fix:
Code

---

## Security Best Practices

### For Users

1. **Never run untrusted code** - Always review source before execution
2. **Use in isolated environments** - Test tools in sandboxes/VMs first
3. **Keep dependencies updated** - Run `pip install --upgrade -r requirements.txt`
4. **Use with authorization** - Only scan systems you own or have permission for
5. **Secure credentials** - Never commit API keys or secrets

### For Developers

1. **Input validation** - Sanitize all user inputs
2. **Output encoding** - Prevent injection attacks
3. **Dependency scanning** - Regular security audits
4. **Code reviews** - Peer review all changes
5. **Secrets management** - Use .env files, never hardcode

---

## Security Scanning

Our CI/CD runs:

- **Bandit** - Python security
- **CodeQL** - Multi-language analysis
- **OWASP Dependency Check** - Vulnerable dependencies
- **npm audit** - Node.js packages

---

## Supported Versions

| Version | Status | Support Until |
|---------|--------|----------------|
| 1.x     | Active | 2027-06 |
| 0.x     | EOL    | 2024-06 |

---

## Known Issues

None currently. Check GitHub Issues for reported security concerns.

docs/INSTALLATION.md

md
# Installation Guide

## Quick Start (5 minutes)

### Option 1: Clone & Install

```bash
# Clone repository
git clone https://github.com/nikhiltomar2712/cybersec.git
cd cybersec

# Install all dependencies
make install
Option 2: Docker
bash
# Build and run
make build-docker
make docker-up

# Access container
docker exec -it cybersec-toolkit bash
Detailed Installation
Prerequisites
Python: 3.8 or higher
Node.js: 14 or higher
C++ Compiler: GCC 7+ or Clang 5+
Git: 2.0 or higher
Docker (optional): 20.10+
Linux/macOS
bash
# Install system dependencies
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential cmake git python3 nodejs

# macOS
brew install build-essential cmake python@3.11 node

# Clone and install
git clone https://github.com/nikhiltomar2712/cybersec.git
cd cybersec

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install Node.js dependencies
npm install

# Build C++ tools
mkdir build
cd build
cmake ..
make
Windows
PowerShell
# Install Python 3.11+ and Node.js 18+ from official websites
# Install Visual Studio Build Tools or MinGW

# Clone repository
git clone https://github.com/nikhiltomar2712/cybersec.git
cd cybersec

# Create virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
npm install

# Build C++ tools
mkdir build
cd build
cmake ..
make
Verification
bash
# Verify Python tools
python3 tools/python/port_scanner.py --help

# Verify Node.js tools
node tools/js/recon.js --help

# Verify C++ tools
./build/crypto_tools --help

# Run tests
make test
Troubleshooting
Issue: "command not found: cmake"
bash
# Ubuntu/Debian
sudo apt-get install cmake

# macOS
brew install cmake
Issue: "No module named 'requests'"
bash
pip install --upgrade pip
pip install -r requirements.txt
Issue: "C++ compilation error"
bash
# Check GCC version (need 7+)
g++ --version

# Install/update GCC
sudo apt-get install g++-9 g++-10 g++-11
Issue: Docker build fails
bash
# Clear Docker cache
docker system prune

# Rebuild
make build-docker
Code
docs/TROUBLESHOOTING.md

md
# Troubleshooting Guide

## Common Issues & Solutions

### Python Tools

#### ImportError: No module named 'dns'

```bash
# Solution: Install dnspython
pip install dnspython

# Or install all dependencies
pip install -r requirements.txt
Port Scanner Timeout
bash
# Increase timeout
python3 tools/python/port_scanner.py target.com --timeout 10

# Reduce concurrent connections
python3 tools/python/port_scanner.py target.com --max-concurrent 50
Hash Cracker Too Slow
bash
# Use optimized wordlist
head -c 100000 rockyou.txt > small_wordlist.txt
python3 tools/python/hash_identifier.py HASH --wordlist small_wordlist.txt

# Limit attempts
python3 tools/python/hash_identifier.py HASH --wordlist rockyou.txt --limit 50000
JavaScript Tools
Module not found error
bash
# Clear and reinstall
rm -rf node_modules package-lock.json
npm install
DNS lookup fails
bash
# Check DNS
dig example.com
nslookup example.com

# Or specify DNS server in code
const dns = require('dns');
dns.setServers(['8.8.8.8', '8.8.4.4']);
C++ Tools
Compilation error: "no match for 'operator<<'"
bash
# Update C++ standard
g++ -std=c++17 -O2 -pthread -o port_scanner tools/cpp/port_scanner.cpp
Threading errors
bash
# Ensure -pthread flag
g++ -std=c++17 -O2 -pthread -o port_scanner tools/cpp/port_scanner.cpp
Segmentation fault on macOS
bash
# Use clang instead
clang++ -std=c++17 -O2 -pthread -o port_scanner tools/cpp/port_scanner.cpp
Docker Issues
Container won't start
bash
# Check logs
docker-compose logs app

# Rebuild
docker-compose down
make build-docker
make docker-up
Port already in use
bash
# Check what's using port
lsof -i :8000

# Change port in docker-compose.yml or
kill -9 <PID>
Permission Issues
"Permission denied" on Linux
bash
# Make scripts executable
chmod +x tools/python/*.py
chmod +x tools/js/*.js

# Or use python3 explicitly
python3 tools/python/port_scanner.py ...
node tools/js/recon.js ...
Performance Issues
High memory usage
bash
# Reduce concurrent connections
python3 tools/python/port_scanner.py target --max-concurrent 50

# Reduce thread count
python3 tools/python/subdomain_enum.py domain.com --threads 5
Network timeouts
bash
# Increase timeout values
python3 tools/python/port_scanner.py target --timeout 15

# Check network
ping target
netstat -an | grep ESTABLISHED
Debug Mode
Enable Verbose Output
Python:

Python
import logging
logging.basicConfig(level=logging.DEBUG)
JavaScript:

JavaScript
process.env.DEBUG = '*';
C++:

C++
#define DEBUG 1
// Recompile with debug symbols
g++ -g -std=c++17 ...
Getting Help
Check GitHub Issues
Review Documentation
Submit detailed bug report with:
OS and version
Tool version
Exact error message
Steps to reproduce
Expected vs actual behavior
Code
docs/CONTRIBUTING_ADVANCED.md

md
# Advanced Contribution Guidelines

## Code Quality Standards

### Python

- **Type Hints**: Use throughout (PEP 484)
- **Docstrings**: Google style, 100% coverage
- **Testing**: 80%+ code coverage minimum
- **Linting**: Flake8, Black, isort, mypy

```python
from typing import List, Optional, Tuple

def analyze_ports(
    host: str,
    ports: List[int],
    timeout: int = 5
) -> Tuple[List[int], int]:
    """
    Analyze open ports on a host.
    
    Args:
        host: Target hostname or IP address
        ports: List of ports to scan
        timeout: Connection timeout in seconds
        
    Returns:
        Tuple of (open_ports, closed_ports)
        
    Raises:
        ValueError: If host is invalid
        TimeoutError: If scan times out
    """
JavaScript
ESLint: No warnings/errors
Prettier: Enforced formatting
JSDoc: Document all exported functions
Jest: Comprehensive test suite
JavaScript
/**
 * Scan target for vulnerabilities.
 * @param {string} target - Target URL or IP
 * @param {Object} options - Scan options
 * @param {number} options.timeout - Request timeout (ms)
 * @param {boolean} options.aggressive - Aggressive mode
 * @returns {Promise<Array>} Array of vulnerabilities found
 * @throws {Error} If target is invalid
 */
async function scanTarget(target, options = {}) {
  // Implementation
}
C++
Modern C++17: No C-style code
RAII: Resource management
STL: Use containers, algorithms
Error Handling: Exceptions, not error codes
C++
/// Scan ports on target host.
/// @param host Target hostname or IP
/// @param ports Vector of ports to scan
/// @param timeout Connection timeout (seconds)
/// @return Vector of open port numbers
/// @throws std::invalid_argument if host is invalid
std::vector<int> scanPorts(
    const std::string& host,
    const std::vector<int>& ports,
    int timeout = 5
);
Testing Requirements
Unit Tests
Python
# tests/test_port_scanner.py
import pytest
from tools.python.port_scanner import parse_ports

class TestPortScanner:
    def test_parse_single_port(self):
        assert parse_ports('80') == [80]
    
    def test_parse_port_range(self):
        assert parse_ports('1-5') == [1, 2, 3, 4, 5]
    
    def test_parse_multiple_ranges(self):
        assert set(parse_ports('1-3,10-12')) == {1, 2, 3, 10, 11, 12}
Integration Tests
Python
# tests/test_integration.py
import pytest
import asyncio
from tools.python.port_scanner import scan_ports

@pytest.mark.asyncio
async def test_scan_localhost():
    open_ports = await scan_ports('127.0.0.1', [22, 80, 443])
    assert isinstance(open_ports, list)
Performance Profiling
bash
# Python profiling
python -m cProfile -s cumulative tools/python/port_scanner.py target --ports 1-100

# C++ profiling
g++ -pg -std=c++17 -o port_scanner tools/cpp/port_scanner.cpp
./port_scanner target 1 1024
gprof port_scanner gmon.out
Documentation Standards
README Sections
 Quick start
 Installation instructions
 Usage examples
 API reference
 Contributing guidelines
 License
Code Comments
Explain "why", not "what"
1 comment per 10 lines maximum
Keep comments up to date
Commit Message Format
Code
<type>(<scope>): <subject>

<body>

<footer>

Type: feat|fix|docs|style|refactor|perf|test|chore
Scope: tools|ci|docs|etc
Subject: imperative, lowercase, no period
Body: wrap at 72 chars, explain what and why
Footer: fix #ISSUE, Closes #ISSUE
Example:

Code
feat(tools): add parallel DNS resolution to subdomain_enum

Implement concurrent DNS queries using asyncio for 10x faster
enumeration. Maintains backward compatibility with existing API.

Closes #123
PR Checklist
 Feature branch from develop
 Code passes all linters
 80%+ test coverage
 All tests passing
 Documentation updated
 Security scan passed
 CHANGELOG.md updated
 Meaningful commit messages
 No merge conflicts
Release Checklist
 Update version in all files
 Update CHANGELOG.md
 Update documentation
 Run full test suite
 Create release notes
 Tag release in Git
 Publish to registries (PyPI, npm)
