# Development Guide

## Setup Development Environment

### Prerequisites
- Python 3.8+
- Node.js 14+
- C++17 compatible compiler (g++ 7+, clang 5+)
- Git

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/nikhiltomar2712/cybersec.git
cd cybersec

# Create development branch
git checkout -b feature/your-feature-name

# Install all dependencies
pip install -r requirements.txt
npm install
mkdir build && cd build && cmake .. && make
```

Project Structure
Code
cybersec/
├── tools/
│   ├── python/           # Python tools
│   ├── js/               # JavaScript tools
│   └── cpp/              # C++ tools
├── tests/                # Unit tests
├── docs/                 # Documentation
├── .github/
│   ├── workflows/        # GitHub Actions CI/CD
│   └── ISSUE_TEMPLATE/   # Issue templates
├── requirements.txt      # Python dependencies
├── package.json          # Node.js dependencies
├── CMakeLists.txt        # C++ build config
└── README.md             # Main documentation
Contributing Workflow
1. Create a Feature Branch
bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-name
2. Make Changes
bash
# Make your changes
# Test locally
# Keep commits atomic and meaningful
3. Format & Lint Code
Python:

bash
black tools/python/*.py
flake8 tools/python/*.py
isort tools/python/*.py
JavaScript:

bash
npm run lint
npm run format
C++:

bash
clang-format -i tools/cpp/*.cpp
4. Test Your Changes
bash
# Python tests
pytest tests/ -v

# JavaScript tests
npm test

# Manual testing
python3 tools/python/port_scanner.py localhost --ports 1-1024
5. Push and Create Pull Request
bash
git push origin feature/your-feature-name
# Create PR on GitHub with clear description
Python Development
Code Style
Follow PEP 8
Use type hints where possible
Max line length: 100 characters
Use docstrings (Google style)
Example:
Python
def my_function(param1: str, param2: int) -> bool:
    """
    Short description.
    
    Args:
        param1: Description of param1
        param2: Description of param2
        
    Returns:
        Description of return value
    """
    return True
Testing
bash
# Run all tests
pytest tests/ -v

# Run specific test
pytest tests/test_utils.py::TestClass::test_method -v

# With coverage
pytest tests/ --cov=. --cov-report=html
JavaScript Development
Code Style
Follow ESLint configuration
Use const/let, avoid var
Use arrow functions where appropriate
Add JSDoc comments
Example:
JavaScript
/**
 * Brief description.
 * @param {string} param1 - Description
 * @param {number} param2 - Description
 * @returns {boolean} Description
 */
function myFunction(param1, param2) {
  return true;
}
Testing
bash
# Run tests
npm test

# Lint and format
npm run lint
npm run format
C++ Development
Build
CMake (Recommended):

bash
mkdir build
cd build
cmake ..
make
Manual:

bash
g++ -std=c++17 -O2 -pthread -o tools/cpp/crypto_tools tools/cpp/crypto_tools.cpp
Code Style
Use modern C++ (C++17)
Follow Google C++ Style Guide
Use meaningful variable names
Add comments for complex logic
Compilation Flags
bash
# Development (debug info, warnings)
g++ -std=c++17 -g -Wall -Wextra -o output file.cpp

# Production (optimized)
g++ -std=c++17 -O2 -Wall -o output file.cpp

# With threading
g++ -std=c++17 -O2 -pthread -o output file.cpp
Testing Guidelines
Before Submitting PR
 Code passes linting
 All tests pass
 New features have tests
 Documentation is updated
 No security vulnerabilities
GitHub Actions
Automated checks will run on every push:

Linting (flake8, ESLint, clang-format)
Security scanning (Bandit, CodeQL)
Multi-version testing (Python 3.8-3.11)
C++ compilation across platforms
Documentation
Updating README
If adding new tools:

Add entry to tools table
Add usage examples
Update repository structure diagram
Add to CHANGELOG.md
Docstrings
All functions should have docstrings:

Python (Google style):

Python
def example(param: str) -> bool:
    """
    Brief description.
    
    Longer description if needed.
    
    Args:
        param: Parameter description
        
    Returns:
        Return value description
        
    Raises:
        ValueError: When something is wrong
    """
C++:

C++
/// Brief description of the function.
/// More detailed description if needed.
/// @param param Description of parameter
/// @return Description of return value
bool example(const std::string& param);
Release Process
Update version in code and package files
Update CHANGELOG.md
Create release branch: git checkout -b release/v1.0.0
Push and create PR
After merge, create GitHub release with tag
Update documentation
Common Issues
CMake not found
bash
sudo apt-get install cmake
# or
brew install cmake
Python import errors
bash
pip install --upgrade pip
pip install -r requirements.txt
Node modules issues
bash
rm -rf node_modules package-lock.json
npm install
C++ compilation errors
bash
# Check compiler version
g++ --version
# Ensure C++17 support
g++ -std=c++17 ...
Resources
Git Workflow
Python Style Guide
JavaScript Style Guide
C++ Style Guide
Semantic Versioning
