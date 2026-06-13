# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-13

### Added
- Complete repository restructuring with proper directory organization
- Python tools: port_scanner.py, hash_identifier.py, subdomain_enum.py
- JavaScript tools: payload_generator.js, recon.js
- C++ tools: crypto_tools.cpp, port_scanner.cpp
- Comprehensive documentation (README, tools/README.md)
- GitHub Actions CI/CD pipelines:
  - Automated linting (Python, JavaScript, C++)
  - Security scanning (Bandit, CodeQL, dependency checks)
  - Multi-version testing and builds
- Dependency management:
  - requirements.txt for Python
  - package.json for Node.js
  - CMakeLists.txt for C++ builds
- MIT License
- .gitignore for all supported languages
- Contributing guidelines
- Security policy
- Code of conduct
- Ethical use guidelines

### Changed
- Fixed file naming inconsistencies (removed spaces in filenames)
- Organized tools into language-specific subdirectories
- Removed duplicate files
- Enhanced README with proper structure

### Fixed
- Resolved missing tools/ directory structure
- Fixed configuration file extensions (.yml vs .tml)
- Aligned documentation with actual repository structure

---

## [0.1.0] - Initial Release

### Added
- Initial project setup
- Basic security tools and notes
