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
