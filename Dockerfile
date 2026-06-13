FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    g++ \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy package.json
COPY package.json package-lock.json* ./
RUN npm install

# Copy source code
COPY . .

# Compile C++ tools
RUN mkdir -p build && \
    cd build && \
    cmake .. && \
    make || true

EXPOSE 8000 5000 6379 5432

CMD ["bash"]
