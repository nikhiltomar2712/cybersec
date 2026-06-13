# 🚀 Advanced Features & Deployment

## Enterprise Setup

### Docker Production Deployment

```bash
# Build production image
docker build -f Dockerfile.prod -t cybersec:prod .

# Run with compose
docker-compose -f docker-compose.prod.yml up -d

# Check health
docker-compose -f docker-compose.prod.yml ps

# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cybersec-toolkit
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cybersec
  template:
    metadata:
      labels:
        app: cybersec
    spec:
      containers:
      - name: cybersec
        image: cybersec:prod
        ports:
        - containerPort: 8000
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"

CI/CD Pipeline
GitHub Actions Workflows
lint.yml - Code quality checks
security.yml - Security scanning
build.yml - Multi-platform builds
codeql-analysis.yml - SAST analysis
docker-build.yml - Container builds
performance.yml - Benchmarking
release.yml - Release automation
Pre-commit Hooks
bash
# Install
pip install pre-commit
pre-commit install

# Test
pre-commit run --all-files
Performance Optimization
Python Async Performance
Python
import asyncio
from tools.python.port_scanner import scan_ports

# Run multiple scans concurrently
async def scan_multiple_targets(targets):
    tasks = [
        scan_ports(target, list(range(1, 1025)))
        for target in targets
    ]
    results = await asyncio.gather(*tasks)
    return results
C++ Multithreading
C++
#include <thread>
#include <vector>

// Multi-threaded port scanning
void scanPortsThreaded(const std::string& host, int threads) {
    std::vector<std::thread> workers;
    for (int i = 0; i < threads; ++i) {
        workers.emplace_back([&host, i, threads]() {
            // Thread work
        });
    }
    for (auto& t : workers) t.join();
}
Monitoring & Logging
Structured Logging
Python
import logging
import json

class JSONFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            'timestamp': self.formatTime(record),
            'level': record.levelname,
            'message': record.getMessage(),
            'module': record.module,
        })

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)
Metrics Collection
Python
from prometheus_client import Counter, Histogram, start_http_server

scans_total = Counter('scans_total', 'Total scans', ['type'])
scan_duration = Histogram('scan_duration_seconds', 'Scan duration')

@scan_duration.time()
async def run_scan():
    # Scan logic
    scans_total.labels(type='port_scan').inc()
Security Hardening
Secrets Management
bash
# Use GitHub Secrets
echo ${{ secrets.API_KEY }} > .env.local

# Or use HashiCorp Vault
vault kv get secret/cybersec/api_keys
RBAC (Role-Based Access Control)
Python
from functools import wraps

def require_role(required_role):
    def decorator(func):
        @wraps(func)
        def wrapper(user, *args, **kwargs):
            if user.role != required_role:
                raise PermissionError(f"Requires {required_role} role")
            return func(user, *args, **kwargs)
        return wrapper
    return decorator

@require_role('admin')
def delete_scan(user, scan_id):
    # Implementation
    pass
API Gateway
Rate Limiting
Python
from ratelimit import limits
import time

@limits(calls=100, period=60)  # 100 calls per minute
async def scan_target(target):
    # Implementation
    pass
API Documentation
bash
# Generate with FastAPI/Swagger
pip install fastapi uvicorn

# Server runs at http://localhost:8000/docs
uvicorn api:app --reload
Scalability Patterns
Distributed Scanning
Python
import celery

app = celery.Celery('cybersec')
app.conf.broker_url = 'redis://localhost:6379'

@app.task
async def scan_target_async(target):
    return await scan_ports(target, list(range(1, 65536)))

# Queue scan
task = scan_target_async.delay('example.com')
Load Balancing
Nginx
# nginx.conf
upstream cybersec_backend {
    least_conn;
    server app1:8000;
    server app2:8000;
    server app3:8000;
}

server {
    location / {
        proxy_pass http://cybersec_backend;
    }
}
Monitoring Dashboard
Prometheus + Grafana
bash
# Run monitoring stack
docker-compose -f docker-compose.monitoring.yml up -d

# Access Grafana at http://localhost:3000
Troubleshooting Production
Health Checks
Python
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}

@app.get("/ready")
async def readiness_check():
    # Check dependencies
    return {"ready": True}
Log Analysis
bash
# Stream logs
docker-compose logs -f app

# Search logs
docker-compose logs app | grep ERROR
