# API Documentation

## Cybersec Toolkit API Reference

### Python Tools

#### port_scanner.py

```python
from tools.python.port_scanner import scan_ports, check_port

# Scan multiple ports
open_ports = await scan_ports(
    host='example.com',
    ports=[22, 80, 443, 3306, 5432],
    timeout=5,
    max_concurrent=100
)
