python3 port_scanner.py <target> [--ports 1-1024] [--timeout 5]


# Scan common ports on localhost
python3 port_scanner.py 127.0.0.1 --ports 1-1024

# Scan specific target
python3 port_scanner.py scanme.nmap.org --ports 20-25,80,443,3306,5432

# Custom timeout
python3 port_scanner.py example.com --timeout 10


[*] Scanning 127.0.0.1:22 ...
[+] Port 22 (SSH) is OPEN
[+] Port 80 (HTTP) is OPEN
[-] Port 443 (HTTPS) is CLOSED


