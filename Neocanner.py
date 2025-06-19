import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

# Configuration
ip_range = "192.168.1.0/24"
ports_to_scan = [22, 80, 443]

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect((str(ip), port))
            print(f"[+] {ip}:{port} is OPEN")
    except:
        pass

def scan_host(ip):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect((str(ip), 80))
            print(f"[+] Host {ip} is LIVE")
            for port in ports_to_scan:
                scan_port(ip, port)
    except:
        pass

def main():
    print("[*] Starting Network Scan...")
    network = ipaddress.ip_network(ip_range, strict=False)
    with ThreadPoolExecutor(max_workers=100) as executor:
        for ip in network.hosts():
            executor.submit(scan_host, ip)

if __name__ == "__main__":
    main()
