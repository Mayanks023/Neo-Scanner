import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

# Configuration
def scan_port(ip, port, open_ports):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect((str(ip), port))
            print(f"    [+] Port {port} is OPEN")
            open_ports.append(port)
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
