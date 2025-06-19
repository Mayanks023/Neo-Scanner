import socket
import sys
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

def scan_host(ip, ports):
    print(f"\n[*] Scanning host: {ip}")
    open_ports = []
    for port in ports:
        scan_port(ip, port, open_ports)

    if not open_ports:
        print("    [-] No open ports found.")

    
def main():
    print("\n=== NeoScanner (by The_Mayanks) ===\n")

    if len(sys.argv) < 2:
        print("Usage: python3 Neoscanner.py <IP/CIDR/hostname> [port1,port2,...]")
        sys.exit(1)

    target = sys.argv[1]

    if len(sys.argv) >= 3:
        ports = [int(p.strip()) for p in sys.argv[2].split(",") if p.strip().isdigit()]
    else:
        ports = [22, 80, 443]

    try:
        # Check if it's a CIDR/network
        network = ipaddress.ip_network(target, strict=False)
        print(f"[*] Scanning network: {target}")
        print(f"[*] Ports to scan: {ports}")
        with ThreadPoolExecutor(max_workers=100) as executor:
            for ip in network.hosts():
                executor.submit(scan_host, ip, ports)
    except ValueError:
        # Else, it's a single host/domain
        try:
            ip = socket.gethostbyname(target)
            print(f"[*] Scanning host: {target} ({ip})")
            print(f"[*] Ports to scan: {ports}")
            scan_host(ip, ports)
        except socket.gaierror:
            print("[-] Invalid hostname or IP address.")



if __name__ == "__main__":
    main()
