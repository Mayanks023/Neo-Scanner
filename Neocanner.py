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

def scan_host(ip, ports):
    print(f"\n[*] Scanning host: {ip}")
    open_ports = []
    for port in ports:
        scan_port(ip, port, open_ports)

    if not open_ports:
        print("    [-] No open ports found.")

    
ddef main():
    print("\n=== NeoScanner (Modified) ===\n")

    if len(sys.argv) < 2:
        print("Usage: python3 Neoscanner.py <IP/CIDR/hostname> [port1,port2,...]")
        sys.exit(1)


if __name__ == "__main__":
    main()
