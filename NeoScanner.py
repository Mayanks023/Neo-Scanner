import socket
import sys
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
import random


# Configuration
def banner():
    colors = [Fore.RED, Fore.GREEN, Fore.BLUE, Fore.CYAN, Fore.MAGENTA, Fore.YELLOW]
    banner_text = r"""
███╗   ██╗███████╗ ██████╗   ███████╗  ██████╗ █████╗ ███╗   ██╗███╗    ██╗███████╗██████╗ 
████╗  ██║██╔════╝██╔═══██║  ██╔════╝ ██╔════╝██╔══██╗████╗  ██║████╗   ██║██╔════╝██╔══██╗
██╔██╗ ██║█████╗  ██║   ██║  ███████╗ ██║     ███████║██╔██╗ ██║██╔██╗  ██║█████╗  ██████╔╝
██║╚██╗██║██╔══╝  ██║   ██║       ██║ ██║     ██╔══██║██║╚██╗██║██║╚██╗ ██║██╔══╝  ██╔══██╗
██║ ╚████║███████╗╚██████╔╝  ███████║ ╚██████╗██║  ██║██║ ╚████║██║  ╚████║███████╗██║  ██║
╚═╝  ╚═══╝╚══════╝ ╚═════╝   ╚══════╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝   ╚═══╝╚══════╝╚═╝  ╚═╝
                               [ Fast Python Port Scanner ]
"""
    for line in banner_text.splitlines():
        if line.strip():
            print(random.choice(colors) + line)
        else:
            print(line)

def scan_port(ip, port, open_ports):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect((str(ip), port))
            print(f"    [+] Port {port} is OPEN")
            open_ports.append(port)
    except:
        pass

import time  # 🔁 Also make sure 'import time' is at the top

# Common port-to-service map
port_services = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds", 3306: "mysql", 3389: "rdp"
}

def scan_host(ip, ports):
    print(f"\nScan report for {ip}")
    start_time = time.time()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, 80))
            latency = round((time.time() - start_time), 2)
            print(f"Host is up ({latency}s latency).")
    except:
        print("Host is down or blocking ping probes.")
        return

    open_ports = []
    filtered_ports = []

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    service = port_services.get(port, "unknown")
                    open_ports.append((port, service))
                elif result in (111, 113):
                    filtered_ports.append((port, "filtered"))
        except:
            pass

    total = len(ports)
    closed = total - len(open_ports) - len(filtered_ports)

    if open_ports:
        print("\nPORT     STATE     SERVICE")
        for port, service in open_ports:
            print(f"{str(port).ljust(8)}open      {service}")
    if filtered_ports:
        for port, _ in filtered_ports:
            print(f"{str(port).ljust(8)}filtered  {port_services.get(port, 'unknown')}")

    if closed > 0:
        print(f"\nNot shown: {closed} closed tcp ports (reset)")

    print(f"\nScan done: 1 host scanned in {round(time.time() - start_time, 2)} seconds")


    
def main():
    banner()
    print("\n=== NeoScanner (by The_Mayanks) ===\n")

    if len(sys.argv) < 2:
        print("Usage: python3 Neoscanner.py <IP/CIDR/hostname> [port1,port2,...]")
        sys.exit(1)

    target = sys.argv[1]

    if len(sys.argv) >= 3:
        ports = [int(p.strip()) for p in sys.argv[2].split(",") if p.strip().isdigit()]
    else:
        print("[*] No ports specified. Scanning all 65535 ports (this may take time).")
        ports = list(range(1, 65536))


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
            resolved = socket.gethostbyname_ex(target)
            aliases = resolved[2]
            print(f"[*] Scan report for {target} ({ip})")
            if len(aliases) > 1:
                print(f"[*] Other addresses for {target} (not scanned): {', '.join(aliases[1:])}")
            print(f"[*] Ports to scan: {ports}")
            scan_host(ip, ports)

        except socket.gaierror:
            print("[-] Invalid hostname or IP address.")



if __name__ == "__main__":
    main()
