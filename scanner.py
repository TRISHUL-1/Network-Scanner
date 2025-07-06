from scapy.all import IP, ICMP, sr1, TCP, RandShort
import sys
import time
import socket
import ipaddress
import threading

def ping_host(ip):
    print(f"Pinging {ip}...")
    icmp = IP(dst = ip)/ICMP()
    resp = sr1(icmp, timeout=2, verbose=0)
    if resp:
        print(f"{ip} is alive")
    else:
        print(f"{ip} is down")

def scan_port(ip, port, open_ports):
    s = socket.socket()
    s.settimeout(1)
    try:
        s.connect((ip, port))
        open_ports.append(port)
    except:
        pass
    s.close()

def scan_ports_multithreading(ip, ports):
    print(f"Scanning for ports on {ip} (20-1024)...")
    open_ports = []
    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(ip, port, open_ports))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    
    print(f"Open ports for {ip}: {open_ports}")

def syn_scan(target_ip, ports, delay=0.5):
    print(f"Performing SYN scan on {target_ip}...")

    for port in ports:
        src_port = RandShort()
        pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="S")

        response = sr1(pkt, timeout=2, verbose=0)

        if response is None:
            print(f"Port {port}: No response (filtered or dropped)")
        elif response.haslayer(TCP):
            if response[TCP].flags == 0x12:
                print(f"Port {port}: OPEN")
                rst_pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="R")
                sr1(rst_pkt, timeout=2, verbose=0)
            elif response[TCP].flags == 0x14:
                print(f"Port {port}: CLOSED")
            else:
                print(f"Port {port}: TCP response with flags {response.getlayer(TCP).flags}")
        else:
            print(f"Port {port}: Unexpected response")

        time.sleep(delay)


banner = """
 ██████   █████ ███████████  █████████    █████████  ██████   █████
░░██████ ░░███ ░█░░░███░░░█ ███░░░░░███  ███░░░░░███░░██████ ░░███ 
 ░███░███ ░███ ░   ░███  ░ ░███    ░░░  ███     ░░░  ░███░███ ░███ 
 ░███░░███░███     ░███    ░░█████████ ░███          ░███░░███░███ 
 ░███ ░░██████     ░███     ░░░░░░░░███░███          ░███ ░░██████ 
 ░███  ░░█████     ░███     ███    ░███░░███     ███ ░███  ░░█████ 
 █████  ░░█████    █████   ░░█████████  ░░█████████  █████  ░░█████
░░░░░    ░░░░░    ░░░░░     ░░░░░░░░░    ░░░░░░░░░  ░░░░░    ░░░░░ 
                                                                   
                                                                   
                                                                   """

print(banner)

while True:
    print(2 * "\n")
    print("What do you want to do ?")
    print("1. Ping Host")
    print("2. Scan for Open Ports")
    print("3. Scan a particular port")
    print("4. Bypass a Firewall")
    print("5. Exit")
    option = int(input(">> "))

    if option == 1:
        ip = input("Enter the ip you want to ping: ")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print("invalid IP address")
            exit(1)

        ping_host(ip)

    elif option == 2:
        
        ip = input("Enter the ip you want to ping: ")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print("invalid IP address")
            exit(1)

        starting_range = int(input("Enter the staring value: "))
        ending_range = int(input("Enter the ending range: "))

        scan_ports_multithreading(ip, range(starting_range, ending_range + 1))
    elif option == 3:

        ip = input("Enter the ip you want to scan: ")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print("invalid IP address")
            exit(1)

        port = int(input("Enter the port you want to scan: "))
        if port < 1 or port > 65535:
            print("Port number must be between 1 and 65535")
            exit(1)

        open_ports = []
        scan_port(ip, port, open_ports)
        if open_ports:
            print(f"Port {port} is open on {ip}")
        else:
            print(f"Port {port} is closed on {ip}")

    elif option == 4:
        ip = input("Enter the ip you want to scan: ")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print("invalid IP address")
            exit(1)

        starting_range = int(input("Enter the staring value: "))
        ending_range = int(input("Enter the ending range: "))

        syn_scan(ip, range(starting_range, ending_range))

    elif option == 5:
        exit(1)