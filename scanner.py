from scanner_func import Scanners
from scapy.all import IP, ICMP, sr1, TCP, RandShort
import ipaddress


scanner = Scanners()


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

    if option == 1:         # option to ping the target ip
        ip = input("Enter the ip you want to ping: ")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print("invalid IP address")
            continue

        scanner.ping_host(ip)

    elif option == 2:       # option to scan for open ports wthin a range 
        
        ip = input("Enter the ip you want to ping: ")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print("invalid IP address")
            continue

        starting_range = int(input("Enter the staring value: "))
        ending_range = int(input("Enter the ending range: "))

        scanner.scan_ports_multithreading(ip, range(starting_range, ending_range + 1))

    elif option == 3:       # option to scan an individual port

        ip = input("Enter the ip you want to scan: ")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print("invalid IP address")
            continue

        port = int(input("Enter the port you want to scan: "))
        if port < 1 or port > 65535:
            print("Port number must be between 1 and 65535")
            continue

        open_ports = []

        scanner.scan_port(ip, port, open_ports)

        if open_ports:
            print(f"Port {port} is open on {ip}")
        else:
            print(f"Port {port} is closed on {ip}")

    elif option == 4:       # option to scan a port bypassing a firewall

        ip = input("Enter the ip you want to scan: ")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print("invalid IP address")
            continue

        starting_range = int(input("Enter the staring value: "))
        ending_range = int(input("Enter the ending range: "))

        scanner.syn_scan_multithreading(ip, range(starting_range, ending_range))

    elif option == 5:
        exit(1)