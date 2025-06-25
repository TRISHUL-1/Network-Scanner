from scapy.all import *
import socket

def ping_host(ip):
    icmp = IP(dst = ip)/ICMP()
    resp = sr1(icmp, timeout=2, verbose=0)
    if resp:
        print(f"{ip} is alive")
    else:
        print(f"{ip} is down")

def scan_ports(ip, ports):
    for port in ports:
        s = socket.socket()
        s.settimeout(1)
        try:
            s.connect(ip, port)
            print(f"Port {port} is open for {ip}")
        except:
            pass
        s.close()


ip = input("Enter the ip you want to ping: ")

ping_host(ip)

scan_ports(ip, range(20, 1025))