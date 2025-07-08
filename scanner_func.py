from scapy.all import IP, ICMP, sr1, TCP, RandShort
import time
import socket
import threading


class Scanners:

    def __init__(self):
        pass



    def ping_host(self, ip):

        '''Pings the target IP address using ICMP packets'''

        print(f"Pinging {ip}...")
        icmp = IP(dst =ip)/ICMP()
        resp = sr1(icmp, timeout=2, verbose=0)
        if resp:
            print(f"{ip} is alive")
        else:
            print(f"{ip} is down")



    def scan_port(self, ip, port, open_ports):

        '''Scans for all the open ports for a target IP within a specified range'''

        try:
            with socket.socket() as s :
                s.settimeout(1)
                s.connect((ip, port))
                open_ports.append(port)
        except:
            pass
        s.close()



    def scan_ports_multithreading(self, ip, ports):

        '''Scans for all the open ports for a target IP within a specified range using multithreading for faster results'''

        print(f"Scanning for ports on {ip} ({ports[0]}-{ports[-1] -1})...")
        open_ports = []
        threads = []
        for port in ports:
            try:
                t = threading.Thread(target=self.scan_port, args=(ip, port, open_ports))
                threads.append(t)
                t.start()
            except Exception as e:
                print(f"Error occured: {e}")

        for t in threads:
            t.join()
        
        print(f"Open ports for {ip}: {open_ports}")



    def syn_scan(self, target_ip, port,open_ports, delay=0.1):

        '''Scans for open ports using TCP packets (effective to break firewalls)'''
    
        src_port = RandShort()
        pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="S")

        response = sr1(pkt, timeout=2, verbose=0)

        if response is None:
            open_ports[port] = "No Response (filtered or dropped)"      # cant bypass firewall

        elif response.haslayer(TCP):
            if response[TCP].flags == 0x12:         # bypassed and port is OPEN
                open_ports[port] = "OPEN"           
                rst_pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="R")
                sr1(rst_pkt, timeout=2, verbose=0)

        else:   # error occured
            open_ports[port] = "Unexpected response"

        time.sleep(delay)



    def syn_scan_multithreading(self, target_ip, ports):
    
        '''Scans for open ports using TCP packets (effective to break firewalls) [uses multithreading]'''

        print(f"Performing SYN scan on {target_ip}...")

        open_ports = {}
        threads = []

        for port in ports:
            t = threading.Thread(target= self.syn_scan, args=(target_ip, port, open_ports))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        for port in open_ports:
            print(f"{port}: {open_ports[port]}")