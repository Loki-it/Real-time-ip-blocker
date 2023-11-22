import json
from scapy.all import sniff
import subprocess
import time
from collections import defaultdict

with open('config.json', 'r') as file:
    config = json.load(file)

TCP_PPS_LIMIT = config["TCP_PPS_LIMIT"]
UDP_PPS_LIMIT = config["UDP_PPS_LIMIT"]
INTERFACE = config["INTERFACE"]

tcp_ip_counts = defaultdict(int)
udp_ip_counts = defaultdict(int)
blocked_ips = set()

def packet_callback(pkt):
    if pkt.haslayer("IP"):
        ip_src = pkt["IP"].src
        current_time = time.time()

        if pkt.haslayer("TCP"):
            tcp_ip_counts[ip_src] += 1
            pps = tcp_ip_counts[ip_src]
            if pps > TCP_PPS_LIMIT and ip_src not in blocked_ips:
                block_ip(ip_src)
                blocked_ips.add(ip_src)

        elif pkt.haslayer("UDP"):
            udp_ip_counts[ip_src] += 1
            pps = udp_ip_counts[ip_src]
            if pps > UDP_PPS_LIMIT and ip_src not in blocked_ips:
                block_ip(ip_src)
                blocked_ips.add(ip_src)

def block_ip(ip):
    subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
    print(f"IP {ip} bloccato.")

def reset_counts():
    while True:
        time.sleep(1)
        tcp_ip_counts.clear()
        udp_ip_counts.clear()

if __name__ == "__main__":
    try:
        import threading
        reset_thread = threading.Thread(target=reset_counts)
        reset_thread.daemon = True
        reset_thread.start()

        sniff(iface=INTERFACE, prn=packet_callback, filter="ip", store=0)

    except KeyboardInterrupt:
        print("Interrotto dall'utente.")
