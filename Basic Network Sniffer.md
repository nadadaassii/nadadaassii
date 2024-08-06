from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP

def packet_callback(packet):
    if IP in packet and TCP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        print(f"IP Packet: {ip_src} -> {ip_dst}")
        print(f"TCP Segment: {tcp_sport} -> {tcp_dport}")

# Capture les paquets et filtre manuellement les paquets TCP
packets = sniff(prn=packet_callback, count=10)

# Enregistrer les paquets capturés dans un fichier pcap
wrpcap("captured_packets.pcap", packets)
