from scapy.all import sniff, wrpcap, TCP, IP, DNS 
from scapy.layers.http import HTTPRequest, HTTPResponse
from collections import defaultdict

# wre are going to store the packets for later use
packets = []

nb_packtes = defaultdict(int)


def manage_packet(pk):
    packets.append(pk)
    nb_packtes[pk.summary()] += 1

    print(pk.summary())

    #tcp
    if pk.haslayer(TCP):
        tcp_layer = pk.getlayer(TCP)
        print(f"[*] Source Port: {tcp_layer.sport}")
        print(f"[*] Destination Port: {tcp_layer.dport}")
        print(f"[*] TCP Flags: {tcp_layer.flags}")

    #IP
    if pk.haslayer(IP):
        ip_layer = pk.getlayer(IP)
        print(f"[*] Source IP: {ip_layer.src}")
        print(f"[*] Destination IP: {ip_layer.dst}")
    
    #http 
    if pk.haslayer(HTTPRequest):
        http_layer = pk.getlayer(HTTPRequest)
        print(f"[*] HTTP Method: {http_layer.Method}")
        print(f"[*] HTTP Host: {http_layer.Host}")
        print(f"[*] HTTP Path: {http_layer.Path}")


    #dns
    if pk.haslayer(DNS):
        dns_layer = pk.getlayer(DNS)
        print(f"[*] DNS Qname: {dns_layer.qd.qname}")

def analyse(interface, filter=None):
    print("[*] Sniffing on %s" % interface)

    sniff(prn=manage_packet, store=False, count=0, iface=interface, filter=filter)

    print("[*] Done capturing packets")
    print(f"[*] Final Packet Counts: {nb_packtes}")


#saving packtes in a file
def save_packets(file):
    wrpcap(file, packets)
    print(f"[*] Packets saved in {file}")


if __name__ == "__main__" :
    interface = "lo"
    filter = "tcp"
    try:
        analyse(interface, filter)
    except Exception as e:
        print("[*] Sniffing stopped. Saving packets to file...")
        save_packets("captured_packets.pcap")
