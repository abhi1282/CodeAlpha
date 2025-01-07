from scapy.all import sniff, IP, TCP, UDP, ARP

def process_packet(packet):
    print("\n" + "-" * 60)  

    if packet.haslayer(IP):
        print("[ 🟢 IP PACKET ]")
        print(f"  🌐 Source IP:       {packet[IP].src}")
        print(f"  🌐 Destination IP:  {packet[IP].dst}")
        print(f"  🔗 Protocol:        {packet[IP].proto}")


        if packet.haslayer(TCP):
            print(f"  [ 🔵 TCP SEGMENT ]")
            print(f"    🛠 Source Port:    {packet[TCP].sport}")
            print(f"    🛠 Destination Port: {packet[TCP].dport}")
            print(f"    🚩 Flags:          {packet[TCP].flags}")


        elif packet.haslayer(UDP):
            print(f"  [ 🟡 UDP PACKET ]")
            print(f"    📌 Source Port:    {packet[UDP].sport}")
            print(f"    📌 Destination Port: {packet[UDP].dport}")


    elif packet.haslayer(ARP):
        print("[ 🔴 ARP PACKET ]")
        print(f"  🖧 Source:          {packet[ARP].psrc}")
        print(f"  🖧 Destination:     {packet[ARP].pdst}")


    else:
        print("[ ⚪ OTHER PACKET ]")
        print(packet.summary())  



print("Starting the network sniffer... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False) 
