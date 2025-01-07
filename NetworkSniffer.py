from scapy.all import sniff, IP, TCP, UDP, ARP

# Function to process captured packets
def process_packet(packet):
    print("\n" + "-" * 60)  # Separator for better readability

    # Check for IP layer and display details
    if packet.haslayer(IP):
        print("[ 🟢 IP PACKET ]")
        print(f"  🌐 Source IP:       {packet[IP].src}")
        print(f"  🌐 Destination IP:  {packet[IP].dst}")
        print(f"  🔗 Protocol:        {packet[IP].proto}")

        # If TCP layer is present, display TCP details
        if packet.haslayer(TCP):
            print(f"  [ 🔵 TCP SEGMENT ]")
            print(f"    🛠 Source Port:    {packet[TCP].sport}")
            print(f"    🛠 Destination Port: {packet[TCP].dport}")
            print(f"    🚩 Flags:          {packet[TCP].flags}")

        # If UDP layer is present, display UDP details
        elif packet.haslayer(UDP):
            print(f"  [ 🟡 UDP PACKET ]")
            print(f"    📌 Source Port:    {packet[UDP].sport}")
            print(f"    📌 Destination Port: {packet[UDP].dport}")

    # If ARP layer is detected
    elif packet.haslayer(ARP):
        print("[ 🔴 ARP PACKET ]")
        print(f"  🖧 Source:          {packet[ARP].psrc}")
        print(f"  🖧 Destination:     {packet[ARP].pdst}")

    # Other packet types
    else:
        print("[ ⚪ OTHER PACKET ]")
        print(packet.summary())  # Generic summary for unknown packets


# Start the network sniffer
print("Starting the network sniffer... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)  # Start sniffing packets
