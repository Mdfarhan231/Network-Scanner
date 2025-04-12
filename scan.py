from scapy.all import ARP, Ether, srp

def scan_network(target_ip_range):
    # Create ARP request packet
    arp = ARP(pdst=target_ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC
    packet = ether/arp

    print(f"Scanning network: {target_ip_range}...\n")

    # Send the packet and capture the response
    result = srp(packet, timeout=2, verbose=0)[0]

    # Parse results
    devices = []
    for sent, received in result:
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc
        })

    # Display results
    print("Available devices in the network:")
    print("IP" + " "*18 + "MAC")
    print("-"*40)
    for device in devices:
        print(f"{device['ip']:20} {device['mac']}")
        
# Example usage (update the IP range according to your subnet)
scan_network("192.168.0.1/24")
