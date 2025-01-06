from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
   
    devices = []
    try:
       
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

       
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

        for sent, received in answered_list:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    except Exception as e:
        print(f"Error scanning the network: {e}")

    return devices

if __name__ == "__main__":
    print("Scanning the network for connected devices...")
   
    ip_range = "192.168.1.0/24"
    connected_devices = scan_network(ip_range)

    print(f"Found {len(connected_devices)} device(s) connected to the network:")
    for idx, device in enumerate(connected_devices, start=1):
        print(f"{idx}. IP: {device['ip']}, MAC: {device['mac']}")
