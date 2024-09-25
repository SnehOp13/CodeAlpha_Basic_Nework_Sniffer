import subprocess
import re
import time
import psutil
from prettytable import PrettyTable
from colorama import Fore, Style
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to get the current MAC address of the system (Windows)
def get_current_mac(interface):
    try:
        output = subprocess.check_output("getmac").decode()
        for line in output.splitlines():
            if interface in line:
                return line.split()[1]  # MAC address is typically the second entry
    except Exception as e:
        print(f"Error getting MAC address: {e}")
        return None

# Function to get the current IP address of the system (Windows)
def get_current_ip(interface):
    try:
        output = subprocess.check_output("ipconfig").decode()
        adapter_found = False
        for line in output.splitlines():
            if interface in line:  # Look for the correct network adapter
                adapter_found = True
            if adapter_found and "IPv4" in line:  # IPv4 address line
                return re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line).group(0)
    except Exception as e:
        print(f"Error getting IP address: {e}")
        return None

# Function to get IP table of the system
def ip_table():
    addrs = psutil.net_if_addrs()
    t = PrettyTable([f"{Fore.GREEN}Interface", "Mac Address", f"IP Address{Style.RESET_ALL}"])
    for k, v in addrs.items():
        mac = get_current_mac(k)
        ip = get_current_ip(k)
        if ip and mac:
            t.add_row([k, mac, ip])
        elif mac:
            t.add_row([k, mac, f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
        elif ip:
            t.add_row([k, f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}", ip])
    print(t)

# Packet callback function to process sniffed packets
def packet_callback(packet):
    packet_details = f"{Fore.CYAN}Packet Details:{Style.RESET_ALL}\n"

    if IP in packet:
        packet_details += f"{Fore.GREEN}IP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source IP: {packet[IP].src} -> Destination IP: {packet[IP].dst}\n"
        packet_details += f"ID: {packet[IP].id} ; Version: {packet[IP].version} ; Length: {packet[IP].len} ; Flags: {packet[IP].flags}\n"
        packet_details += f"Protocol: {packet[IP].proto} ; TTL: {packet[IP].ttl} ; Checksum: {packet[IP].chksum}\n"

    if TCP in packet:
        packet_details += f"{Fore.YELLOW}TCP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source Port: {packet[TCP].sport} -> Destination Port: {packet[TCP].dport}\n"
        packet_details += f"Sequence Number: {packet[TCP].seq} ; Acknowledgment Number: {packet[TCP].ack}\n"
        packet_details += f"Window: {packet[TCP].window} ; Checksum: {packet[TCP].chksum}\n"
        packet_details += f"Flags: {packet[TCP].flags} ; Options: {packet[TCP].options}\n"

    if UDP in packet:
        packet_details += f"{Fore.YELLOW}UDP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source Port: {packet[UDP].sport}\n"
        packet_details += f"Destination Port: {packet[UDP].dport}\n"

    if ICMP in packet:
        packet_details += f"{Fore.YELLOW}ICMP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Type: {packet[ICMP].type}\n"
        packet_details += f"Code: {packet[ICMP].code}\n"

    print(packet_details)

# Main function to start the packet sniffer
def main():
    print(f"{Fore.BLUE}Welcome To Packet Sniffer{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[***] Please Start Arp Spoofer Before Using this Module [***]{Style.RESET_ALL}")
    try:
        ip_table()
        interface = input("[*] Please enter the interface name: ")
        print(get_current_ip(interface))
        print(get_current_mac(interface))
        print("[*] Sniffing Packets...")
        sniff(iface=interface, prn=packet_callback, store=False)
        print(f"{Fore.YELLOW}\n[*] Interrupt...{Style.RESET_ALL}")
        time.sleep(3)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Stopping the Sniffer...{Style.RESET_ALL}")
        time.sleep(3)

if __name__ == "__main__":
    main()
