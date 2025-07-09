from scapy.all import sniff, IP
from colorama import init, Fore
import datetime

init(autoreset=True)

def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        time = datetime.datetime.now().strftime('%H:%M:%S')

        print(Fore.CYAN + f"[{time}] " +
              Fore.YELLOW + f"SRC: {src} " +
              Fore.GREEN + f"→ DST: {dst} " +
              Fore.MAGENTA + f"| Protocol: {proto}")

# === Filter Menu ===
print(Fore.BLUE + "\n🌐 Network Sniffer with Filters")
print(Fore.WHITE + "Choose a filter option:")
print("1. All Traffic")
print("2. Only ICMP (ping)")
print("3. Only TCP")
print("4. Only HTTP (port 80)")

choice = input(Fore.LIGHTCYAN_EX + "Enter choice (1-4): ")

# Filter based on user input
if choice == '2':
    packet_filter = "icmp"
elif choice == '3':
    packet_filter = "tcp"
elif choice == '4':
    packet_filter = "tcp port 80"
else:
    packet_filter = ""

print(Fore.LIGHTBLUE_EX + f"\n🚀 Starting Sniffer with filter: '{packet_filter or 'None'}' ...\nPress Ctrl+C to stop.\n")

sniff(filter=packet_filter, prn=process_packet, store=0)
