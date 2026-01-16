
import socket
import json
import hmac
import hashlib
from colorama import Fore, Style, init
from scapy.all import Ether, IPv6, TCP, Dot1Q, sendp

# Khởi tạo colorama
init(autoreset=True)

# =======================================================
# === Config Client (Windows) ===
# =======================================================
PI_HOST_IPv6 = "fe80::da3a:ddff:fee5:31b7"   # IPv6 Raspberry Pi
PI_CONTROL_PORT = 13344
PI_SCOPE_ID = 14                             # Scope ID Ethernet trên Windows
SHARED_SECRET_KEY = b"MySuperSecretKeyForLGCars_v1"

# Tương tự md_fw_declare
IFACE_DEFAULT = "Ethernet"
VLAN_ID = 5
VALID_SPORT = 13344
VALID_DPORT = 13344
payload_default = "Default"

def send_structured_payload(payload_json, show_output=True):
    try:
        payload_str = json.dumps(payload_json, sort_keys=True).encode("utf-8")
        signature = hmac.new(SHARED_SECRET_KEY, payload_str, hashlib.sha256).hexdigest()
        final_package = {"payload": payload_json, "signature": signature}
        final_package_str = json.dumps(final_package)

        if show_output:
            print(f"\n{Fore.CYAN}--- Sending RPC to [{PI_HOST_IPv6}%{PI_SCOPE_ID}]:{PI_CONTROL_PORT} ---{Style.RESET_ALL}")
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((PI_HOST_IPv6, PI_CONTROL_PORT, 0, PI_SCOPE_ID))
            s.sendall(final_package_str.encode("utf-8"))

            # Đọc phản hồi
            response = s.recv(8192).decode("utf-8")
            if show_output:
                try:
                    response_json = json.loads(response)
                    print(f"{Fore.GREEN}📩 Response from server:{Style.RESET_ALL}")
                    print(json.dumps(response_json, indent=4, ensure_ascii=False))
                except Exception:
                    print(f"{Fore.RED}📩 Raw Response:{Style.RESET_ALL} {response}")
            return True
    except Exception as e:
        if show_output:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Could not send RPC: {e}")
        return False

# =======================================================
# === Hàm gửi gói raw đơn giản (theo mẫu md_fw_declare)
# =======================================================

def send_raw_custom_ipv6(src_ipv6, iface=IFACE_DEFAULT):
    """
    Tạo gói theo mẫu md_fw_declare:
    Ether()/Dot1Q(vlan=VLAN_ID)/IPv6(src=src_ipv6,dst=PI_HOST_IPv6)/TCP(sport=VALID_SPORT,dport=VALID_DPORT)/payload_default
    Gửi bằng sendp qua interface chỉ định.
    """
    try:
        dot1q = Dot1Q(vlan=VLAN_ID)
        pkt = Ether() / dot1q / IPv6(src=src_ipv6, dst=PI_HOST_IPv6) / TCP(sport=VALID_SPORT, dport=VALID_DPORT) / payload_default
        print(f"{Fore.CYAN}--- Sending raw test packet with custom src IPv6 {src_ipv6} -> {PI_HOST_IPv6} via {iface} ---{Style.RESET_ALL}")
        sendp(pkt, iface=iface, verbose=1)
        print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Packet sent. Kiểm tra trên Raspberry Pi (tcpdump) để xác nhận." )
        return True
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to send raw packet: {e}")
        return False

# =======================================================
# === Menu (giữ logic gốc, thêm mục 6 đơn giản)
# =======================================================

def main_menu():
    while True:
        print(f"\n{Fore.YELLOW}===== Remote Pi Configurator (Windows Client) ====={Style.RESET_ALL}")
        print("1. Get current network config (eth0)")
        print("2. Set new IPv6 address for eth0")
        print("3. Set new MAC address for eth0")
        print("4. Set VLAN ID for eth0 (0 to remove VLAN)")
        print("5. Set new IPv4 address for eth0")
        print("6. Send test packet with custom source IPv6 (chỉ nhập IPv6)")
        print("0. Exit")
        choice = input(Fore.CYAN + "Enter your choice: " + Style.RESET_ALL).strip()

        payload = None

        if choice == "1":
            payload = {"command": "get_config", "params": {"iface": "eth0"}}
        elif choice == "2":
            ip = input("  Enter new IPv6 address: ").strip()
            payload = {"command": "set_ipv6", "params": {"ip": ip}}
        elif choice == "3":
            mac = input("  Enter new MAC address: ").strip()
            payload = {"command": "set_mac", "params": {"mac": mac}}
        elif choice == "4":
            try:
                vlan_id = int(input("  Enter new VLAN ID (0 to remove): ").strip())
                payload = {"command": "set_vlan", "params": {"vlan_id": vlan_id}}
            except ValueError:
                print(f"{Fore.RED}Invalid VLAN ID. Please enter a number.{Style.RESET_ALL}")
                continue
        elif choice == "5":
            ip = input("  Enter new IPv4 address: ").strip()
            try:
                prefix = int(input("  Enter prefix length (e.g., 24): ").strip())
            except ValueError:
                print(f"{Fore.RED}Invalid Prefix.{Style.RESET_ALL}")
                continue
            payload = {"command": "set_ipv4", "params": {"ip": ip, "prefix": prefix}}
        elif choice == "6":
            src_ipv6 = input("  Enter custom source IPv6: ").strip()
            iface = input(f"  Enter interface name (default '{IFACE_DEFAULT}'): ").strip() or IFACE_DEFAULT
            send_raw_custom_ipv6(src_ipv6, iface=iface)
            print("Gợi ý: Trên Raspberry Pi chạy: sudo tcpdump -n -i eth0 ip6 and port 13344 để kiểm tra gói")
            continue
        elif choice == "0":
            print(f"{Fore.MAGENTA}👋 Exiting client...{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}Invalid choice.{Style.RESET_ALL}")
            continue

        if payload:
            send_structured_payload(payload)

if __name__ == "__main__":
    main_menu()

