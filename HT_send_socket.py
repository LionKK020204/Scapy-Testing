import socket
import json
import hmac
import hashlib
from colorama import Fore, Style, init

# Khởi tạo colorama
init(autoreset=True)

# =======================================================
# === Config Client (Windows) ===
# =======================================================
PI_HOST_IPv6 = "fe80::da3a:ddff:fee5:31b7"   # IPv6 Raspberry Pi
PI_CONTROL_PORT = 13344
PI_SCOPE_ID = 14                             # Scope ID Ethernet trên Windows
SHARED_SECRET_KEY = b"MySuperSecretKeyForLGCars_v1"

# =======================================================
# === Hàm gửi lệnh
# =======================================================
def send_structured_payload(payload_json):
    try:
        payload_str = json.dumps(payload_json, sort_keys=True).encode("utf-8")
        signature = hmac.new(SHARED_SECRET_KEY, payload_str, hashlib.sha256).hexdigest()
        final_package = {"payload": payload_json, "signature": signature}
        final_package_str = json.dumps(final_package)

        print(f"\n{Fore.CYAN}--- Sending command to [{PI_HOST_IPv6}%{PI_SCOPE_ID}]:{PI_CONTROL_PORT} ---{Style.RESET_ALL}")
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.connect((PI_HOST_IPv6, PI_CONTROL_PORT, 0, PI_SCOPE_ID))
            s.sendall(final_package_str.encode("utf-8"))

            # Đọc phản hồi
            response = s.recv(4096).decode("utf-8")
            try:
                response_json = json.loads(response)
                print(f"{Fore.GREEN}📩 Response from server:{Style.RESET_ALL}")
                print(json.dumps(response_json, indent=4, ensure_ascii=False))
            except:
                print(f"{Fore.RED}📩 Raw Response:{Style.RESET_ALL} {response}")

    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Could not send command: {e}")

# =======================================================
# === Menu
# =======================================================
def main_menu():
    while True:
        print(f"\n{Fore.YELLOW}===== Remote Pi Configurator (Windows Client) ====={Style.RESET_ALL}")
        print("1. Get current network config (eth0)")
        print("2. Set new IPv6 address for eth0")
        print("3. Set new MAC address for eth0")
        print("4. Set VLAN ID for eth0 (0 to remove VLAN)")
        print("5. Set new IPv4 address for eth0")
        print("0. Exit")
        choice = input(Fore.CYAN + "Enter your choice: " + Style.RESET_ALL)

        payload = None

        if choice == "1":
            payload = {"command": "get_config", "params": {"iface": "eth0"}}
        elif choice == "2":
            ip = input("  Enter new IPv6 address: ")
            payload = {"command": "set_ipv6", "params": {"ip": ip}}
        elif choice == "3":
            mac = input("  Enter new MAC address: ")
            payload = {"command": "set_mac", "params": {"mac": mac}}
        elif choice == "4":
            try:
                vlan_id = int(input("  Enter new VLAN ID (0 to remove): "))
                payload = {"command": "set_vlan", "params": {"vlan_id": vlan_id}}
            except ValueError:
                print(f"{Fore.RED}Invalid VLAN ID. Please enter a number.{Style.RESET_ALL}")
                continue
        elif choice == "5":
            ip = input("  Enter new IPv4 address: ")
            try:
                prefix = int(input("  Enter prefix length (e.g., 24): "))
            except ValueError:
                print(f"{Fore.RED}Invalid Prefix.{Style.RESET_ALL}")
                continue
            payload = {"command": "set_ipv4", "params": {"ip": ip, "prefix": prefix}}
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
