#!/usr/bin/env python3
import socket
import subprocess

LISTEN_IP = "0.0.0.0"
PORT = 13344
BUF_SIZE = 1024

def change_vlan(iface, vlan_id):
    try:
        # Xoá VLAN cũ nếu tồn tại
        subprocess.run(
            ["ip", "link", "del", f"{iface}.{vlan_id}"],
            stderr=subprocess.DEVNULL
        )

        # Tạo VLAN mới
        subprocess.check_call(
            ["ip", "link", "add", "link", iface, "name", f"{iface}.{vlan_id}", "type", "vlan", "id", str(vlan_id)]
        )

        subprocess.check_call(["ip", "link", "set", f"{iface}.{vlan_id}", "up"])
        return f"OK: VLAN {vlan_id} created on {iface}"

    except subprocess.CalledProcessError as e:
        return f"ERROR: {e}"

def run_server():
    print("[*] VLAN control server running...")
    print(f"[*] Listening on port {PORT}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((LISTEN_IP, PORT))
    s.listen(5)

    while True:
        conn, addr = s.accept()
        with conn:
            print(f"[+] Connection from {addr}")

            data = conn.recv(BUF_SIZE)
            if not data:
                continue

            payload = data.decode(errors="ignore").strip()
            print(f"[>] Payload received: {payload}")

            # Format: CMD=SET_VLAN;IFACE=eth0;VLAN=5
            try:
                parts = dict(x.split("=") for x in payload.split(";"))
                iface = parts["IFACE"]
                vlan = int(parts["VLAN"])

                result = change_vlan(iface, vlan)
            except Exception as e:
                result = f"INVALID PAYLOAD: {e}"

            print(f"[!] {result}")
            conn.sendall(result.encode())

if __name__ == "__main__":
    run_server()
