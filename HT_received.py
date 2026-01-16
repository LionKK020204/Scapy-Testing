#!/usr/bin/env python3
"""
HT_received.py - improved server
- Listen on IPv6 (supports link-local with scope id).
- Verify HMAC signature, dispatch to handlers.
- Return JSON response to client.
- Handlers call system 'ip' or 'systemctl' commands (Linux).
"""
import socket
import json
import subprocess
import shlex
import hmac
import hashlib
import sys
import os
from typing import Dict

# ===== Configuration =====
LISTEN_IPv6 = "fe80::a26d:40be:1318:c596"   # server's IPv6 (if link-local, must supply iface below)
LISTEN_PORT = 13344
BUFFER_SIZE = 8192
SHARED_SECRET_KEY = b"MySuperSecretKeyForLGCars_v2"
SERVER_IFACE = "eth0"   # if LISTEN_IPv6 is link-local, set interface name here (ex: "eth0")
# =========================

def run_shell_command(command_str, timeout=20):
    """Run a shell command safely and return dict with status/output."""
    try:
        # Default: avoid shell=True unless special chars
        use_shell = False
        if any(tok in command_str for tok in ["|", ">", "&&", ";"]):
            use_shell = True

        if use_shell:
            proc = subprocess.run(command_str, shell=True, capture_output=True, text=True, timeout=timeout)
        else:
            proc = subprocess.run(shlex.split(command_str), capture_output=True, text=True, timeout=timeout)

        output = (proc.stdout or "") + (proc.stderr or "")
        status = "success" if proc.returncode == 0 else "error"
        return {"status": status, "output": output.strip(), "rc": proc.returncode}
    except Exception as e:
        return {"status": "error", "output": str(e), "rc": -1}

# --- Action handlers ---
def get_config_action(params):
    iface = params.get("iface", "eth0")
    return run_shell_command(f"ip addr show dev {iface}")

def set_ipv6_action(params):
    ip = params.get("ip")
    prefix = params.get("prefix", 64)
    iface = params.get("iface", "eth0")
    if not ip:
        return {"status": "error", "output": "Missing 'ip' parameter."}
    run_shell_command(f"ip -6 addr flush dev {iface}")
    return run_shell_command(f"ip -6 addr add {ip}/{prefix} dev {iface}")

def set_ipv4_action(params):
    ip = params.get("ip")
    prefix = params.get("prefix", 24)
    iface = params.get("iface", "eth0")
    if not ip:
        return {"status": "error", "output": "Missing 'ip' parameter."}
    run_shell_command(f"ip -4 addr flush dev {iface}")
    return run_shell_command(f"ip addr add {ip}/{prefix} dev {iface}")

def set_mac_action(params):
    mac = params.get("mac")
    iface = params.get("iface", "eth0")
    if not mac:
        return {"status": "error", "output": "Missing 'mac' parameter."}
    service_name = "change-mac-on-boot.service"
    service_path = f"/etc/systemd/system/{service_name}"
    service_content = f"""[Unit]
Description=One-time script to change MAC address for {iface}
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip link set dev {iface} address {mac}
ExecStartPost=/usr/bin/systemctl disable {service_name}

[Install]
WantedBy=multi-user.target
"""
    try:
        with open(service_path, "w") as f:
            f.write(service_content)
        enable = run_shell_command(f"systemctl enable {service_name}")
        if enable.get("status") != "success":
            return {"status": "error", "output": f"Failed to enable service: {enable.get('output')}"}
        # Reboot now
        run_shell_command("shutdown -r now")
        return {"status": "success", "output": f"MAC change scheduled and system will reboot."}
    except PermissionError:
        return {"status": "error", "output": "Permission denied. Run server as root for MAC change."}
    except Exception as e:
        return {"status": "error", "output": f"Failed to schedule mac change: {e}"}

def set_vlan_action(params):
    vlan_id = params.get("vlan_id")
    iface = params.get("iface", "eth0")
    if vlan_id is None:
        return {"status": "error", "output": "Missing 'vlan_id'."}
    # Remove old subinterface (ignore errors)
    run_shell_command(f"ip link del {iface}.{vlan_id} 2>/dev/null")
    if vlan_id == 0:
        return {"status": "success", "output": "VLAN removed (untagged)."}
    return run_shell_command(f"ip link add link {iface} name {iface}.{vlan_id} type vlan id {vlan_id}")

COMMAND_HANDLERS = {
    "get_config": get_config_action,
    "set_ipv6": set_ipv6_action,
    "set_ipv4": set_ipv4_action,
    "set_mac": set_mac_action,
    "set_vlan": set_vlan_action,
}

def verify_and_dispatch(data_json: Dict):
    # verify signature
    try:
        signature = data_json["signature"]
        payload = data_json["payload"]
    except KeyError:
        return {"status": "error", "output": "Missing signature or payload."}

    payload_str = json.dumps(payload, sort_keys=True).encode('utf-8')
    expected = hmac.new(SHARED_SECRET_KEY, payload_str, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return {"status": "error", "output": "Invalid signature."}

    command = payload.get("command")
    params = payload.get("params", {})
    handler = COMMAND_HANDLERS.get(command)
    if not handler:
        return {"status": "error", "output": f"Unknown command '{command}'."}

    # dispatch
    return handler(params)

def run_server():
    print("=== Remote Control Protocol Server ===")
    print(f"Listening on [{LISTEN_IPv6}]:{LISTEN_PORT} (iface={SERVER_IFACE})")

    # Create IPv6 socket
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # If link-local, include scope id when binding
    bind_tuple = (LISTEN_IPv6, LISTEN_PORT)
    if LISTEN_IPv6.lower().startswith("fe80"):
        if_index = socket.if_nametoindex(SERVER_IFACE)
        bind_tuple = (LISTEN_IPv6, LISTEN_PORT, 0, if_index)

    try:
        s.bind(bind_tuple)
        s.listen(5)
    except OSError as e:
        print(f"[FATAL] Could not bind/listen: {e}")
        sys.exit(1)

    try:
        while True:
            print("\nWaiting for incoming connection...")
            conn, addr = s.accept()
            with conn:
                peer_ip = addr[0]
                peer_port = addr[1]
                print(f"Connection from [{peer_ip}]:{peer_port}")
                try:
                    data_raw = conn.recv(BUFFER_SIZE)
                    if not data_raw:
                        print("Empty payload received.")
                        continue
                    try:
                        data_json = json.loads(data_raw.decode('utf-8'))
                    except json.JSONDecodeError:
                        resp = {"status": "error", "output": "Invalid JSON."}
                        conn.sendall(json.dumps(resp).encode('utf-8'))
                        continue

                    # Verify & run
                    result = verify_and_dispatch(data_json)
                    # Send response back as JSON
                    conn.sendall(json.dumps(result).encode('utf-8'))
                    print("Processed request; response sent.")
                except Exception as e:
                    print(f"Error handling connection: {e}")
    except KeyboardInterrupt:
        print("Shutting down server.")
    finally:
        s.close()

if __name__ == "__main__":
    run_server()
