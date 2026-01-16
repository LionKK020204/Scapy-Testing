import socket

HOST = "192.168.1.114"
PORT = 13344

payload = "SET_VLAN eth0 5"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.sendall(payload.encode())
print(s.recv(1024))
s.close()