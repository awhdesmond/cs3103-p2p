import socket

HOST = "127.0.0.1"
PORT = 7494

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((HOST, PORT))
    sock.sendall(b'JOIN 123 1.2.3.45\r\n')
    data = sock.recv(1024)
    print(data)
