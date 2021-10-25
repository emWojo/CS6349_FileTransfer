import socket
import threading
import base64

HOST = '127.0.0.1'
PORT = 6265
DEBUG_MODE = True

print("Client Running")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send(b"This is Client")
data = s.recv(4096)
s.close()
print (data)

