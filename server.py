import socket
import threading
import base64

HOST = '0.0.0.0'
PORT = 6265

print("Server Running")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(5)
while True:
    conn, addr = s.accept()
    msg = b''
    while True:
        data = conn.recv(4096)
        if not data: break
        msg += data
        print (msg)
        conn.send(b"This is Server")
    conn.close()
    print ('client disconnected')





