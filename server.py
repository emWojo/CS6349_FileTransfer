import socket

HOST = 'localhost'
PORT = 22
DEBUG_MODE = True

print("Server Running")
tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpSocket.setblocking(False)

try:
    tcpSocket.bind(('localhost', PORT))
except socket.error as e:
    print(str(e))
    print('Try again in a few minutes, exiting..')
    exit()

if DEBUG_MODE:
    print(tcpSocket)




