#! /usr/bin/env python3

import argparse
import sys
import ipaddress
import socket
import atexit

# level 3: packets
# level 2: debug
# level 1: informational
# level 0: errors
def log(*msg, level=2):
    global args
    if level == 0:
        print("ERROR:", *msg, file=sys.stderr)
    elif level <= args.verbose:
        print(*msg)

# used as a central socket manager that make sures all sockets are closed at
# program exit
class SockManager:
    def __init__(self):
        self.sockets = {}

    def register(self, sock):
        log("registering socket with fd", sock.fileno())
        self.sockets[sock.fileno()] = sock

    def deregister(self, sock):
        self.sockets.pop(sock.fileno(), None)

    def connect(self, ip, port):
        log("creating socket to connect to", ip, "port", port)
        s = socket.socket()
        s.connect((str(ip), port))
        self.register(s)
        return s

    def listen(self, ip, port):
        log("creating socket to listen on", ip, "port", port)
        s = socket.socket()
        s.bind((str(ip), port))
        self.register(s)
        return s

    def close(self, sock):
        log("closing socket", sock)
        self.deregister(sock)
        sock.close()

    def cleanup(self):
        for key in list(self.sockets):
            self.close(self.sockets[key])

sock_manager = SockManager()
atexit.register(sock_manager.cleanup)

def run_server():
    global args

    log("attempting to listen on", args.ip, "port", args.port)
    sock = sock_manager.listen(args.ip, args.port)

def run_client():
    pass

parser = argparse.ArgumentParser(epilog='Long options can be abbreviated if '
        'the abbreviation is unambiguous')
parser.add_argument('--no-ssh', action='store_true', help='do not use ssh tunneling (INSECURE)')
parser.add_argument('--port', default=8200, type=int, help='csync port')
parser.add_argument('ip', nargs='?', default='0.0.0.0', type=ipaddress.ip_address)
parser.add_argument('--server', action='store_true', help='run in server mode')
parser.add_argument('--ssh-port', default=22, type=int, help='remote ssh port')
parser.add_argument('--verbose', '-v', action='count', default=0)

args = parser.parse_args()
log("called with arguments:", vars(args))

if args.server:
    log("attempting to start server")
    run_server()
else:
    log("attempting to start client")
    run_client()
