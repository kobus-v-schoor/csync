#! /usr/bin/env python3

import argparse
import os
import sys
import ipaddress
import socket
import atexit
import json
import threading
import hashlib
import pickle

# protocol settings
MSG_SIZE_HEADER = 4 # message size is 8 bytes
MSG_RECV_CHUNK_SIZE = 1024 # message receive buffer size

# level 4: packets, config
# level 3: sockets, packets headers
# level 2: debug
# level 1: informational
# level 0: errors
def log(*msg, level=2):
    global args
    if level == 0:
        print("ERROR:", *msg, file=sys.stderr)
    elif level <= args.verbose:
        print('[' + "*" * (4 - level) + " " * level + ']', *msg)

# used as a central socket manager that make sures all sockets are closed at
# program exit
class SockManager:
    def __init__(self):
        self.sockets = {}

    def register(self, sock):
        log("registering socket with fd", sock.fileno(), level=3)
        self.sockets[sock.fileno()] = sock

    def deregister(self, sock):
        self.sockets.pop(sock.fileno(), None)

    def connect(self, ip, port):
        log("creating socket to connect to", ip, "port", port, level=3)
        s = socket.socket()
        try:
            s.connect((str(ip), port))
        except ConnectionError:
            log("unable to connect to", ip, "on port", port, ": connection "
                    "refused", level=0)
            raise
        self.register(s)
        return s

    def listen(self, ip, port):
        log("creating socket to listen on", ip, "port", port, level=3)
        s = socket.socket()
        try:
            s.bind((str(ip), port))
        except OSError:
            log("unable to listen on", ip, "port", port, level=0)
            raise
        s.listen()
        return s

    def close(self, sock):
        log("closing socket fd", sock.fileno(), sock.getpeername(), level=3)
        self.deregister(sock)
        sock.close()

    def cleanup(self):
        for key in list(self.sockets):
            self.close(self.sockets[key])

sock_manager = SockManager()
atexit.register(sock_manager.cleanup)

class Server(threading.Thread):
    def __init__(self, client_sock, index, **kwargs):
        super().__init__(**kwargs)
        self.client_sock = client_sock
        self.index = index

    def run(self):
        client_ip = self.client_sock.getpeername()
        sock = self.client_sock
        log("spawned server to handle", client_ip)

        try:
            log("waiting for index from", client_ip)
            client_index = rcv_message(sock)

            log("index received from", client_ip)
            log("index ", client_ip, ":", client_index, level=4)

            # print(gen_patch(self.index, client_index))

        except ConnectionError:
            log("connection error with {}, stopping server".format(
                    self.client_sock.getpeername()), level=0)
            sock_manager.close(self.client_sock)
            return

        sock_manager.close(self.client_sock)


# sends an object serializable as json (e.g. dict)
def send_msg(sock, data):
    msg_data = json.dumps(data).encode()
    msg_size = len(msg_data).to_bytes(MSG_SIZE_HEADER, 'big')
    log("attempting to send message of size", len(data), "to",
            sock.getpeername(), level=3)
    log("outbound message ({}):".format(sock.getpeername()), data, level=4)
    try:
        sock.sendall(msg_size + msg_data)
    except: # not sure what exception to catch
        log("unable to send message of size", msg_size, "to",
                sock.getpeername(), level=0)
        raise ConnectionError

    log("message sent to", sock.getpeername(), level=3)

def send_file(sock, filename):
    pass

# reads a message from sock - object must be decodable as valid json
def rcv_message(sock):
    def read_chunk(size):
        read_bytes = 0
        chunks = bytearray()
        while read_bytes < size:
            chunk = sock.recv(min(MSG_RECV_CHUNK_SIZE, size))
            if not chunk:
                break
            read_bytes += len(chunk)
            chunks += chunk
        if not chunks:
            log("failed to read message from", sock.getpeername(), level=0)
            raise ConnectionError
        return bytes(chunks)

    log("attempting to receive message from", sock.getpeername(), level=3)

    message_size = int.from_bytes(read_chunk(MSG_SIZE_HEADER), 'big')
    log("attempting to read", message_size, "bytes", level=3)

    message = read_chunk(message_size).decode()

    log("inbound message ({}):".format(sock.getpeername()), message, level=4)

    try:
        message = json.loads(message)
    except json.decoder.JSONDecodeError:
        log("unable to decode message to json format", level=0)
        raise ConnectionError

    log("message received from", sock.getpeername(), level=3)

    return message


def rcv_file(sock, filename):
    pass

def get_config():
    global args

    log("attempting to read config", level=2)

    # create config file if it doesn't exist
    if not os.path.isdir(os.path.dirname(args.conf)):
        os.makedirs(os.path.dirname(args.conf))
    if not os.path.isfile(args.conf):
        open(args.conf, 'w').close()

    try:
        config = {}
        with open(args.conf, 'r') as conf_file:
            cur_sec = None
            line_num = 0
            for line in conf_file.readlines():
                line_num += 1
                line = line.strip()
                if not line:
                    continue
                if line[0] == '#':
                    continue
                if cur_sec is None or line[0] == '[':
                    if line[0] != '[':
                        log("invalid config file, file listed without parent: line no",
                                line_num, level=0)
                        raise RuntimeError
                    else:
                        if line[-1] != ']':
                            log("invalid config file, closing bracket for parent",
                                    "not found: line no", line_num, level=0)
                            raise RuntimeError
                        cur_sec = line[1:-1].strip()
                        if not cur_sec:
                            log("invalid config file, parent cannot be an empty:",
                                    "line no", line_num, level=0)
                            raise RuntimeError
                        if config.get(cur_sec, None):
                            logf("invalid config file, duplicate parent: line no",
                                    line_num, level=0)
                            raise RuntimeError

                        config[cur_sec] = []
                        continue

                config[cur_sec].append(line)
    except RuntimeError:
        log("unable to read config file, aborting...", level=0)
        sys.exit(1)
        return

    log("config successfully read")
    log("config:", config, level=4)
    return config

def save_config(config):
    global args

    log("attempting to save config file")

    if not os.path.isdir(os.path.dirname(args.conf)):
        os.makedirs(os.path.dirname(args.conf))

    with open(args.conf, 'w') as cf:
        for parent in config:
            cf.write("[{}]\n".format(parent))
            for path in config[parent]:
                cf.write("{}\n".format(path))

def file_md5(fname):
    md5 = hashlib.md5()
    with open(fname, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            md5.update(chunk)
    return md5.hexdigest()

def get_index(config):
    global args

    log("building index")

    def build_index(path):
        index = {}

        if args.md5:
            stamp = lambda f: file_md5(f)
        else:
            stamp = lambda f: os.stat(f).st_mtime

        path = os.path.join(os.environ['HOME'], path)
        for root, dir, files in os.walk(path):
            for f in files:
                fname = os.path.join(root, f)
                index[os.path.relpath(fname, os.environ['HOME'])] = stamp(fname)

        return index

    index = {}

    if not args.force_index and os.path.isfile(args.cache):
        try:
            with open(args.cache, 'r+b') as f:
                index = pickle.load(f)
            log("index loaded from cache")
        except pickle.UnpicklingError:
            log("cache file corrupt, rebuilding index", level=0)
            os.remove(args.cache)
            index = {}

    for parent in config:
        index[parent] = {}
        for path in config[parent]:
            # if path is already in index from cache, skip it
            if index[parent].get(path, None):
                continue
            log("building index for", path)
            index[parent][path] = build_index(path)

    log("index:", index, level=4)

    return index

def save_index(index):
    global args

    log("saving index")

    cachedir = os.path.dirname(args.cache)
    try:
        if not os.path.isdir(cachedir):
            os.makedirs(cachedir)
        with open(args.cache, 'w+b') as f:
            pickle.dump(index, f)
    except pickle.PicklingError:
        log("unable to save index cache, aborting cache", level=0)
        return
    log("index cache successfully saved")

# generates a "patch" to go from the old index to the new
def gen_patch(old_index, new_index):
    global args

    if args.md5:
        def modded(old_path, new_path):
            return old_path != new_path
    else:
        def modded(old_path, new_path):
            return new_path > old_path

    patch = {}

    patch['add'] = {}
    patch['mod'] = {}

    for parent in new_index:
        # if parent is new, just add the whole thing
        if not parent in old_index:
            patch['add'][parent] = new_index[parent]
            continue

        patch['add'][parent] = {}
        patch['mod'][parent] = {}
        for root_path in new_index[parent]:
            # if root_path is new, just add the whole thing
            if not root_path in old_index[parent]:
                patch['add'][parent][root_path] = new_index[parent][root_path]
                continue

            patch['add'][parent][root_path] = {}
            patch['mod'][parent][root_path] = {}
            for path in new_index[parent][root_path]:
                # if path is new, add it
                # if path is modified, mod it
                if path in old_index[parent][root_path]:
                    if modded(old_index[parent][root_path][path],
                            new_index[parent][root_path][path]):
                        patch['mod'][parent][root_path][path] = new_index[parent][root_path][path]
                else:
                    patch['add'][parent][root_path][path] = new_index[parent][root_path][path]


    patch['del'] = {}

    for parent in old_index:
        # non-existent parents don't get deleted as they might not be used on
        # client
        if not parent in new_index:
            continue

        patch['del'][parent] = {}

        for root_path in old_index[parent]:
            patch['del'][parent][root_path] = {}

            # if root path doesn't exist in new index, remove the whole thing
            if not root_path in new_index[parent]:
                patch['del'][parent][root_path] = old_index[parent][root_path]
                continue

            # if path doesn't exist in new index, remove it
            for path in old_index[parent][root_path]:
                if not path in new_index[parent][root_path]:
                    patch['del'][parent][root_path][path] = \
                            old_index[parent][root_path][path]

    # remove empty entries
    for op in patch:
        for parent in patch[op]:
            pd = patch[op][parent]
            patch[op][parent] = {rp: pd[rp] for rp in pd if pd[rp]}
        od = patch[op]
        patch[op] = {pa : od[pa] for pa in od if od[pa]}

    return patch

def run_server():
    global args

    config = get_config()
    index = get_index(config)

    log("attempting to listen on", args.ip, "port", args.port)
    sock = sock_manager.listen(args.ip, args.port)
    log("listening on", sock.getsockname(), level=1)

    while True:
        client_sock, client_address = sock.accept()
        log("accepted incoming connection from", client_address, level=1)
        sock_manager.register(client_sock)
        server = Server(client_sock, index)
        server.start()

def run_client():
    global args

    config = get_config()

    try:
        sock = sock_manager.connect(args.ip, args.port)
    except ConnectionError:
        log("unable to connect to server, aborting...", level=0)
        sys.exit(1)
        return

    log("successfully connected to server at", sock.getpeername(), level=1)

    index = get_index(config)

    log("sending index to server")
    send_msg(sock, index)


# if a valid fqdn is given it will still get resolved and used - if not, raise
# an exception
def valid_ip(ip):
    try:
        socket.gethostbyname(ip)
    except socket.gaierror:
        raise argparse.ArgumentTypeError("unable to resolve " + str(ip))
    return ip

parser = argparse.ArgumentParser(epilog='Long options can be abbreviated if '
        'the abbreviation is unambiguous')
parser.add_argument('--cache', default='{}/.cache/csync'.format(os.environ['HOME']),
        help='cache file for indexing')
parser.add_argument('--conf', default="{}/.config/csync".format(os.environ['HOME']),
        help="config file to use")
parser.add_argument('--force-index', action='store_true', help='force recreation of index')
parser.add_argument('--md5', action='store_true', help='use md5 for file comparison')
parser.add_argument('--no-ssh', action='store_true', help='do not use ssh tunneling (INSECURE)')
parser.add_argument('--port', default=8200, type=int, help='csync port')
parser.add_argument('ip', nargs='?', default='0.0.0.0', type=valid_ip)
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
