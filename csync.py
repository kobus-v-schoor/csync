#! /usr/bin/env python3

import argparse
import sys

def run_server():
    pass

def run_client():
    pass

parser = argparse.ArgumentParser(epilog='Long options can be abbreviated if '
        'the abbreviation is unambiguous')
parser.add_argument('--no-ssh', action='store_true', help='do not use ssh tunneling (INSECURE)')
parser.add_argument('--port', default=8200, type=int, help='remote csync port')
parser.add_argument('--server', action='store_true', help='run in server mode')
parser.add_argument('--ssh-port', default=22, type=int, help='remote ssh port')
parser.add_argument('--verbose', action='count', default=0)

args = parser.parse_args()
