#!/usr/bin/env python3

import paramiko
import socket
import time
import threading
import sys

import _thread
import csv
from datetime import datetime

# Disclaimer: I've only ran this on my localhost. Again, this is a passion project. 
# There are much more secure honeypots that I would advise using over this one. 

# Functionality: 
#   This honeypot actually allows clients to create a connection with the server
#   Takes a single command (ie- until client presses enter)
#     Echos response back to them/ends connection

# TODO: 
#   Create better way to read data sent by client(right now not very efficient/pretty)
#   Create responses based on command (so that it seems more natural/mimics an actual ssh server)
#   Create contingencies: ie- timeout for unresponsive clients, character count limit(overflow concerns), etc

# for locking critical section
lock=_thread.allocate_lock()

hostKey = paramiko.rsakey.RSAKey(filename='[add location of .ssh/id_rsa]')
clientAttempts = [number of clients that are allowed to join before while loop ends]
csvFileLocation = [location of where to write all logging information]


# implements InteractiveQuery (for prompts/session look) and ServerInterface(for authentication)
# auth_none/publickey not used in HP2; only need to re-implement the password authorization
class Server(paramiko.server.ServerInterface):
    # used for writing to a csv file
    def __init__(self, clientID, ip, port):
        self.clientID = clientID
        self.port = port
        self.ip = ip
        self.event = threading.Event()

    # checks if user can open channel w/out authentication
    # allows all connections
    def check_auth_none(self, username):
        # creates lock for critical section; writes to file; releases lock
        lock.acquire()         
        with open(csvFileLocation, mode='a+') as csv_file:   
            time = datetime.now()
            data = [self.clientID, self.ip, self.port, 'None', username, time.strftime("%d/%m : %H:%M:%S")]
            writer = csv.writer(csv_file)
            writer.writerow(data)
        lock.release()
        return paramiko.AUTH_SUCCESSFUL


    # checks if user can open channel w/ certain username/password
    # allows all connections
    def check_auth_password(self, username, password):
        # creates lock for critical section; writes to file; releases lock
        lock.acquire()         
        with open(csvFileLocation, mode='a+') as csv_file:   
            time = datetime.now()
            data = [self.clientID, self.ip, self.port, 'Pass', password, username, time.strftime("%d/%m : %H:%M:%S")]
            writer = csv.writer(csv_file)
            writer.writerow(data)
        lock.release()
        return paramiko.AUTH_SUCCESSFUL

    # checks if user can open channel w/ certain username/key
    def check_auth_publickey(self, username, key):
        # creates lock for critial section; writes to file; releases lock
        lock.acquire()         
        with open(csvFileLocation, mode='a+') as csv_file:   
            time = datetime.now()
            data = [self.clientID, self.ip, self.port, 'Key', key, username, time.strftime("%d/%m : %H:%M:%S")]
            writer = csv.writer(csv_file)
            writer.writerow(data)
        lock.release()
        return paramiko.AUTH_FAILED

    # determine if channel request will be granted
    # for honeypot 3; actually allows a channel to be created
    # only allows session requests
    def check_channel_request(self, kind, chanid):
        print(chanid, " ", kind)
        if(kind == "session"):
            print("success")
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        #return paramiko.OPEN_SUCCEEDED

    # returns authentication methods supported by server
    def get_allowed_auths(self, username):
        return 'none, password'

    
    # this is for HP 3, allows connecting clients to see a 'terminal' on their screen and run commands
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        #print(channel, " ", term, " ", width, " ", height, " ", pixelwidth, " ", pixelheight, " ", modes)
        return True

    def check_channel_shell_request(self, channel):
        #print("channel ", channel)
        self.event.set()
        return True

# Same setup as w/ HP2 so that each client runs on their own thread                                            
class NewThread(threading.Thread):                                                                                                                                             
    
    def __init__(self, clientID, conn, ip, port):                                                                                                                  
        threading.Thread.__init__(self)                                                                                                                                        
        self.clientID = clientID 
        self.conn = conn
        self.ip = ip                                                                                                                                                           
        self.port = port
        
        lock.acquire()
        self.server = Server(self.clientID, self.ip, self.port)
        lock.release()

    def run(self):
        # critical section; writes to file(records first time a client connects)
        # if a client only has 1 entry, that means that the client  ran nmap
        lock.acquire()         
        with open(csvFileLocation, mode='a+') as csv_file:   
            time = datetime.now()
            data = [self.clientID, self.ip, self.port, 'Begin', time.strftime("%d/%m : %H:%M:%S")]
            writer = csv.writer(csv_file)
            writer.writerow(data)
        lock.release()

        # creates paramiko transport(attaches to connection/negotiates session/creates channel)
        mainTransport = paramiko.Transport(self.conn)
        mainTransport.banner_timeout = 300
        mainTransport.add_server_key(hostKey)

        # starts server
        mainTransport.start_server(event=threading.Event(), server=self.server)
        chan = mainTransport.accept(20)
        
        self.server.event.wait(10)
        
        # fun part- send/receive data to/from client
        # receives one character at a time/echos that character back --> not ideal but it shows POC
        if not self.server.event.isSet():        # closes transport
            # record command
            lock.acquire()         
            with open(csvFileLocation, mode='a+') as csv_file:   
                time = datetime.now()
                data = [self.clientID, self.ip, self.port, 'Command failed", time.strftime("%d/%m : %H:%M:%S")]
                writer = csv.writer(csv_file)
                writer.writerow(data)
            lock.release()
            #print("ssh failure")
        else:
            conversation = b""
            endConversation = 0
            #while(endConversation == 0):
            #    chan.send("hello")
            while(True):
                data = chan.recv(1024)
                if not data:
                    break
                if(data == b'\r'):
                    break
                conversation += data

            #print("data")
            #print(conversation)
            chan.sendall(data)
            
            # record command
            lock.acquire()         
            with open(csvFileLocation, mode='a+') as csv_file:   
                time = datetime.now()
                data = [self.clientID, self.ip, self.port, 'Command', conversation, time.strftime("%d/%m : %H:%M:%S")]
                writer = csv.writer(csv_file)
                writer.writerow(data)
            lock.release()

        mainTransport.close()


def startSocket():
    # creates localhost socket on port 2222
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 2222))
    sock.listen(5)
    
    # runs socket on a loop until clientAttempts clients have connected
    connectedClients = 0
    while(connectedClients <  clientAttempts):
        conn, addr = sock.accept()
        newClient = NewThread(connectedClients, conn, str(addr[0]), str(addr[1]))
        newClient.start()
        connectedClients += 1; 
    sock.close()

startSocket()
