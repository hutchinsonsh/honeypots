#!/usr/bin/env python3

import paramiko
import socket
import time
import threading
import sys
import _thread
import csv
from datetime import datetime

# functionality:
#   Runs while loop to accept all new clients (I set a limit of the # of attempts since my ec2 instance had limited space and I was afraid of spamming)
#   Each client runs on their own thread --> pointless at this time since all clients try to connect/get immediately rejected
#     Store each attempt in csv format to given file 

# the main difference between this and HP1 is 1. HP2 forces clients to have 3 password attempts and 2. I changed how the threading works
# The reason for the threading change was because in the HP1, the variables client ID, ip, port, etc, were all treated as global variables- so whenever a new client joined, it would change that variable for everyone. So not ideal for logging purposes. 


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

    # checks if user can open channel w/out authentication
    # for HP2 - should never be ran; for contingencies 
    def check_auth_none(self, username):
        # creates lock for critical section; writes to file; releases lock
        lock.acquire()         
        with open(csvFileLocation, mode='a+') as csv_file:   
            time = datetime.now()
            data = [self.clientID, self.ip, self.port, 'None', username, time.strftime("%d/%m : %H:%M:%S")]
            writer = csv.writer(csv_file)
            writer.writerow(data)
        lock.release()
        return paramiko.AUTH_FAILED


    # checks if user can open channel w/ certain username/password
    # for HP2 - actually runs this function; records username/password; doesn't allow client to connect
    # in all, each client should run this function 3 times (each client has 3 attempts by default to enter the right password)
    def check_auth_password(self, username, password):
        # creates lock for critical section; writes to file; releases lock
        lock.acquire()         
        with open(csvFileLocation, mode='a+') as csv_file:   
            time = datetime.now()
            data = [self.clientID, self.ip, self.port, 'Pass', password, username, time.strftime("%d/%m : %H:%M:%S")]
            writer = csv.writer(csv_file)
            writer.writerow(data)
        lock.release()
        return paramiko.AUTH_FAILED

    # checks if user can open channel w/ certain username/key
    # for HP2 - should never be ran; for contingencies 
    def check_auth_publickey(self, username, key):
        # creates lock for critical section; writes to file; releases lock
        lock.acquire()         
        with open(csvFileLocation, mode='a+') as csv_file:   
            time = datetime.now()
            data = [self.clientID, self.ip, self.port, 'Key', key, username, time.strftime("%d/%m : %H:%M:%S")]
            writer = csv.writer(csv_file)
            writer.writerow(data)
        lock.release()
        return paramiko.AUTH_FAILED

    # determine if channel request will be granted
    # for honeypot 3; actually allows a channel to be created; should never get to this point for hp 1 and 2
    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        #return paramiko.OPEN_SUCCEEDED

    # returns authentication methods supported by server
    # HP 2 --> password
    def get_allowed_auths(self, username):
        return 'password'


# In previous versions, I didn't have a class for threading, I just implemented threading from the python library
# However, that prevented me from creating class objects in the threads- which is necessary for keeping track of                                                               
# what client enters what password in what order, which is imperative for good data analysis                                                                                   
# so, this is a class for each thread object                                                                                                                                   
# Reference: https://stackoverflow.com/questions/53151032/create-object-after-thread-creation-vs-passing-object-on-thread-creation                                             
class NewThread(threading.Thread):                                                                                                                                             
    
    def __init__(self, clientID, conn, ip, port):                                                                                                                  
        threading.Thread.__init__(self)                                                                                                                                        
        self.clientID = clientID 
        self.conn = conn
        self.ip = ip                                                                                                                                                           
        self.port = port
        
        # creates a new server class object; needs to be unique from rest of threads
        lock.acquire()
        self.server = Server(self.clientID, self.ip, self.port)
        lock.release()

    def run(self):
        #critical section; writes to file
        #in theory, each client can write to the file between 2-5 times (begin + none + pass(0-3) attempts)
        #   if a client only has 1 entry, that means that the client  ran nmap
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
    
        # closes transport
        mainTransport.close()


def startSocket():
    # creates localhost socket on port 22
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    hostIP = socket.gethostbyname([name of ec2 instance; for example: "ec2-1-2-3-4.us-east-2.compute.amazonaws.com"]) 
    sock.bind((hostIP, 22))
    sock.listen(5)
    
    # runs socket on a loop until clientAttempts clients have connected
    connectedClients = 0
    while(connectedClients < clientAttempts):
        conn, addr = sock.accept()
        newClient = NewThread(connectedClients, conn, str(addr[0]), str(addr[1]))
        newClient.start()
        connectedClients += 1; 
    sock.close()

startSocket()
