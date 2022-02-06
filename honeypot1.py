#!/usr/bin/env python3

import paramiko
import socket
import time
import threading
import _thread
import csv
import sys
from datetime import datetime

# functionality:
#   Runs while loop to accept all new clients (I set a limit of the # of attempts since my ec2 instance had limited space and I was afraid of spamming)
#   Each client runs on their own thread --> pointless at this time since all clients try to connect/get immediately rejected
#     Store each attempt in csv format to given file 

# for locking critical section (ie- reading/writing to a file )
lock=_thread.allocate_lock()
hostKey = paramiko.rsakey.RSAKey(filename='[add location of .ssh/id_rsa]')
clientAttempts = [number of clients that are allowed to join before while loop ends]
csvFileLocation = [location of where to write all logging information]

# implements InteractiveQuery (for promts/session look) and ServerInterface(for authentication)
# not really needed for HP1, later used for HP2/HP3
class Server(paramiko.server.ServerInterface):
    clientID = 0
    port = 0
    ip = 0
    # used for writing to a csv file
    def __init__(self, clientID, port, ip):
        Server.clientID = clientID
        Server.port = port
        Server.ip = ip

    # checks if user can open channel w/out authentication & records client data
    # for HP1, always fails
    def check_auth_none(self, username):
        # creates lock for critial section; writes to file; releases lock
        lock.acquire()    
        with open(csvFileLocation, mode='a+') as csv_file:   
            time = datetime.now()
            data = [Server.clientID, Server.ip, Server.port, 'None', username, time.strftime("%d/%m : %H:%M:%S")]
            writer = csv.writer(csv_file)
            writer.writerow(data)
        lock.release()

        # always fails; no actual server to log into yet
        return paramiko.AUTH_FAILED

    # checks if client can open channel w/ given username/password & records client data
    # by default, HP1 doesn't run this, but client can force it to run
    def check_auth_password(self, username, password):
        # creates lock for critial section; writes to file; releases lock
        lock.acquire()         
        with open(csvFileLocation, mode='a+') as csv_file:   
            time = datetime.now()
            data = [Server.clientID, Server.ip, Server.port, 'Pass', password, username, time.strftime("%d/%m : %H:%M:%S")]
            writer = csv.writer(csv_file)
            writer.writerow(data)
        lock.release()
        
        # always fails; no actual server to log into yet
        return paramiko.AUTH_FAILED

    # checks if client can open channel w/ given key
    # by default, HP1 doesn't run this, but client can force it to run
    def check_auth_publickey(self, username, key):
        # creates lock for critial section; writes to file; releases lock
        lock.acquire()         
        with open(csvFileLocation, mode='a+') as csv_file:   
            time = datetime.now()
            data = [Server.clientID, Server.ip, Server.port, 'Key', key, username, time.strftime("%d/%m : %H:%M:%S")]
            writer = csv.writer(csv_file)
            writer.writerow(data)
        lock.release()
        
        # always fails; no actual server to log into yet
        return paramiko.AUTH_FAILED

    # determine if channel request will be granted
    # for HP1 - should never run; auth always fails before this point
    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    # returns authenication methods supported by server
    def get_allowed_auths(self, username):
        return 'none, password, publickey'



# creates new transport/server for every connection
# allows multiple connections at the same time
def clientConnects(conn, ip, port, connectedClients): 
    # creates lock for critical section; writes to file; releases lock
    # in theory; every client that tries to connect will have 2 entries; client that just runs nmap will have 1
    lock.acquire()         
    with open(csvFileLocation, mode='a+') as csv_file:   
        time = datetime.now()
        data = [connectedClients, ip, port, 'Begin', time.strftime("%d/%m : %H:%M:%S")]
        writer = csv.writer(csv_file)
        writer.writerow(data)
    lock.release()


    # creates paramiko transport(attaches to connection/negotiates session/creates channel)
    mainTransport = paramiko.Transport(conn)
    mainTransport.banner_timeout = 300
    mainTransport.add_server_key(hostKey)

    # creates server object for transport layer
    server = Server(connectedClients, port, ip)

    # starts server
    mainTransport.start_server(event=threading.Event(), server=server)
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
        threading.Thread(target=clientConnects, args= (conn, str(addr[0]), str(addr[1]), connectedClients)).start()     
        connectedClients += 1                                                                                                                                                  
          
    # ends entire program / stops server
    sock.close()         
    
def main():
    startSocket()

main()
