# honeypots
Created three honeypot servers with varying levels of functionality using python with paramiko 


Honeypot Descriptions: 
Overall: Each honeypot is designed to mimic an actual ssh server(by this, I mean when nmap is ran, it shows up as an ssh server and bots can connect using ssh user@server command)
These honeypots were run on ec2 amazon instances for 48-72 hrs

Honeypot 1: 
  This is the most basic honeypot. It denies all connections. 
  Information it collects: IP address, username, date/time (and inadvertently- passwords)
  Results: One thing I didn't expect is that even though it's set up to not request password attempts, the clients were able to use flags in their ssh commands to try to enter passwords anyways. I actually got more password attempt data from this honeypot than I did from HP2. 
  
Honeypot 2: 
  This honeypot also denies all connections. The only additional functionality from HP1 is that it forces clients to enter a password(3 attempts- all denied).
  Information it collects: IP address, username, date/time, passwords
  Results: I only got a fraction of responses that I got from the first honeypot. I got around the same number of nmap scans, so I'm assuming the scripts scanning noticed that passwords are required and were dissuaded. 
  
Honeypot 3: 
  This honeypot actually allows a connection. It only allows a session terminal (so no scp commands). Right now, it only reads commands and sends nothing back so any bot with the most basic exception checking will be able to recognize that this is a fake server almost instantly. 
  Information it collects: IP address, username, date/time, passwords, commands attempted
  Results: I haven't ran it yet
