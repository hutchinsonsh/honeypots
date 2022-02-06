# honeypots
Created three honeypot ssh servers with varying levels of functionality using python with paramiko 


Honeypot Descriptions: 
Overall: Each honeypot is designed to mimic an actual ssh server(by this, I mean when nmap is ran, it shows up as an ssh server and bots can connect using ssh user@server command). 
These honeypots were run on ec2 amazon instances for 48-72 hrs

___________
**Disclaimer:**
I am not a cyber security expert- this was an ill-advised passion project more than anything else. Setting up a honeypot is asking for trouble and I would highly suggest doing your own research before hosting one. When I ran these honeypots, I set up an ec2 instance(to avoid using my own network), collected and viewed all data in a sandbox, and only ran the ec2 instance for a limited amount of time- making sure I shut down each instance between use. 

___________
**Honeypot 1**: 
  This is the most basic honeypot. It denies all connections. 
  
  Information it collects: IP address, username, date/time (and inadvertently- passwords)
  
  Results: One thing I didn't expect is that even though it's set up to not request password attempts, the clients were able to use flags in their ssh commands to try to enter passwords anyways. I actually got more password attempt data from this honeypot than I did from HP2. 
  
___________
**Honeypot 2**: 
  This honeypot also denies all connections. The only additional functionality from HP1 is that it forces clients to enter a password(3 attempts- all denied).
  
  Information it collects: IP address, username, date/time, passwords
  
  Results: I only got a fraction of responses that I got from the first honeypot. I got around the same number of nmap scans, so I'm assuming the scripts scanning noticed that passwords are required and were dissuaded. 
  
___________
**Honeypot 3**: 
  This honeypot actually allows a connection. It only allows a session terminal (so no scp commands). Right now, it only reads commands and sends nothing back so any bot with the most basic exception checking will be able to recognize that this is a fake server almost instantly. 
 
  Information it collects: IP address, username, date/time, passwords, commands attempted
  
  Results: I haven't ran it yet(other than on my localhost w/ only myself having access to it. So it works, I'm just cautious about the security risks)
