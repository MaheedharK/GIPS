import nmap
import socket
import time
import csv
import getmac
import os
import threading
import ipaddress

import pprint
from netaddr import *
import requests
from queue import Queue
from scapy.all import *
from nmb.NetBIOS import NetBIOS


class LANnetworks(object):
    def __init__(self):
        ip=input("plz enter d ip of router is 192.168.0.1/192.168.0.1")
        self.ip=ip
    def networkscanner(self):
        if len(self.ip)==0:
            network='192.168.43.1/24'
        else:
            network=self.ip+'24'
        print("scanning plz wait...")
        nm=nmap.PortScanner()
        nm.scan(hosts=network, arguments='-sP')
        host_list=[(x,nm[x]['status']['state']) for x in nm.all_hosts()]
        hosts=[]
        for host,status in host_list:
            print("Host\t{}".format(host))
            hosts.append(host)
            time.sleep(15)
            
            time.sleep(5)
        
        i=1
        with open("Network.csv","w",newline="") as file:
             writer=csv.writer(file)
             writer.writerow(["Router ip","HOST IP","HOST NAME","MAC Address","NetBiosname","Manufacturer","OS","net mask","subnet","Ports open"])   
             while i<len(hosts):
                    
               
              try: 
                print('MAC of',hosts[i],"is ",getmac.get_mac_address(ip=hosts[i], network_request=True))
                time.sleep(20)
                n = NetBIOS()
                nbname = n.queryIPForName(hosts[i])
                print(nbname)
                
                ip = IPNetwork(str(hosts[i]))
                print(hosts[i]," has net mask ",ip.netmask)
                
                net = ipaddress.ip_network('192.168.43.1/255.255.255.0', strict=False)
                print(net.network_address)
                time.sleep(20)
                
                ttl_values = {32: "Windows", 60: "MAC OS", 64: "MAC OS / Linux", 128: "Windows", 255: "Linux 2.4 Kernal"}
                ans = sr1(IP(dst=str(hosts[i])) / ICMP(), timeout = 2, verbose=0)
                if ans:
                 if ans.ttl in ttl_values:
                   print ("Host",hosts[i],"has ",ttl_values.get(ans.ttl))
                 else:
                   print ("TBC")
                else:
                   print( "TBC")
                for addr in [getmac.get_mac_address(ip=hosts[i], network_request=True)]:
                 vendor = requests.get('http://api.macvendors.com/' + addr).text
                 print(hosts[i],"vendor is", vendor)
                   
                host_name=socket.gethostbyaddr(hosts[i])
                print("host ip is",hosts[i],"host name is",host_name[0])
                
                time.sleep(10)
                ##port scan
                socket.setdefaulttimeout(0.25)
                print_lock = threading.Lock()
                Total_ports_open = []   
                target = str(hosts[i])
                t_IP = socket.gethostbyname(target)
                print ('Starting scan on host: ', t_IP)
                def portscan(port):
                  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                  try:
                   con = s.connect((t_IP, port))
                   with print_lock:
                    print(port, 'is open')
                    Total_ports_open.append(port)
                   con.close()
                  except:
                    pass
                def threader():
                  while True:
                   worker = q.get()
                   portscan(worker)
                   q.task_done()
   
                q = Queue()
                startTime = time.time()
   
                for x in range(100):
                 t = threading.Thread(target = threader)
                 t.daemon = True
                 t.start()

                for worker in range(1, 5000):
                   q.put(worker)
                q.join()

                print('Time taken:', time.time() - startTime)
                print(Total_ports_open)
               
                
                writer.writerow([hosts[0],hosts[i],host_name[0],getmac.get_mac_address(ip=hosts[i], network_request=True), n.queryIPForName(hosts[i]),vendor,ttl_values.get(ans.ttl),ip.netmask,net.network_address,Total_ports_open])
                 
                
               
                 
              except:
                pass
               
              i+=1
if __name__=="__main__":
    D=LANnetworks()
    D.networkscanner()
  
    
 
