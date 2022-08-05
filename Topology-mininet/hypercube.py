from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink, TCIntf
from mininet.util import dumpNodeConnections,dumpNetConnections, dumpPorts
from mininet.cli import CLI
from mininet.log import setLogLevel

from ryu.lib import hub
from sys import argv
import argparse
import random
import math



##########################################################################################
#Custom Topology
class MyTopo(Topo):
    def __init__(self, noHyper=3,noHost=1):
        Topo.__init__(self)

        noHost= noHost
        noHyper = noHyper
        noOFS = pow(2,noHyper)
        Host = []
        OFS  = []
        new =[]
        self.switch_connect={}
        self.switch=[]
        self.host=[]
        self.host_connect=[]
        

        com=list(range(0,noHyper+1)) # create array for example if noHyper=3 com=[1,2,3]
        new=[math.pow(2,i) for i in com] # create array for example []
        print("New:",new)

        ################################################################
        #Add Switch to topology
        #
        for i in range(noOFS):
            OFS.append(self.addSwitch("s{}".format(i+1),ip="10.0.{}.0".format(i+1), mac=""))
            
        
        
        ################################################################    
        #Create Switch and Host Array
        #
        z=0      
        while z < noHost:
            if z == noHost:
                break
            l=input("Connect h{} to switch:".format(z+1))
            self.switch.append(l)
            self.host.append(z+1)
            z+=1
        
        for i in range(0, len(self.switch)):
            for j in range(i+1, len(self.switch)):
                if self.switch[i] != self.switch[j]:
                    self.switch_connect.setdefault(self.switch[i],[])
                    self.switch_connect.setdefault(self.switch[j],[])

        print("")
        for i in range(len(self.switch_connect)):
            for j in range(0, len(self.switch)):
                if self.switch_connect.keys()[i] == self.switch[j]:
                    self.switch_connect.values()[i].append(self.host[j])
        
        print(self.switch_connect)

        ################################################################
        #Add Host to topology
        #
        for i in range(len(self.switch_connect)):
            print("")
            print("Switch connect: {}".format(self.switch_connect.keys()[i]))
            for j in range(len(self.switch_connect.values()[i])):
                Host.append(self.addHost("h{}".format(self.switch_connect.values()[i][j]), ip="10.0.{}.{}".format(self.switch_connect.keys()[i],j+1)))    
                print("Host:{} <--> IPv4:10.0.{}.{}".format(self.switch_connect.values()[i][j],self.switch_connect.keys()[i],j+1))

        ################################################################
        #Connect between Host and Switch
        #
        count=0
        number_host=0
        for i in range(len(self.switch_connect)):
            count=count+1
            if count == len(self.switch_connect)+1:
                break
            else:
                for j in range(len(self.switch_connect.values()[i])):
                    number_host=number_host+1
                    if number_host == range(len(self.switch_connect.values()[i])):
                        continue
                    else:
                        linkopts1 = dict(loss=random.randint(0,9)+1, bw=100, delay='1ms') #Host link  , link loss=1-10%
                        self.addLink(Host[number_host-1],OFS[self.switch_connect.keys()[i]-1],**linkopts1)
                    
        ################################################################
        #Connect between switch and switch
        #         
        for i in range (noOFS):
            for j in range (noOFS):
                if ((j^i) in new) & (j > i): #j^i means: j XOR i to compare 2 values        
                    print(i+1,"link",j+1)
                    linkopts2 = dict(loss=random.randint(0,9)+1, bw=1000, delay='3ms') #Switch Link, link loss=1-10%
                    self.addLink(OFS[i],OFS[j],**linkopts2)

############################################################################################
def main(*args):
    
    k=input("k=")
    NumHost=input("Number of Host:")
    mytopo = MyTopo(k,NumHost)
    net  = Mininet(topo=mytopo, switch=OVSKernelSwitch, 
                   controller=RemoteController("c0", ip="127.0.0.1"), 
                   autoSetMacs=True, link=TCLink)
    

    #Run default command from hosts. E.g., Disable IPv6:
    for h in net.hosts:
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    #Start simulation --------------------------
    net.start()
   
    print("---------------------- NETS ------------------------")
    dumpNetConnections(net)
    print("----------------------------------------------------\n")
    
   
    
    # h1 ping h2
    hub.sleep(1)
    h1=net.getNodeByName("h1")
    print(h1.cmd("ping 10.0.1.2 -c 1"))
    
    #h2 ping h1
    hub.sleep(1)
    h2=net.getNodeByName("h2")
    print(h2.cmd("ping 10.0.1.1 -c 1"))
    
    #net.pingAll()
    CLI(net)
    #Stop simulation ----------------------------
    net.stop()
##########################################################################################
#Default run simulation
if __name__ == "__main__":
    setLogLevel("info")
    main()

