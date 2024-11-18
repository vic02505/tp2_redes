from mininet.topo import Topo
import sys

MINIMUM_SWITCHES = 1
HOST = "h"
SWITCH = "s"
BASE_IP = "10.0.0."
HOSTS_AMOUNT = 4

class ChainedSwitchesTopology(Topo):
    def __init__(self, ns):
        Topo.__init__(self)

        switches_amount = int(ns)

        if  switches_amount < MINIMUM_SWITCHES:
            raise Exception("Error - El número de switches debe ser mayor o igual a 1.")

        #Switches building
        switches_list = []
        
        for i in range (0, switches_amount):
            switches_list.append(self.addSwitch(name=SWITCH+str(i+1)))

        for i in range (0, switches_amount - 1):
            self.addLink(switches_list[i], switches_list[i+1])


        #Hosts building
        hosts_list = []

        for i in range(0, HOSTS_AMOUNT):
            hosts_list.append(self.addHost(name=HOST+str(i+1), ip=BASE_IP+str(i+1)))
      

        #Linking hosts to swtiches      
        first_switch = switches_list[0]
        self.addLink(hosts_list[0], first_switch)
        self.addLink(hosts_list[1], first_switch)
        
        last_switch = switches_list[-1]
        self.addLink(hosts_list[2], last_switch)        
        self.addLink(hosts_list[3], last_switch)
            
topos = {'tp2': ChainedSwitchesTopology}