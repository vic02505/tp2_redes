from mininet.topo import Topo
import sys

MINIMUM_SWITCHES = 1
HOST = "h"
SWITCH = "s"
BASE_IP = "10.0.0."

class ChainedSwitchesTopology(Topo):
    def build(self, ns):
        Topo.__init__(self)

        switches_amount = ns

        if  switches_amount < MINIMUM_SWITCHES:
            raise Exception("Error - El número de switches debe ser mayor o igual a 1.")

        #Hosts building
        hosts_list = []

        host_amount =  switches_amount * 2
        for i in range (0, host_amount):
            hosts_list.append(self.addHost(name=HOST+str(i), ip=BASE_IP+str(i)))

        #Switches building
        switches_list = []

        for i in range (0, switches_amount):
            switches_list.append(self.addSwitch(name=SWITCH+str(i)))

        #Linking hosts with switches:
        host_id = 0
        for switch in switches_list:
            self.addLink(hosts_list[host_id], switch)
            host_id += 1
            self.addLink(hosts_list[host_id], switch)
            host_id += 1


topos = {'tp2': ChainedSwitchesTopology}