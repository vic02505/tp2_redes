#Coursera :
#- Software Defined Networking ( SDN ) course
#-- Programming Assignment : Layer -2 Firewall Application Professor : Nick Feamster
#Teaching Assistant : Arpit Gupta

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
import pox.lib.packet as pkt

# Add your imports here ...
log = core.getLogger()

# Add your global variables here ...
class Firewall(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        log.debug("Enabling␣Firewall␣Module")
        
    def _handle_ConnectionUp(self, event):
        log.info("ConnectionUp for switch {}: ".format(event.dpid))
        # Si no ponemos ningun if, se instalarán las reglas en todos los switches
        if event.dpid == 1 || event.dpid == 4:                                 # Se conecta al primer switch nada mas
            log.info("Seteando reglas")
            self.set_rule_1(event)
            self.set_rule_2(event)
            self.set_rule_3(event, "10.0.0.1", "10.0.0.4")
        return            

    # 1. Se deben descartar todos los mensajes cuyo puerto destino sea 80.
    def set_rule_1(self, event):
        rule = of.ofp_flow_mod()
        rule.match.tp_dst = 80                              # Puerto destino 80
        rule.match.dl_type = pkt.ethernet.IP_TYPE           # Tipo IP (Es obligatorio?)
        rule.match.nw_proto = 17                           # Protocolo TCP (Es obligatorio?)
        event.connection.send(rule)

    def set_rule_2(self, event):
        rule = of.ofp_flow_mod()
        rule.match.dl_type = pkt.ethernet.IP_TYPE           # Tipo de paquete: IP
        rule.match.nw_proto = pkt.ipv4.UDP_PROTOCOL         # Protocolo UDP (17 es el valor en decimal para UDP)
        rule.match.nw_src = IPAddr("10.0.0.1")              # Dirección IP del host 1
        rule.match.tp_dst = 5001                            # Puerto destino 5001
        event.connection.send(rule)

    def set_rule_3(self, event, h1, h2):
        rule = of.ofp_flow_mod()
        rule.match.dl_type = pkt.ethernet.IP_TYPE           # Tipo de paquete: IP
        rule.match.nw_src = IPAddr(h1)                      # Dirección IP del host 1
        rule.match.nw_dst = IPAddr(h2)                      # Dirección IP del host 1
        event.connection.send(rule)
        

def launch():
     # Starting the Firewall module
     core.registerNew(Firewall)
