
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.addresses import IPAddr
import json

log = core.getLogger()

class Firewall(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        log.debug("Enabling␣Firewall␣Module")
        with open("config.json", "r") as config_file:
            self.rules_config = json.load(config_file)["config"]["firewallRules"]
        config_file.close()
        
    def _handle_ConnectionUp(self, event):
        log.info("ConnectionUp for switch {}: ".format(event.dpid))
        # Si no ponemos ningun if, se instalarán las reglas en todos los switches
        #if event.dpid == 1:                          # Se conecta al primer switch nada mas
        log.info("Seteando reglas")
        self.set_rule_1(event)
        self.set_rule_2(event)
        self.set_rule_3(event)

        return            

    # 1. Se deben descartar todos los mensajes cuyo puerto destino sea 80.
    def set_rule_1(self, event):
        #Esta regla se setea tanto para TCP como para UDP!

        # TCP
        rule_tcp = of.ofp_flow_mod()
        rule_tcp.match.tp_dst = self.rules_config[0]["tp_dst"]      # Puerto destino 80
        rule_tcp.match.nw_proto = 6                                 #TCP
        rule_tcp.match.dl_type = 0x0800                             #IPv4
        event.connection.send(rule_tcp)

        # UDP
        rule_udp = of.ofp_flow_mod()
        rule_udp.match.tp_dst = self.rules_config[0]["tp_dst"]      # Puerto destino 80
        rule_udp.match.nw_proto = 17                                # UDP
        rule_udp.match.dl_type = 0x0800                             # IPv4
        event.connection.send(rule_udp)

    # 2. Se deben descartar todos los mensajes que provengan del host 1, tengan como puerto destino el 5001, y estén utilizando el protocolo UDP.
    def set_rule_2(self, event):
        rule = of.ofp_flow_mod()
        rule.match.dl_type = 0x0800                                     # IPv4
        rule.match.nw_src = IPAddr(self.rules_config[1]["nw_src"])      # Dirección IP del host 1
        rule.match.tp_dst = self.rules_config[1]["tp_dst"]              # Puerto destino 5001
        rule.match.nw_proto = self.rules_config[1]["nw_proto"]          # Protocolo UDP (17 es el valor en decimal para UDP)
        event.connection.send(rule)

    # 3. Se deben elegir dos hosts cualesquiera y los mismos no deben poder comunicarse de ninguna forma.
    def set_rule_3(self, event):
        rule = of.ofp_flow_mod()
        rule.match.dl_type = 0x0800                                     # IPv4
        rule.match.nw_src = IPAddr(self.rules_config[2]["nw_src"])      # Dirección IP del host 1
        rule.match.nw_dst = IPAddr(self.rules_config[2]["nw_dst"])      # Dirección IP del host 2
        event.connection.send(rule)
        

def launch():
     # Starting the Firewall module
     core.registerNew(Firewall)
