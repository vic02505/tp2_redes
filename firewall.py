
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.addresses import IPAddr
import json
import pox.lib.packet as pkt

log = core.getLogger()

class Firewall(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        log.debug("Enabling␣Firewall␣Module")
        with open("config.json", "r") as config_file:
            config = json.load(config_file)["config"]
            self.rules_config = config["firewallRules"]
            self.num_switch = config["switches"]
            self.firewallInSwitch = config["firewallInSwitch"]
        config_file.close()
        
    def _handle_ConnectionUp(self, event):
        log.info("ConnectionUp for switch {}: ".format(event.dpid))
        # Si no ponemos ningun if, se instalarán las reglas en todos los switches
        if event.dpid == 1 or event.dpid == self.num_switch:
        #if event.dpid == self.firewallInSwitch:                          # Se conecta al primer switch nada mas
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
        rule_tcp.match.tp_dst = self.rules_config[0]["tp_dst"]          # Puerto destino 80
        rule_tcp.match.nw_proto = 6                                     #TCP
        rule_tcp.match.dl_type = 0x0800                                 #IPv4
        event.connection.send(rule_tcp)
        log.info("Rule 1 (TCP to port 80) applied.")

        # UDP
        rule_udp = of.ofp_flow_mod()
        rule_udp.match.tp_dst = self.rules_config[0]["tp_dst"]          # Puerto destino 80
        rule_udp.match.nw_proto = 17                                    # UDP
        rule_udp.match.dl_type = 0x0800                                 # IPv4
        event.connection.send(rule_udp)
        log.info("Rule 1 (UDP to port 80) applied.")

    # 2. Se deben descartar todos los mensajes que provengan del host 1, tengan como puerto destino el 5001, y estén utilizando el protocolo UDP.
    def set_rule_2(self, event):
        rule = of.ofp_flow_mod()
        rule.match.dl_type = 0x0800                                     # IPv4
        rule.match.nw_src = IPAddr(self.rules_config[1]["nw_src"])      # Dirección IP del host 1
        rule.match.tp_dst = self.rules_config[1]["tp_dst"]              # Puerto destino 5001
        rule.match.nw_proto = self.rules_config[1]["nw_proto"]          # Protocolo UDP (17 es el valor en decimal para UDP)
        event.connection.send(rule)
        log.info(f"Rule 2 (UDP from {self.rules_config[1]['nw_src']} to port 5001) applied.")

    # 3. Se deben elegir dos hosts cualesquiera y los mismos no deben poder comunicarse de ninguna forma.
    def set_rule_3(self, event):
        rule = of.ofp_flow_mod()
        rule.match.dl_type = 0x0800                                     # IPv4
        rule.match.nw_src = IPAddr(self.rules_config[2]["nw_src"])      # Dirección IP del host 1
        rule.match.nw_dst = IPAddr(self.rules_config[2]["nw_dst"])      # Dirección IP del host 2
        event.connection.send(rule)
        log.info(
            f"Rule 3 (No communication between {self.rules_config[2]['nw_src']} and {self.rules_config[2]['nw_dst']}) applied.")

    # Método para capturar y registrar paquetes
    def _handle_PacketIn(self, event):
        packet = event.parsed  # Paquete recibido
        log.info(f"PacketIn: Switch {event.dpid}, Port {event.port}")

        # Log básico de direcciones
        if packet.type == pkt.ethernet.IP_TYPE:  # Solo IPv4
            ip_packet = packet.payload  # Extraer la carga útil de IP
            log.info(f"Source IP: {ip_packet.src}, Destination IP: {ip_packet.dst}")
            log.info(f"Protocol: {ip_packet.protocol}")

            # Si es TCP o UDP, registrar puertos
            if ip_packet.protocol == pkt.ipv4.TCP_PROTOCOL:
                tcp_packet = ip_packet.payload
                log.info(f"TCP Packet: Src Port {tcp_packet.srcport}, Dst Port {tcp_packet.dstport}")
            elif ip_packet.protocol == pkt.ipv4.UDP_PROTOCOL:
                udp_packet = ip_packet.payload
                log.info(f"UDP Packet: Src Port {udp_packet.srcport}, Dst Port {udp_packet.dstport}")
        else:
            log.info(f"Non-IP Packet: Type {packet.type}")

def launch():
     # Starting the Firewall module
     core.registerNew(Firewall)
