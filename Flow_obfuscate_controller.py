#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4, icmp
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

# Constants for flow timeouts
IDLE_TIMEOUT = 300
HARD_TIMEOUT = 600

# Biến toàn cục để lưu obfuscate_path
_obfuscate_path = 3  # Giá trị mặc định

def subnet(ip):
    """Extract the subnet (first 3 octets) from an IP address."""
    parts = str(ip).split('.')
    return ".".join(parts[:3])

def is_allowed_access(src_ip, dst_ip):
    """Check if communication between two IPs is allowed based on subnet rules."""
    src_sub = subnet(src_ip)
    dst_sub = subnet(dst_ip)
    deny_pairs = [("10.0.1", "10.0.2"), ("10.0.3", "10.0.4"), ("10.0.4", "10.0.5")]
    for (a, b) in deny_pairs:
        if (src_sub == a and dst_sub == b) or (src_sub == b and dst_sub == a):
            return False
    return True

class FlowObfuscateSwitch(object):
    # Class variables for flow mapping and subnet-to-switch mapping
    flow_mapping = {}  # {flow_id: (real_src_ip, [virtual_ips])}
    next_flow_id = 1
    subnet_to_switch = {
        "10.0.0": 1,  # s1
        "10.0.1": 2,  # s2
        "10.0.2": 3,  # s3
        "10.0.3": 4,  # s4
        "10.0.4": 5,  # s5
        "10.0.5": 6,  # s6
    }
    virtual_macs = {
        IPAddr("10.0.0.254"): EthAddr("00:00:00:00:00:01"),
        IPAddr("10.0.1.254"): EthAddr("00:00:00:00:00:02"),
        IPAddr("10.0.2.254"): EthAddr("00:00:00:00:00:03"),
        IPAddr("10.0.3.254"): EthAddr("00:00:00:00:00:04"),
        IPAddr("10.0.4.254"): EthAddr("00:00:00:00:00:05"),
        IPAddr("10.0.5.254"): EthAddr("00:00:00:00:00:06"),
    }
    # Routing table: (src_switch, dst_switch) -> [path of switches]
    routing_table = {
        (1, 2): [1, 7, 8, 9, 10, 11, 12, 13, 2],  # h1 -> s1 -> s7 -> s8 -> s9 -> s10 -> s11 -> s12 -> s13 -> s2 -> h6
        (1, 3): [1, 7, 8, 9, 10, 11, 12, 13, 3],
        (1, 4): [1, 7, 8, 9, 10, 11, 12, 13, 4],
        (1, 5): [1, 7, 8, 9, 10, 11, 12, 13, 2, 3, 4, 5],
        (1, 6): [1, 7, 8, 9, 10, 11, 12, 13, 2, 3, 4, 5, 6],
        (2, 1): [2, 13, 12, 11, 10, 9, 8, 7, 1],  # h6 -> s2 -> s13 -> s12 -> s11 -> s10 -> s9 -> s8 -> s7 -> s1 -> h1
        (2, 3): [2, 3],
        (2, 4): [2, 3, 4],
        (2, 5): [2, 3, 4, 5],
        (2, 6): [2, 3, 4, 5, 6],
        (3, 1): [3, 2, 13, 12, 11, 10, 9, 8, 7, 1],
        (3, 2): [3, 2],
        (3, 4): [3, 4],
        (3, 5): [3, 4, 5],
        (3, 6): [3, 4, 5, 6],
        (4, 1): [4, 3, 2, 13, 12, 11, 10, 9, 8, 7, 1],
        (4, 2): [4, 3, 2],
        (4, 3): [4, 3],
        (4, 5): [4, 5],
        (4, 6): [4, 5, 6],
        (5, 1): [5, 4, 3, 2, 13, 12, 11, 10, 9, 8, 7, 1],
        (5, 2): [5, 4, 3, 2],
        (5, 3): [5, 4, 3],
        (5, 4): [5, 4],
        (5, 6): [5, 6],
        (6, 1): [6, 5, 4, 3, 2, 13, 12, 11, 10, 9, 8, 7, 1],
        (6, 2): [6, 5, 4, 3, 2],
        (6, 3): [6, 5, 4, 3],
        (6, 4): [6, 5, 4],
        (6, 5): [6, 5],
    }

    def __init__(self, connection):
        """Initialize the switch with connection, MAC table, and default rules."""
        self.connection = connection
        self.mac_table = {}  # {mac: (dpid, port)}
        self.ip_to_mac = {}  # {ip: mac}
        self.pending_packets = {}  # {ip: [(event, packet, ipp, dpid, inport)]}
        connection.addListeners(self)
        self._install_default_rule()

    def _install_default_rule(self):
        """Install default flow rules for ARP and other packets."""
        # Rule for ARP: send to controller
        msg_arp = of.ofp_flow_mod()
        msg_arp.match = of.ofp_match()
        msg_arp.match.dl_type = ethernet.ARP_TYPE
        msg_arp.priority = 1000
        msg_arp.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        self.connection.send(msg_arp)
        log.debug("[Debug] Installed ARP rule on switch dpid=%s: send ARP packets to controller", self.connection.dpid)

        # Default rule: send all other packets to controller
        msg_default = of.ofp_flow_mod()
        msg_default.priority = 500
        msg_default.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        self.connection.send(msg_default)
        log.debug("[Debug] Installed default rule on switch dpid=%s: send all packets to controller", self.connection.dpid)

    def _get_path(self, src_switch, dst_switch):
        """Get the path (list of switches) from src_switch to dst_switch."""
        return self.routing_table.get((src_switch, dst_switch), [])

    def _get_outport(self, current_switch, next_switch):
        """Determine the output port to reach the next switch."""
        if current_switch == next_switch:
            return None
        if current_switch == 1: return 1  # s1 -> s7
        if current_switch == 7: return 2 if next_switch == 8 else 1  # s7 -> s8
        if current_switch == 8: return 2 if next_switch == 9 else 1  # s8 -> s9
        if current_switch == 9: return 2 if next_switch == 10 else 1  # s9 -> s10
        if current_switch == 10: return 2 if next_switch == 11 else 1  # s10 -> s11
        if current_switch == 11: return 2 if next_switch == 12 else 1  # s11 -> s12
        if current_switch == 12: return 2 if next_switch == 13 else 1  # s12 -> s13
        if current_switch == 13: return 2 if next_switch == 2 else 1  # s13 -> s2
        if current_switch == 2:
            if next_switch == 13: return 1  # s2 -> s13
            if next_switch == 3: return 2   # s2 -> s3
            return 3  # s2 -> hosts
        if current_switch == 3:
            if next_switch == 2: return 1   # s3 -> s2
            if next_switch == 4: return 2   # s3 -> s4
            return 3  # s3 -> hosts
        if current_switch == 4:
            if next_switch == 3: return 1   # s4 -> s3
            if next_switch == 5: return 2   # s4 -> s5
            return 3  # s4 -> hosts
        if current_switch == 5:
            if next_switch == 4: return 1   # s5 -> s4
            if next_switch == 6: return 2   # s5 -> s6
            return 3  # s5 -> hosts
        if current_switch == 6:
            if next_switch == 5: return 1   # s6 -> s5
            return 2  # s6 -> hosts
        return None

    def _handle_PacketIn(self, event):
        """Handle incoming packets from the switch."""
        packet = event.parsed
        if not packet:
            return

        inport = event.port
        switch_dpid = event.dpid
        self.mac_table[packet.src] = (switch_dpid, inport)

        if packet.type == ethernet.ARP_TYPE:
            self._handle_arp(event, packet, switch_dpid, inport)
        elif packet.type == ethernet.IP_TYPE:
            ipp = packet.find('ipv4')
            if ipp is None:
                return

            self.ip_to_mac[ipp.srcip] = packet.src
            self.ip_to_mac[ipp.dstip] = packet.dst if ipp.dstip in self.ip_to_mac else None

            src_subnet = subnet(ipp.srcip)
            dst_subnet = subnet(ipp.dstip)

            if src_subnet == dst_subnet:
                self._forward_within_subnet(event, packet, ipp, switch_dpid, inport)
            else:
                self._handle_obfuscation(event, packet, ipp, switch_dpid, inport)

    def _handle_obfuscation(self, event, packet, ipp, switch_dpid, inport):
        """Handle packet obfuscation along the path based on obfuscate_path."""
        # Handle flow mapping first to determine real_src_ip
        flow_id = int(str(ipp.srcip).split('.')[-1]) if str(ipp.srcip).startswith("10.0.") else None
        if flow_id is None or flow_id not in self.flow_mapping:
            if switch_dpid == 1:  # First switch in the path (s1)
                flow_id = self.next_flow_id
                self.flow_mapping[flow_id] = (ipp.srcip, [])
                self.next_flow_id += 1
            else:
                log.debug("[Debug] Switch dpid=%s: Flow ID %s not in flow_mapping, dropping packet from %s to %s", switch_dpid, flow_id, ipp.srcip, ipp.dstip)
                return

        real_src_ip, virtual_ips = self.flow_mapping[flow_id]
        src_subnet = subnet(real_src_ip)  # Use real_src_ip to determine source subnet
        dst_subnet = subnet(ipp.dstip)
        src_switch = self.subnet_to_switch.get(src_subnet)
        dst_switch = self.subnet_to_switch.get(dst_subnet)
        if not src_switch or not dst_switch:
            log.debug("[Debug] Switch dpid=%s: Cannot determine src/dst switch for %s -> %s (real src: %s)", switch_dpid, ipp.srcip, ipp.dstip, real_src_ip)
            return

        # Get the path from src_switch to dst_switch
        path = self._get_path(src_switch, dst_switch)
        if not path or switch_dpid not in path:
            log.debug("[Debug] Switch dpid=%s: No path found or switch not in path for %s -> %s", switch_dpid, ipp.srcip, ipp.dstip)
            return

        # Find the position of the current switch in the path
        current_pos = path.index(switch_dpid)

        # Determine if we should obfuscate at this switch
        if current_pos < _obfuscate_path and current_pos < len(path) - 1:
            # Obfuscate: change source IP
            new_virtual_ip = IPAddr("10.0.{}.{}".format(99 - current_pos, flow_id))
            virtual_ips.append(new_virtual_ip)
            self.flow_mapping[flow_id] = (real_src_ip, virtual_ips)
            log.debug("[Debug] Switch dpid=%s: Obfuscating source IP from %s to %s", switch_dpid, ipp.srcip, new_virtual_ip)
        else:
            new_virtual_ip = ipp.srcip  # No change if we've exceeded obfuscate_path

        # Check access rules at the last obfuscation point
        if current_pos == min(_obfuscate_path, len(path) - 2):
            if not is_allowed_access(real_src_ip, ipp.dstip):
                log.debug("[Debug] Switch dpid=%s: Access denied for packet from %s to %s", switch_dpid, real_src_ip, ipp.dstip)
                fm = of.ofp_flow_mod()
                fm.match = of.ofp_match.from_packet(packet, inport)
                fm.priority = 25
                self.connection.send(fm)
                return

        # Forward to the next switch
        next_switch = path[current_pos + 1] if current_pos < len(path) - 1 else None
        if next_switch:
            outport = self._get_outport(switch_dpid, next_switch)
            if not outport:
                log.debug("[Debug] Switch dpid=%s: No outport found to reach switch %s", switch_dpid, next_switch)
                return

            # Forward rule
            fm = of.ofp_flow_mod()
            fm.match = of.ofp_match.from_packet(packet, inport)
            if new_virtual_ip != ipp.srcip:
                fm.actions.append(of.ofp_action_nw_addr.set_src(new_virtual_ip))
            fm.actions.append(of.ofp_action_output(port=outport))
            fm.idle_timeout = IDLE_TIMEOUT
            fm.hard_timeout = HARD_TIMEOUT
            fm.priority = 65535
            fm.data = event.ofp
            self.connection.send(fm)
            log.debug("[Debug] Switch dpid=%s: Installed flow rule to forward ICMP from %s to %s via port %s, new src IP=%s", switch_dpid, ipp.srcip, ipp.dstip, outport, new_virtual_ip)

            # Return rule
            fm_back = of.ofp_flow_mod()
            fm_back.match = of.ofp_match()
            fm_back.match.dl_type = ethernet.IP_TYPE
            fm_back.match.nw_proto = ipp.protocol
            fm_back.match.nw_src = ipp.dstip
            fm_back.match.in_port = outport
            fm_back.match.icmp_type = 0
            fm_back.match.icmp_code = 0
            prev_virtual_ip = virtual_ips[-1] if virtual_ips else real_src_ip
            fm_back.actions.append(of.ofp_action_nw_addr.set_dst(prev_virtual_ip))
            fm_back.actions.append(of.ofp_action_output(port=inport))
            fm_back.idle_timeout = IDLE_TIMEOUT
            fm_back.hard_timeout = HARD_TIMEOUT
            fm_back.priority = 65535
            self.connection.send(fm_back)
            log.debug("[Debug] Switch dpid=%s: Installed return flow rule for ICMP from %s to %s via port %s", switch_dpid, ipp.dstip, prev_virtual_ip, inport)
        else:
            # Last switch: forward to destination host
            self._forward_to_destination(event, packet, ipp, switch_dpid, inport)  # Sửa lỗi đệ quy

    def _handle_arp(self, event, packet, switch_dpid, inport):
        """Handle ARP packets (requests and replies)."""
        arp_pkt = packet.find('arp')
        if not arp_pkt:
            return

        self.mac_table[arp_pkt.hwsrc] = (switch_dpid, inport)
        self.ip_to_mac[arp_pkt.protosrc] = arp_pkt.hwsrc

        if arp_pkt.opcode == arp.REQUEST:
            target_ip = arp_pkt.protodst
            log.debug("[Debug] Switch dpid=%s: Received ARP request for %s from %s (MAC %s) on port %s", 
                      switch_dpid, target_ip, arp_pkt.protosrc, arp_pkt.hwsrc, inport)
            
            # If the target IP is a virtual gateway, reply with the virtual MAC
            if target_ip in self.virtual_macs:
                virtual_mac = self.virtual_macs[target_ip]
                arp_reply = arp()
                arp_reply.opcode = arp.REPLY
                arp_reply.hwsrc = virtual_mac
                arp_reply.hwdst = arp_pkt.hwsrc
                arp_reply.protosrc = target_ip
                arp_reply.protodst = arp_pkt.protosrc

                eth_reply = ethernet()
                eth_reply.type = ethernet.ARP_TYPE
                eth_reply.src = virtual_mac
                eth_reply.dst = arp_pkt.hwsrc
                eth_reply.payload = arp_reply

                msg = of.ofp_packet_out()
                msg.data = eth_reply.pack()
                msg.actions.append(of.ofp_action_output(port=inport))
                self.connection.send(msg)
                log.debug("[Debug] Switch dpid=%s: Sent ARP reply for %s with MAC %s to %s (MAC %s) on port %s", 
                          switch_dpid, target_ip, virtual_mac, arp_pkt.protosrc, arp_pkt.hwsrc, inport)
                return

            # If the target IP is in a different subnet, reply with the gateway MAC
            src_subnet = subnet(arp_pkt.protosrc)
            dst_subnet = subnet(arp_pkt.protodst)
            if src_subnet != dst_subnet:
                gateway_ip = IPAddr("{}.254".format(src_subnet))
                gateway_mac = self.virtual_macs.get(gateway_ip, EthAddr("00:00:00:00:00:00"))
                arp_reply = arp()
                arp_reply.opcode = arp.REPLY
                arp_reply.hwsrc = gateway_mac
                arp_reply.hwdst = arp_pkt.hwsrc
                arp_reply.protosrc = target_ip
                arp_reply.protodst = arp_pkt.protosrc

                eth_reply = ethernet()
                eth_reply.type = ethernet.ARP_TYPE
                eth_reply.src = gateway_mac
                eth_reply.dst = arp_pkt.hwsrc
                eth_reply.payload = arp_reply

                msg = of.ofp_packet_out()
                msg.data = eth_reply.pack()
                msg.actions.append(of.ofp_action_output(port=inport))
                self.connection.send(msg)
                log.debug("[Debug] Switch dpid=%s: Sent ARP reply for %s (outside subnet) with gateway MAC %s to %s (MAC %s) on port %s", 
                          switch_dpid, target_ip, gateway_mac, arp_pkt.protosrc, arp_pkt.hwsrc, inport)
                return

        dst_mac = packet.dst
        if dst_mac.is_multicast:
            src_subnet = subnet(arp_pkt.protosrc)
            dst_subnet = subnet(arp_pkt.protodst)
            msg = of.ofp_packet_out(data=event.ofp, in_port=inport)
            if src_subnet == dst_subnet:
                for port in range(1, 8):
                    if port != inport:
                        msg.actions.append(of.ofp_action_output(port=port))
            else:
                dst_switch = self.subnet_to_switch.get(dst_subnet)
                if dst_switch:
                    outport = self._get_outport(switch_dpid, dst_switch)
                    if outport:
                        msg.actions.append(of.ofp_action_output(port=outport))
            self.connection.send(msg)
        else:
            if arp_pkt.opcode == arp.REPLY:
                log.debug("[Debug] Switch dpid=%s: Received ARP reply: %s is at %s on port %s", 
                          switch_dpid, arp_pkt.protosrc, arp_pkt.hwsrc, inport)
                self.mac_table[arp_pkt.hwsrc] = (switch_dpid, inport)
                self.ip_to_mac[arp_pkt.protosrc] = arp_pkt.hwsrc

                # Process pending packets waiting for this ARP reply
                target_ip = arp_pkt.protosrc
                if target_ip in self.pending_packets:
                    for pending_event, pending_packet, ipp, pending_dpid, pending_inport in self.pending_packets[target_ip]:
                        log.debug("[Debug] Switch dpid=%s: Processing pending packet for destination %s after receiving ARP reply", 
                                  switch_dpid, target_ip)
                        self._forward_to_destination(pending_event, pending_packet, ipp, pending_dpid, pending_inport)
                    del self.pending_packets[target_ip]

            if dst_mac in self.mac_table:
                out_dpid, outport = self.mac_table[dst_mac]
                if out_dpid == switch_dpid and outport != inport:
                    fm = of.ofp_flow_mod()
                    fm.match = of.ofp_match.from_packet(packet, inport)
                    fm.actions.append(of.ofp_action_output(port=outport))
                    fm.idle_timeout = IDLE_TIMEOUT
                    fm.hard_timeout = HARD_TIMEOUT
                    fm.priority = 10
                    fm.data = event.ofp
                    self.connection.send(fm)

    def _forward_within_subnet(self, event, packet, ipp, switch_dpid, inport):
        """Forward packets within the same subnet."""
        dst_mac = self.ip_to_mac.get(ipp.dstip)
        if not dst_mac or dst_mac not in self.mac_table:
            return

        out_dpid, outport = self.mac_table[dst_mac]
        if out_dpid != switch_dpid or outport == inport:
            return

        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match.from_packet(packet, inport)
        fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        fm.actions.append(of.ofp_action_output(port=outport))
        fm.idle_timeout = IDLE_TIMEOUT
        fm.hard_timeout = HARD_TIMEOUT
        fm.priority = 65535
        fm.data = event.ofp
        self.connection.send(fm)

    def _forward_to_destination(self, event, packet, ipp, switch_dpid, inport):
        """Forward packets to the destination host."""
        flow_id = int(str(ipp.srcip).split('.')[-1]) if str(ipp.srcip).startswith("10.0.") else None
        real_src_ip = self.flow_mapping.get(flow_id, (ipp.srcip, []))[0] if flow_id in self.flow_mapping else ipp.srcip

        dst_subnet = subnet(ipp.dstip)
        dst_switch = self.subnet_to_switch.get(dst_subnet)
        if not dst_switch:
            return

        if switch_dpid != dst_switch:
            log.debug("[Debug] Switch dpid=%s: Not the destination switch (%s), should not reach here", switch_dpid, dst_switch)
            return

        dst_mac = self.ip_to_mac.get(ipp.dstip)
        if not dst_mac or dst_mac not in self.mac_table:
            if ipp.dstip not in self.pending_packets:
                self.pending_packets[ipp.dstip] = []
            self.pending_packets[ipp.dstip].append((event, packet, ipp, switch_dpid, inport))
            log.debug("[Debug] Switch dpid=%s: Added packet to pending_packets, waiting for ARP reply for %s", 
                      switch_dpid, ipp.dstip)
            self._broadcast_arp_request(event, ipp.dstip, switch_dpid, inport)
            return

        out_dpid, outport = self.mac_table[dst_mac]
        if out_dpid != switch_dpid or outport == inport:
            return

        # Forward rule
        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match.from_packet(packet, inport)
        if real_src_ip and real_src_ip != ipp.srcip:
            fm.actions.append(of.ofp_action_nw_addr.set_src(real_src_ip))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        fm.actions.append(of.ofp_action_output(port=outport))
        fm.idle_timeout = IDLE_TIMEOUT
        fm.hard_timeout = HARD_TIMEOUT
        fm.priority = 65535
        fm.data = event.ofp
        self.connection.send(fm)
        log.debug("[Debug] Switch dpid=%s: Installed flow rule to forward ICMP directly to host %s (port %s), set dl_dst to %s", 
                  switch_dpid, ipp.dstip, outport, dst_mac)

        # Return rule
        fm_back = of.ofp_flow_mod()
        fm_back.match = of.ofp_match()
        fm_back.match.dl_type = ethernet.IP_TYPE
        fm_back.match.nw_proto = ipp.protocol
        fm_back.match.nw_src = ipp.dstip
        fm_back.match.nw_dst = real_src_ip if real_src_ip else ipp.srcip
        fm_back.match.in_port = outport
        fm_back.match.icmp_type = 0
        fm_back.match.icmp_code = 0
        fm_back.actions.append(of.ofp_action_output(port=inport))
        fm_back.idle_timeout = IDLE_TIMEOUT
        fm_back.hard_timeout = HARD_TIMEOUT
        fm_back.priority = 65535
        self.connection.send(fm_back)
        log.debug("[Debug] Switch dpid=%s: Installed return flow rule for ICMP from %s to %s via port %s", 
                  switch_dpid, ipp.dstip, real_src_ip if real_src_ip else ipp.srcip, inport)

    def _broadcast_arp_request(self, event, target_ip, switch_dpid, inport):
        """Broadcast an ARP request to resolve the target IP."""
        dst_subnet = subnet(target_ip)
        src_ip = IPAddr("{}.254".format(dst_subnet))
        src_mac = self.virtual_macs.get(src_ip, EthAddr("00:00:00:00:00:00"))

        arp_req = arp()
        arp_req.opcode = arp.REQUEST
        arp_req.protosrc = src_ip
        arp_req.protodst = target_ip
        arp_req.hwsrc = src_mac
        arp_req.hwdst = EthAddr("ff:ff:ff:ff:ff:ff")

        eth = ethernet()
        eth.type = ethernet.ARP_TYPE
        eth.src = src_mac
        eth.dst = EthAddr("ff:ff:ff:ff:ff:ff")
        eth.payload = arp_req

        msg = of.ofp_packet_out()
        msg.data = eth.pack()

        if switch_dpid == 2 and dst_subnet == "10.0.1":
            for port in [3, 4, 5, 6, 7]:
                if port != inport:
                    msg.actions.append(of.ofp_action_output(port=port))
                    log.debug("[Debug] Switch dpid=%s: Sending ARP request for %s to port %s", switch_dpid, target_ip, port)
        else:
            for port in range(1, 8):
                if port != inport:
                    msg.actions.append(of.ofp_action_output(port=port))
                    log.debug("[Debug] Switch dpid=%s: Sending ARP request for %s to port %s", switch_dpid, target_ip, port)

        self.connection.send(msg)

def launch(obfuscate_path="3"):
    """Start the controller and listen for switch connections."""
    global _obfuscate_path
    try:
        _obfuscate_path = int(obfuscate_path)
        if _obfuscate_path < 0:
            raise ValueError("obfuscate_path must be non-negative")
    except ValueError as e:
        log.error("Invalid obfuscate_path value: %s. Using default value 3.", e)
        _obfuscate_path = 3
    log.info("[FlowObfuscate] Using obfuscate_path=%d", _obfuscate_path)

    def start_switch(event):
        FlowObfuscateSwitch(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("[FlowObfuscate] Started.")
