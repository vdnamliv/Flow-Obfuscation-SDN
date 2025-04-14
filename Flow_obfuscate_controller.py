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
    flow_mapping = {}  # {flow_id: (real_src_ip, [virtual_ip1, virtual_ip2])}
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
            elif switch_dpid == 1:
                self._handle_s1(event, packet, ipp, inport)
            elif switch_dpid == 7:
                self._handle_s7(event, packet, ipp, inport)
            elif switch_dpid == 8:
                self._handle_s8(event, packet, ipp, inport)
            else:
                self._forward_to_destination(event, packet, ipp, switch_dpid, inport)

            # Handle ICMP reply packets that don't match existing flow rules
            icmp_packet = packet.find('icmp')
            if icmp_packet and icmp_packet.type == 0:  # ICMP Echo Reply
                log.debug("[Debug] Switch dpid=%s: Received ICMP Echo Reply from %s to %s on port %s", 
                          switch_dpid, ipp.srcip, ipp.dstip, inport)
                if switch_dpid == 8 and inport == 2:  # From s2 to s8
                    flow_id = int(str(ipp.dstip).split('.')[-1]) if str(ipp.dstip).startswith("10.0.0") else None
                    if flow_id and flow_id in FlowObfuscateSwitch.flow_mapping:
                        real_src_ip, virtual_ips = FlowObfuscateSwitch.flow_mapping[flow_id]
                        virtual_ip2 = virtual_ips[1]
                        fm = of.ofp_flow_mod()
                        fm.match = of.ofp_match()
                        fm.match.dl_type = ethernet.IP_TYPE
                        fm.match.nw_proto = ipp.protocol
                        fm.match.nw_src = ipp.srcip
                        fm.match.in_port = inport
                        fm.match.icmp_type = 0
                        fm.match.icmp_code = 0
                        fm.actions.append(of.ofp_action_nw_addr.set_dst(virtual_ip2))
                        fm.actions.append(of.ofp_action_output(port=1))
                        fm.idle_timeout = IDLE_TIMEOUT
                        fm.hard_timeout = HARD_TIMEOUT
                        fm.priority = 65535
                        fm.data = event.ofp
                        self.connection.send(fm)
                        log.debug("[Debug] Switch dpid=8: Installed ad-hoc flow rule for ICMP reply from %s to %s via port 1", ipp.srcip, virtual_ip2)
                elif switch_dpid == 7 and inport == 2:  # From s8 to s7
                    flow_id = int(str(ipp.dstip).split('.')[-1])
                    if flow_id in FlowObfuscateSwitch.flow_mapping:
                        real_src_ip, virtual_ips = FlowObfuscateSwitch.flow_mapping[flow_id]
                        virtual_ip1 = virtual_ips[0]
                        fm = of.ofp_flow_mod()
                        fm.match = of.ofp_match()
                        fm.match.dl_type = ethernet.IP_TYPE
                        fm.match.nw_proto = ipp.protocol
                        fm.match.nw_src = ipp.srcip
                        fm.match.in_port = inport
                        fm.match.icmp_type = 0
                        fm.match.icmp_code = 0
                        fm.actions.append(of.ofp_action_nw_addr.set_dst(virtual_ip1))
                        fm.actions.append(of.ofp_action_output(port=1))
                        fm.idle_timeout = IDLE_TIMEOUT
                        fm.hard_timeout = HARD_TIMEOUT
                        fm.priority = 65535
                        fm.data = event.ofp
                        self.connection.send(fm)
                        log.debug("[Debug] Switch dpid=7: Installed ad-hoc flow rule for ICMP reply from %s to %s via port 1", ipp.srcip, virtual_ip1)
                elif switch_dpid == 1 and inport == 1:  # From s7 to s1
                    flow_id = int(str(ipp.dstip).split('.')[-1])
                    if flow_id in FlowObfuscateSwitch.flow_mapping:
                        real_src_ip, virtual_ips = FlowObfuscateSwitch.flow_mapping[flow_id]
                        fm = of.ofp_flow_mod()
                        fm.match = of.ofp_match()
                        fm.match.dl_type = ethernet.IP_TYPE
                        fm.match.nw_proto = ipp.protocol
                        fm.match.nw_src = ipp.srcip
                        fm.match.in_port = inport
                        fm.match.icmp_type = 0
                        fm.match.icmp_code = 0
                        fm.actions.append(of.ofp_action_nw_addr.set_dst(real_src_ip))
                        fm.actions.append(of.ofp_action_output(port=2))
                        fm.idle_timeout = IDLE_TIMEOUT
                        fm.hard_timeout = HARD_TIMEOUT
                        fm.priority = 65535
                        fm.data = event.ofp
                        self.connection.send(fm)
                        log.debug("[Debug] Switch dpid=1: Installed ad-hoc flow rule for ICMP reply from %s to %s via port 2", ipp.srcip, real_src_ip)

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

    def _handle_s1(self, event, packet, ipp, inport):
        """Handle packets on switch s1: obfuscate source IP and forward to s7."""
        flow_id = FlowObfuscateSwitch.next_flow_id
        virtual_ip1 = IPAddr("10.0.99.{}".format(flow_id))
        FlowObfuscateSwitch.flow_mapping[flow_id] = (ipp.srcip, [virtual_ip1])
        FlowObfuscateSwitch.next_flow_id += 1

        # Forward rule: change source IP to virtual_ip1 and send to s7
        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match.from_packet(packet, inport)
        fm.actions.append(of.ofp_action_nw_addr.set_src(virtual_ip1))
        fm.actions.append(of.ofp_action_output(port=1))
        fm.idle_timeout = IDLE_TIMEOUT
        fm.hard_timeout = HARD_TIMEOUT
        fm.priority = 65535
        fm.data = event.ofp
        self.connection.send(fm)
        log.debug("[Debug] Switch dpid=1: Installed flow rule to forward ICMP from %s to %s via s7 (port 1), new src IP=%s", ipp.srcip, ipp.dstip, virtual_ip1)

        # Return rule: handle ICMP reply from dst to src
        fm_back = of.ofp_flow_mod()
        fm_back.match = of.ofp_match()
        fm_back.match.dl_type = ethernet.IP_TYPE
        fm_back.match.nw_proto = ipp.protocol  # Match ICMP
        fm_back.match.nw_src = ipp.dstip  # Source IP of reply (e.g., 10.0.1.1)
        fm_back.match.in_port = 1  # From s7 (s1-eth1)
        fm_back.match.icmp_type = 0
        fm_back.match.icmp_code = 0
        fm_back.actions.append(of.ofp_action_nw_addr.set_dst(ipp.srcip))
        fm_back.actions.append(of.ofp_action_output(port=inport))
        fm_back.idle_timeout = IDLE_TIMEOUT
        fm_back.hard_timeout = HARD_TIMEOUT
        fm_back.priority = 65535
        self.connection.send(fm_back)
        log.debug("[Debug] Switch dpid=1: Installed return flow rule for ICMP from %s to %s via port %s", ipp.dstip, ipp.srcip, inport)

    def _handle_s7(self, event, packet, ipp, inport):
        """Handle packets on switch s7: further obfuscate source IP and forward to s8."""
        flow_id = int(str(ipp.srcip).split('.')[-1])
        if flow_id not in FlowObfuscateSwitch.flow_mapping:
            log.debug("[Debug] Switch dpid=7: Flow ID %s not in flow_mapping, dropping packet from %s to %s", flow_id, ipp.srcip, ipp.dstip)
            return

        real_src_ip, virtual_ips = FlowObfuscateSwitch.flow_mapping[flow_id]
        virtual_ip1 = virtual_ips[0]
        virtual_ip2 = IPAddr("10.0.98.{}".format(flow_id))
        FlowObfuscateSwitch.flow_mapping[flow_id] = (real_src_ip, [virtual_ip1, virtual_ip2])

        # Forward rule: change source IP to virtual_ip2 and send to s8
        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match.from_packet(packet, inport)
        fm.actions.append(of.ofp_action_nw_addr.set_src(virtual_ip2))
        fm.actions.append(of.ofp_action_output(port=2))
        fm.idle_timeout = IDLE_TIMEOUT
        fm.hard_timeout = HARD_TIMEOUT
        fm.priority = 65535
        fm.data = event.ofp
        self.connection.send(fm)
        log.debug("[Debug] Switch dpid=7: Installed flow rule to forward ICMP from %s to %s via s8 (port 2), new src IP=%s", ipp.srcip, ipp.dstip, virtual_ip2)

        # Return rule: handle ICMP reply from dst to virtual_ip1
        fm_back = of.ofp_flow_mod()
        fm_back.match = of.ofp_match()
        fm_back.match.dl_type = ethernet.IP_TYPE
        fm_back.match.nw_proto = ipp.protocol  # Match ICMP
        fm_back.match.nw_src = ipp.dstip  # Source IP of reply (e.g., 10.0.1.1)
        fm_back.match.in_port = 2  # From s8 (s7-eth2)
        fm_back.match.icmp_type = 0
        fm_back.match.icmp_code = 0
        fm_back.actions.append(of.ofp_action_nw_addr.set_dst(virtual_ip1))
        fm_back.actions.append(of.ofp_action_output(port=1))
        fm_back.idle_timeout = IDLE_TIMEOUT
        fm_back.hard_timeout = HARD_TIMEOUT
        fm_back.priority = 65535
        self.connection.send(fm_back)
        log.debug("[Debug] Switch dpid=7: Installed return flow rule for ICMP from %s to %s via port 1", ipp.dstip, virtual_ip1)

    def _handle_s8(self, event, packet, ipp, inport):
        """Handle packets on switch s8: check access, forward to s2."""
        flow_id = int(str(ipp.srcip).split('.')[-1])
        if flow_id not in FlowObfuscateSwitch.flow_mapping:
            log.debug("[Debug] Switch dpid=8: Flow ID %s not in flow_mapping, dropping packet from %s to %s", flow_id, ipp.srcip, ipp.dstip)
            return

        real_src_ip, virtual_ips = FlowObfuscateSwitch.flow_mapping[flow_id]
        virtual_ip2 = virtual_ips[1]

        # Check if access is allowed between source and destination
        if not is_allowed_access(real_src_ip, ipp.dstip):
            log.debug("[Debug] Switch dpid=8: Access denied for packet from %s to %s", real_src_ip, ipp.dstip)
            fm = of.ofp_flow_mod()
            fm.match = of.ofp_match.from_packet(packet, inport)
            fm.priority = 25
            self.connection.send(fm)
            return

        dst_subnet = subnet(ipp.dstip)
        dst_switch = FlowObfuscateSwitch.subnet_to_switch.get(dst_subnet)
        if not dst_switch:
            log.debug("[Debug] Switch dpid=8: No dst_switch found for subnet %s, dropping packet from %s to %s", dst_subnet, real_src_ip, ipp.dstip)
            return

        # Forward rule: send to s2 (port 2)
        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match.from_packet(packet, inport)
        fm.actions.append(of.ofp_action_output(port=2))
        fm.idle_timeout = IDLE_TIMEOUT
        fm.hard_timeout = HARD_TIMEOUT
        fm.priority = 65535
        fm.data = event.ofp
        self.connection.send(fm)
        log.debug("[Debug] Switch dpid=8: Installed flow rule to forward ICMP from %s to %s via s2 (port 2)", real_src_ip, ipp.dstip)

        # Return rule: handle ICMP reply from dst to original src_ip (10.0.0.1)
        fm_back = of.ofp_flow_mod()
        fm_back.match = of.ofp_match()
        fm_back.match.dl_type = ethernet.IP_TYPE
        fm_back.match.nw_proto = ipp.protocol  # Match ICMP
        fm_back.match.nw_src = ipp.dstip  # Source IP of reply (e.g., 10.0.1.1)
        fm_back.match.in_port = 2  # From s2 (s8-eth2)
        fm_back.match.icmp_type = 0
        fm_back.match.icmp_code = 0
        fm_back.actions.append(of.ofp_action_nw_addr.set_dst(virtual_ip2))
        fm_back.actions.append(of.ofp_action_output(port=1))  # To s7 (s8-eth1)
        fm_back.idle_timeout = IDLE_TIMEOUT
        fm_back.hard_timeout = HARD_TIMEOUT
        fm_back.priority = 65535
        self.connection.send(fm_back)
        log.debug("[Debug] Switch dpid=8: Installed return flow rule for ICMP from %s to %s via port 1 (s8-eth1)", ipp.dstip, real_src_ip)

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
        """Forward packets to the destination switch or host."""
        flow_id = int(str(ipp.srcip).split('.')[-1])
        real_src_ip = FlowObfuscateSwitch.flow_mapping.get(flow_id, (None, None))[0] if flow_id in FlowObfuscateSwitch.flow_mapping else ipp.srcip

        dst_subnet = subnet(ipp.dstip)
        dst_switch = FlowObfuscateSwitch.subnet_to_switch.get(dst_subnet)
        if not dst_switch:
            return

        # If the packet is on the destination switch, forward to the host
        if switch_dpid == dst_switch:
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

            # Forward rule: set real source IP and destination MAC, then output
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

            # Return rule: handle ICMP reply from dst to src
            fm_back = of.ofp_flow_mod()
            fm_back.match = of.ofp_match()
            fm_back.match.dl_type = ethernet.IP_TYPE
            fm_back.match.nw_proto = ipp.protocol  # Match ICMP
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
            return

        # Forward to the next switch
        outport = self._get_outport(switch_dpid, dst_switch)
        if not outport:
            return

        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match.from_packet(packet, inport)
        if real_src_ip and real_src_ip != ipp.srcip:
            fm.actions.append(of.ofp_action_nw_addr.set_src(real_src_ip))
        fm.actions.append(of.ofp_action_output(port=outport))
        fm.idle_timeout = IDLE_TIMEOUT
        fm.hard_timeout = HARD_TIMEOUT
        fm.priority = 65535
        fm.data = event.ofp
        self.connection.send(fm)

        fm_back = of.ofp_flow_mod()
        fm_back.match = of.ofp_match()
        fm_back.match.dl_type = ethernet.IP_TYPE
        fm_back.match.nw_proto = ipp.protocol  # Match ICMP
        fm_back.match.nw_src = ipp.dstip
        fm_back.match.nw_dst = real_src_ip if real_src_ip else ipp.srcip
        fm_back.actions.append(of.ofp_action_output(port=inport))
        fm_back.idle_timeout = IDLE_TIMEOUT
        fm_back.hard_timeout = HARD_TIMEOUT
        fm_back.priority = 65535
        self.connection.send(fm_back)

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

    def _get_outport(self, switch_dpid, dst_switch):
        """Determine the output port to reach the destination switch."""
        if switch_dpid == dst_switch:
            return None
        if switch_dpid == 1: return 1
        if switch_dpid == 7: return 2
        if switch_dpid == 8: return 2
        if switch_dpid == 2:
            if dst_switch == 1: return 1
            return 2
        if switch_dpid == 3:
            if dst_switch in [1, 2]: return 1
            return 2
        if switch_dpid == 4:
            if dst_switch in [1, 2, 3]: return 1
            return 2
        if switch_dpid == 5:
            if dst_switch in [1, 2, 3, 4]: return 1
            return 2
        if switch_dpid == 6:
            return 1
        return None

def launch():
    """Start the controller and listen for switch connections."""
    def start_switch(event):
        FlowObfuscateSwitch(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("[FlowObfuscate] Started.")
