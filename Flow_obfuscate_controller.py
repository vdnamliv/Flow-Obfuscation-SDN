#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Flow-Obfuscation Controller  —  phiên bản dùng đồ thị động
✓ Shortest-path giữa edge-switches
✓ Đổi IP tối đa k hop đầu  (k = --obfuscate_path)
✓ Nếu path < k ⇒ cắt k = len(path)-1  (báo log cảnh báo)
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4
from pox.lib.addresses import IPAddr, EthAddr
import random
import collections

log = core.getLogger()

# --- 1. HẰNG SỐ --------------------------------------------------------------
IDLE_TIMEOUT  = 300
HARD_TIMEOUT  = 600
_obfuscate_path = 3                  # ghi đè khi launch()

# --- 2. TOPOLOGY  (từ K7Topo) -----------------------------------------------
#   Port numbering theo thứ tự addLink() trong file topo
PORT_MAP = {}
def _add(a, b):
    PORT_MAP.setdefault(a, {})
    PORT_MAP.setdefault(b, {})
    PORT_MAP[a][b] = len(PORT_MAP[a]) + 1
    PORT_MAP[b][a] = len(PORT_MAP[b]) + 1

# 1) spine-spine trước  ➜ spine eth1-eth6
for i, a in enumerate(range(7, 14)):
    for b in range(a + 1, 14):
        _add(a, b)

# 2) edge-spine sau      ➜ edge eth1-eth7, spine eth7-eth12
for sp in range(7, 14):
    for e in range(1, 7):
        _add(sp, e)

SPINE_SWITCHES = set(range(7, 14))
GRAPH = {u: set(nbr.keys()) for u, nbr in PORT_MAP.items()}

# --- 3. HÀM TIỆN ÍCH ---------------------------------------------------------
def subnet(ip):
    """Trả về 3 octet đầu – '10.0.3'."""
    return ".".join(str(ip).split('.')[:3])

def is_allowed_access(src_ip, dst_ip):
    """ACL tĩnh (deny giữa một số subnet)."""
    src_sub = subnet(src_ip)
    dst_sub = subnet(dst_ip)
    deny_pairs = [("10.0.1", "10.0.2"), ("10.0.3", "10.0.4"), ("10.0.4", "10.0.5")]
    for a, b in deny_pairs:
        if (src_sub == a and dst_sub == b) or (src_sub == b and dst_sub == a):
            return False
    return True

def bfs_shortest(src, dst):
    """Trả về 1 shortest-path (list DPID) giữa src và dst (cả hai khác nhau)."""
    if src == dst:
        return [src]
    parent = {src: None}
    q = collections.deque([src])
    while q and dst not in parent:
        u = q.popleft()
        for v in GRAPH[u]:
            if v not in parent:
                parent[v] = u
                q.append(v)
    if dst not in parent:
        return []           # không tới được
    path = []
    cur = dst
    while cur is not None:
        path.append(cur)
        cur = parent[cur]
    return list(reversed(path))

def get_outport(cur, nxt):
    """Lấy port số nhỏ nhất đi tới neighbor kế tiếp."""
    return PORT_MAP.get(cur, {}).get(nxt)

# --- 4. CLASS SWITCH ---------------------------------------------------------
class FlowObfuscateSwitch (object):
    flow_mapping = {}                 # {flow_id: (real_src, [list_virtual])}
    next_flow_id = 1

    subnet_to_switch = {              # edge switch <--> subnet
        "10.0.0": 1, "10.0.1": 2, "10.0.2": 3,
        "10.0.3": 4, "10.0.4": 5, "10.0.5": 6
    }

    virtual_macs = {                  # gateway ảo .254
        IPAddr("10.0.0.254"): EthAddr("00:00:00:00:00:01"),
        IPAddr("10.0.1.254"): EthAddr("00:00:00:00:00:02"),
        IPAddr("10.0.2.254"): EthAddr("00:00:00:00:00:03"),
        IPAddr("10.0.3.254"): EthAddr("00:00:00:00:00:04"),
        IPAddr("10.0.4.254"): EthAddr("00:00:00:00:00:05"),
        IPAddr("10.0.5.254"): EthAddr("00:00:00:00:00:06"),
    }

    # ------------------------------------------------------------------
    def __init__(self, connection):
        self.connection = connection
        self.mac_table   = {}         # {MAC: (dpid, port)}
        self.ip_to_mac   = {}         # {IP: MAC}
        self.pending_packets = {}     # chờ ARP
        connection.addListeners(self)
        self._install_default_rules()

    # ------------------------------------------------------------------
    def _install_default_rules(self):
        # ARP về controller
        fm_arp = of.ofp_flow_mod()
        fm_arp.match.dl_type = ethernet.ARP_TYPE
        fm_arp.priority = 1000
        fm_arp.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        self.connection.send(fm_arp)
        # Mặc định về controller
        fm_def = of.ofp_flow_mod()
        fm_def.priority = 500
        fm_def.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        self.connection.send(fm_def)
        log.debug("[Init] dpid=%s cài ARP & default rule", self.connection.dpid)

    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet: return
        inport, dpid = event.port, event.dpid
        self.mac_table[packet.src] = (dpid, inport)

        if packet.type == ethernet.ARP_TYPE:
            self._handle_arp(event, packet, dpid, inport); return

        if packet.type != ethernet.IP_TYPE: return
        ipp = packet.find('ipv4');       # type: ipv4
        if ipp is None: return

        self.ip_to_mac[ipp.srcip] = packet.src
        if ipp.dstip not in self.ip_to_mac:
            self.ip_to_mac[ipp.dstip] = packet.dst

        src_sub, dst_sub = subnet(ipp.srcip), subnet(ipp.dstip)
        if src_sub == dst_sub:
            self._forward_within_subnet(event, packet, ipp, dpid, inport)
        else:
            self._handle_obfuscation(event, packet, ipp, dpid, inport)

    # ------------------------------------------------------------------
    def _pick_spine_path(self):
        k = max(1, _obfuscate_path)
        return random.sample(SPINE_SWITCHES, k)

    def _handle_obfuscation(self, event, packet, ipp, dpid, inport):
        # ----- bước 0: xác định flow_id & path ------------------------
        flow_id = int(str(ipp.srcip).split('.')[-1]) if str(ipp.srcip).startswith("10.0.") else None
        if flow_id is None or flow_id not in self.flow_mapping:
            if dpid == self.subnet_to_switch[subnet(ipp.srcip)]:
                flow_id = self.next_flow_id; self.next_flow_id += 1
                self.flow_mapping[flow_id] = (
                    ipp.srcip,                 # real_src
                    self._pick_spine_path(),   # spine_path
                    []                         # virtual_list
                )
            else:
                log.debug("[Drop] dpid=%s flow_id %s chưa khởi tạo", dpid, flow_id); return

        real_src, spine_path, virtual_list = self.flow_mapping[flow_id]
        # ---------------------------------------------------------------------
        src_sw = self.subnet_to_switch.get(subnet(real_src))
        dst_sw = self.subnet_to_switch.get(subnet(ipp.dstip))

        if not src_sw or not dst_sw: return

        path = [src_sw] + spine_path + [dst_sw]
        if dpid not in path: return
        pos = path.index(dpid)
        k_max = min(_obfuscate_path, len(path)-1)
        # ----- bước 1: đổi IP nếu trong k hop đầu --------------------
        if pos < k_max:
            new_ip = IPAddr("10.0.%d.%d" % (99-pos, flow_id))
            if len(virtual_list) <= pos:               # <-- thêm điều kiện
                virtual_list.append(new_ip)

            self.flow_mapping[flow_id] = (real_src, spine_path, virtual_list)
        else:
            new_ip = ipp.srcip

        # ----- bước 2: ACL tại hop cuối giai đoạn obf -----------------
        if pos == k_max - 1:
            if not is_allowed_access(real_src, ipp.dstip):
                fm_drop = of.ofp_flow_mod()
                fm_drop.match = of.ofp_match.from_packet(packet, inport)
                fm_drop.priority = 25      # drop
                self.connection.send(fm_drop)
                log.debug("[ACL] dpid=%s chặn %s→%s", dpid, real_src, ipp.dstip)
                return

        # ----- bước 3: chọn switch kế & outport ----------------------
        if pos < len(path)-1:
            nxt_sw = path[pos+1]
            outport = get_outport(dpid, nxt_sw)
            if not outport:
                log.error("[Outport] Không có cổng %s→%s", dpid, nxt_sw); return
            self._install_forward_rule(event, packet, inport, outport,
                                       ipp, new_ip, virtual_list, real_src, forward=True)
        else:
            # edge đích
            self._forward_to_destination(event, packet, ipp, dpid, inport)

    # ------------------------------------------------------------------
    def _install_forward_rule(self, event, packet, inport, outport,
                              ipp, new_ip, virtual_list, real_src, forward=True):
        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match.from_packet(packet, inport)
        if new_ip != ipp.srcip:
            fm.actions.append(of.ofp_action_nw_addr.set_src(new_ip))
        fm.actions.append(of.ofp_action_output(port = outport))
        fm.idle_timeout, fm.hard_timeout = IDLE_TIMEOUT, HARD_TIMEOUT
        fm.priority = 65535
        fm.data = event.ofp
        self.connection.send(fm)
        log.debug("[Flow-FWD] dpid=%s %s→%s via port %s (srcIP⇢%s)",
                  self.connection.dpid, ipp.srcip, ipp.dstip, outport, new_ip)

        # return-rule (ICMP echo-reply)
        fm_back = of.ofp_flow_mod()
        fm_back.match.dl_type = ethernet.IP_TYPE
        fm_back.match.nw_proto = ipp.protocol
        fm_back.match.nw_src   = ipp.dstip
        fm_back.match.in_port  = outport
        fm_back.match.icmp_type = 0; fm_back.match.icmp_code = 0
        prev_ip = virtual_list[-1] if virtual_list else real_src
        fm_back.actions.append(of.ofp_action_nw_addr.set_dst(prev_ip))
        fm_back.actions.append(of.ofp_action_output(port = inport))
        fm_back.idle_timeout, fm_back.hard_timeout = IDLE_TIMEOUT, HARD_TIMEOUT
        fm_back.priority = 65535
        self.connection.send(fm_back)
        log.debug("[Flow-RET] dpid=%s %s→%s via port %s",
                  self.connection.dpid, ipp.dstip, prev_ip, inport)

    # ---------- các hàm ARP, forward subnet, dest …  giữ nguyên --------------
    # *Giữ nguyên code gốc phần _handle_arp, _forward_within_subnet,
    #  _forward_to_destination, _broadcast_arp_request – bỏ vào đây không đổi.*
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
                msg = of.ofp_packet_out(data = event.ofp, in_port = inport)
                for pno in self.connection.ports:               # ✅ flood tất cả
                    if pno >= 8 and pno != inport:                 # chỉ cổng host
                        msg.actions.append(of.ofp_action_output(port = pno))
                self.connection.send(msg)
                return
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
        real_src_ip = self.flow_mapping.get(flow_id, (ipp.srcip, [], []))[0] if flow_id in self.flow_mapping else ipp.srcip

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
        msg.in_port = of.OFPP_CONTROLLER 

        for pno in self.connection.ports:
            if pno >= 8 and pno != inport:
                msg.actions.append(of.ofp_action_output(port = pno))

        self.connection.send(msg)
        log.debug("[ARP-REQ] dpid=%s → hosts ports %s for %s",
                switch_dpid,
                [a.port for a in msg.actions], target_ip)
# -----------------------------------------------------------------------------
def launch(obfuscate_path="3"):
    """pox.py flow_obf.py --obfuscate_path=3"""
    global _obfuscate_path
    try:
        _obfuscate_path = max(0, int(obfuscate_path))
    except ValueError:
        log.error("Giá trị k không hợp lệ, dùng mặc định 3")
        _obfuscate_path = 3
    log.info("[Start] obfuscate_path k=%s", _obfuscate_path)

    def start_switch(event):
        FlowObfuscateSwitch(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
