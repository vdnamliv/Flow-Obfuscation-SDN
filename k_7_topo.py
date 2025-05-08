# -*- coding: utf-8 -*-
"""
Clos 2-tier topo với 6 edge switch và 3 spine switch, delay mặc định 5ms/link
"""

from mininet.topo import Topo
from mininet.link import TCLink
from functools import partial

class K7Topo(Topo):
    def build(self, delay='5ms'):
        link = partial(self.addLink, cls=TCLink, delay=delay, bw=100)

        # ---------- switches ----------
        edges  = [self.addSwitch(f's{i}') for i in range(1, 7)]   # s1..s6
        spines = [self.addSwitch(f's{i}') for i in range(7, 14)]  # s7..s13

        # ---------- 1. full-mesh spine-spine ----------
        for i, a in enumerate(spines):
            for b in spines[i+1:]:
                link(a, b)          # tạo 21 link, chiếm eth1-eth6 trên spine

        # ---------- 2. edge-spine uplink ----------
        for e in edges:             # s1..s6
            for sp in spines:       # s7..s13
                link(e, sp)         # sX-eth1..eth7  |  spine eth7..eth12

        # ---------- 3. hosts ----------
        host_id = 1
        for subnet, edge in enumerate(edges):    # 0..5
            for n in range(1, 6):                # h1-h5 mỗi edge
                h = self.addHost(f'h{host_id}',
                                 ip=f'10.0.{subnet}.{n}/24',
                                 defaultRoute=f'via 10.0.{subnet}.254')
                link(h, edge)
                host_id += 1

topos = {'k7topo': lambda: K7Topo()}
