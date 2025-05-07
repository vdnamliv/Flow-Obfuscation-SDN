from mininet.topo import Topo

class K7Topo(Topo):
    def build(self):
        # Switches
        s1 = self.addSwitch('s1')  # Subnet 10.0.0.0/24 (h1-h5)
        s2 = self.addSwitch('s2')  # Subnet 10.0.1.0/24 (h6-h10)
        s3 = self.addSwitch('s3')  # Subnet 10.0.2.0/24 (h11-h15)
        s4 = self.addSwitch('s4')  # Subnet 10.0.3.0/24 (h16-h20)
        s5 = self.addSwitch('s5')  # Subnet 10.0.4.0/24 (h21-h25)
        s6 = self.addSwitch('s6')  # Subnet 10.0.5.0/24 (h26-h30)
        s7 = self.addSwitch('s7')  # Obfuscation path
        s8 = self.addSwitch('s8')  # Obfuscation path
        s9 = self.addSwitch('s9')  # Obfuscation path
        s10 = self.addSwitch('s10')  # Obfuscation path
        s11 = self.addSwitch('s11')  # Obfuscation path
        s12 = self.addSwitch('s12')  # Obfuscation path
        s13 = self.addSwitch('s13')  # Obfuscation path

        # Kết nối các switch
        self.addLink(s1, s7)
        self.addLink(s7, s8)
        self.addLink(s8, s9)
        self.addLink(s9, s10)
        self.addLink(s10, s11)
        self.addLink(s11, s12)
        self.addLink(s12, s13)
        self.addLink(s13, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s4, s5)
        self.addLink(s5, s6)

        # Hosts
        for i in range(1, 6):
            h = self.addHost(f'h{i}', ip=f'10.0.0.{i}/24', defaultRoute='via 10.0.0.254')
            self.addLink(h, s1)
        for i in range(6, 11):
            h = self.addHost(f'h{i}', ip=f'10.0.1.{i-5}/24', defaultRoute='via 10.0.1.254')
            self.addLink(h, s2)
        for i in range(11, 16):
            h = self.addHost(f'h{i}', ip=f'10.0.2.{i-10}/24', defaultRoute='via 10.0.2.254')
            self.addLink(h, s3)
        for i in range(16, 21):
            h = self.addHost(f'h{i}', ip=f'10.0.3.{i-15}/24', defaultRoute='via 10.0.3.254')
            self.addLink(h, s4)
        for i in range(21, 26):
            h = self.addHost(f'h{i}', ip=f'10.0.4.{i-20}/24', defaultRoute='via 10.0.4.254')
            self.addLink(h, s5)
        for i in range(26, 31):
            h = self.addHost(f'h{i}', ip=f'10.0.5.{i-25}/24', defaultRoute='via 10.0.5.254')
            self.addLink(h, s6)

topos = { 'k7topo': (lambda: K7Topo()) }
