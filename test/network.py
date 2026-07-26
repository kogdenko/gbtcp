#!/usr/bin/python

# SPDX-License-Identifier: LGPL-2.1-only

import math
import ipaddress

from common import *

class Network:
    def __init__(self, cp=None):
        self.ip_network = None
        self.interface = None
        self.config = ""

        if cp != None:
            self.set_ip_network(cp.ip_network)
            self.gw_mac = cp.gw_mac
            self.interface = cp.interface

    def set_gw_mac(self, gw_mac):
        self.gw_mac = gw_mac

    def set_interface(self, interface):
        self.interface = interface

    def set_ip_network(self, ip_network):
        ip_network = ipaddress.ip_network(ip_network)
        if self.ip_network == ip_network:
            return
        self.ip_network = ip_network
        self.first_client, *_, self.last_client, self.server = self.ip_network.hosts()

    def _configure_server_routing(self):
        self.reset_routing()
        self.ip_a_a(self.server)
        self.ip_r_a(str(self.first_client) + "/32")
        self.ip_r_a(self.ip_network, self.first_client)

    def _configure_client_routing(self):
        self.reset_routing()
        for client in self.clients:
            for a in range(int(client[0]), int(client[1] + 1)):
                address = ipaddress.ip_address(a)
                self.ip_a_a(address)
        self.ip_r_a(self.ip_network)
 
    def configure(self, mode, concurrency, cpus):
        assert(self.interface != None)
        assert(self.ip_network != None)

        n = math.ceil(concurrency/cpus/self.local_ports_per_addr)
    
        if mode == Mode.SERVER:
            self._configure_server_routing()
        else:
            self.clients = []
            first = self.first_client
            for _ in range(0, cpus):
                last = first + n - 1
                if last > self.server:
                    raise RuntimeError(f"Out of ips ('{self.ip_network}')")
                self.clients.append([first, last])
                first = last + 1
            self._configure_client_routing()

class LinuxNetwork(Network):
    local_ports_per_addr = 65535 - 49152

    def ip_a_a(self, addr):
        system("ip a a dev %s %s/32" % (self.interface.name, addr))

    def ip_r_a(self, prefix, via=None):
        cmd = f"ip r a dev {self.interface.name} {prefix}"
        if via != None:
            cmd += f" via {via}"
        cmd += " initcwnd 1"
        system(cmd)

    def reset_routing(self):
        system("ip a flush dev %s" % self.interface.name)

        # Add some route table entry to mitigate flush error:
        # Error: ipv4: FIB table does not exist.
        # Flush terminated
        system("ip r a dev %s 1.1.1.1/32" % self.interface.name)

        system("ip r flush dev %s" % self.interface.name)

class NoNetwork(Network):
    local_ports_per_addr = 65535 - 1024

    def reset_routing(self):
        pass

    def ip_a_a(self, addr):
        pass

    def ip_r_a(self, prefix, via=None):
        pass

class GbtcpNetwork(Network):
    local_ports_per_addr = 65535 - 10000

    def reset_routing(self):
        self.config = ""
        self.config += f"ip r f dev {self.interface.name}\n"
        self.config += f"ip a f dev {self.interface.name}\n"

    def ip_a_a(self, addr):
        self.config += f"ip a a dev {self.interface.name} address {addr}\n"

    def ip_r_a(self, prefix, via=None):
        self.config += f"ip r a dev {self.interface.name} prefix {prefix}"
        if via != None:
            self.config += f" via {via}"
        self.config += "\n" 
