#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import math
import ipaddress

from common import *


class Network:
    EPHEMERAL_PER_ADDRESS = 30000

    def __init__(self):
        self.ip_network = None
        self.interface = None
        self.mode = None
        self.dirty = True
        self.routing = True
        self.clients = []


    def set_interface(self, interface):
        self.interface = interface
        self.dirty = True
       

    def set_ip_network(self, ip_network):
        if self.ip_network != ip_network:
            self.ip_network = ip_network
            self.__first_client, *_, self.server = self.ip_network.hosts()
            self.dirty = True


    def set_routing(self, routing):
        if self.routing != routing:
            self.routing = routing
            self.dirty = True


    def configure_server_routing(self):
        system("ip a a dev %s %s/32" % (self.interface.name, self.server))
        system("ip r a dev %s %s/32 initcwnd 1" % (self.interface.name, self.__first_client))
        system("ip r a dev %s %s via %s initcwnd 1" %
            (self.interface.name, self.ip_network, self.__first_client))


    def configure_client_routing(self):
        for r in self.clients:
            for a in range(int(r[0]), int(r[1] + 1)):
                address = ipaddress.ip_address(a)
                system("ip a a dev %s %s" % (self.interface.name, address))
        system("ip r a dev %s %s initcwnd 1" % (self.interface.name, self.ip_network))
 

    def configure(self, mode, concurrency, cpus):
        assert(self.interface != None)
        assert(self.ip_network != None)

        if self.mode != mode:
            self.mode = mode
            self.dirty = True

        if self.mode == Mode.CLIENT and len(self.clients) != cpus:
            self.dirty = True

        if not self.dirty:
            return;

        n = math.ceil(concurrency/cpus/Network.EPHEMERAL_PER_ADDRESS)
    
        system("ip r flush dev %s" % self.interface.name)
        system("ip a flush dev %s" % self.interface.name)
        if self.mode == Mode.SERVER:
            if self.routing:
                self.configure_server_routing()
        else:
            self.clients = []
            first = self.__first_client
            for _ in range(0, cpus):
                last = first + n - 1
                if last > self.server:
                    raise RuntimeError("running out of ip addresses: '%s'" % self.ip_network)
                self.clients.append([first, last])
                first = last + 1
            if self.routing:
                self.configure_client_routing()

        self.dirty = False

class PseudoInterface:
    def __init__(self, name):
        self.name = name

def main():
    interface = PseudoInterface("eth2")
    net = Network()
    net.set_interface(interface)
    net.set_ip_network(ipaddress.ip_network('10.20.0.0/16'))
    net.configure(Mode.CLIENT, 10000000, 3)

if __name__ == "__main__":
    sys.exit(main())
