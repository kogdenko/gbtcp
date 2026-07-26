#!/usr/bin/python

# SPDX-License-Identifier: LGPL-2.1-only

import argparse
import sys
import singleton
import time
import numpy

from application import Application
from util import (monotonic_ms)
from common import (mac_address,
    Interface,
    Transport,
    Mode,
    Socket,
    set_cpus_scaling_governor,
    parse_sockaddr_in,
    get_cpus,
    argparse_add_cpus,
    argparse_get_cpus
)
from netstat import Netstat
from network import Network

class E2eServer:
    def _rpc(self, timeout, name, l):
        args = []
        args.append(name)
        for arg in list(l.values())[1:]:
            args.append(str(arg))

        if self.sock == None:
            method = getattr(self, "msg_" + args[0])
            return method(args[1:])
        else:
            self.sock.send(args)
            self.sock.set_timeout(timeout)
            return self.sock.recv()

    # set_parameters
    def real_set_parameters(self, ip_network, mac):
        self.network.set_ip_network(ip_network)
        self.network.set_gw_mac(mac)

    def msg_set_parameters(self, args):
        assert(len(args) == 2)
        mac = mac_address.create(args[1])
        self.real_set_parameters(args[0], mac)
        return []

    def set_parameters(self, ip_network, mac):
        res = self._rpc(2, "set_parameters", locals())
        assert(len(res) == 0)

    # get_mac
    def real_get_mac(self):
        return self.network.interface.mac

    def msg_get_mac(self, args):
        mac = self.real_get_mac()
        return [str(mac)]

    def get_mac(self):
        res = self._rpc(2, "get_mac", locals())
        assert(len(res) == 1)
        return mac_address.create(res[0])

    # start
    def real_start(self, n_cpus, concurrency, transport, app_name, mode):
        if self.network.interface.is_paired:
            assert(n_cpus <= len(self.cpus))
            cpus = self.cpus[:n_cpus]
            self.network.interface.set_channels(cpus)
        else:
            cpus = self.cpus

        self.app = Application.create(app_name, self.network, transport)
        assert(not self.app.is_gbtcp())
        self.app.start(None, mode, None, concurrency, cpus)

    def msg_start(self, args):
        assert(len(args) == 5)
        self.real_start(int(args[0]), int(args[1]), Transport(args[2]), args[3], Mode(args[4]))
        return []

    def start(self, n_cpus, concurrency, transport, app_name, mode):
        self._rpc(2, "start", locals())
    
    # Read the cumulative TCP `connects` counter (established, including
    # accepts) from the tester. Symmetric across client/server roles.
    # Returns None if the counter can't be read (e.g. the con-gen control
    # socket isn't up yet) so cps degrades to 0 rather than failing the run.
    def read_connects(self):
        try:
            netstat = self.app.read_netstat()
        except OSError:
            return None
        if netstat is None:
            return None
        tcp = netstat.get_table("tcp")
        if tcp is None:
            return None
        entry = tcp.get_entry("connects")
        if entry is None:
            return None
        return entry.value

    # process
    def real_process(self, seconds):
        ifstat_old = None
        self.ipps = []
        self.opps = []
        self.ibps = []
        self.obps = []

        connects_old = None
        cps_ms_old = None
        for _ in range(0, seconds):
            time.sleep(1)
            ms_new = monotonic_ms()
            ifstat_new = self.app.read_ifstat()
            assert(ifstat_new)
            if ifstat_old:
                ifstat_rate = (ifstat_new - ifstat_old) / ((ms_new - ms_old) / 1000)
                self.ipps.append(ifstat_rate.ipackets)
                self.ibps.append(ifstat_rate.ibytes)
                self.opps.append(ifstat_rate.opackets)
                self.obps.append(ifstat_rate.obytes)
            else:
                # First successful ifstat read: the tester is up, so its
                # control socket exists. Snapshot the cps baseline here,
                # aligned with the same window pps is measured over.
                connects_old = self.read_connects()
                cps_ms_old = ms_new
            ms_old = ms_new
            ifstat_old = ifstat_new
        connects_new = self.read_connects()
        cps_ms_new = monotonic_ms()
        if (connects_old is None or connects_new is None or
                cps_ms_old is None or cps_ms_new <= cps_ms_old):
            self.cps = 0
        else:
            self.cps = int((connects_new - connects_old) /
                ((cps_ms_new - cps_ms_old) / 1000))

    def msg_process(self, args):
        assert(len(args) == 1)
        self.real_process(int(args[0]))
        return []

    def process(self, seconds):
        self._rpc(seconds + 2, "process", locals())

    # stop
    def real_stop(self):
        self.app.stop()
        pps = int(numpy.mean(self.ipps)) + int(numpy.mean(self.opps))
        bps = int(numpy.mean(self.ibps)) + int(numpy.mean(self.obps))
        return pps, bps, self.cps, self.app.netstat

    def msg_stop(self, args):
        pps, bps, cps, netstat = self.real_stop()
        return [str(pps), str(bps), str(cps), str(netstat)]

    def stop(self):
        args = self._rpc(2, "stop", locals())
        assert(len(args) > 3)
        netstat = Netstat()
        netstat.create_from_lines(args[3:])
        return int(args[0]), int(args[1]), int(args[2]), netstat

    @classmethod
    def create_local(cls, interface, cpus):
        s = E2eServer()
        s.sock = None
        s.network = Network()
        s.network.set_interface(interface)
        set_cpus_scaling_governor(cpus)
        s.cpus = cpus
        s.network.interface.set_channels(cpus)
        return s

    @classmethod
    def create_remote(cls, address):
        s = E2eServer()
        s.sock = Socket()
        s.sock.set_timeout(2)
        s.sock.connect(address)
        return s

def process_client(server, sock):
    while True:
        args = sock.recv()
        if len(args) == 0:
            return
        method = getattr(server, "msg_" + args[0])
        print("recv:", args)
        res = method(args[1:])
        print("send:", res)
        sock.send(res)

def main():
    ap = argparse.ArgumentParser()

    cpus = get_cpus()
    
    ap.add_argument('-b', type=parse_sockaddr_in, metavar="ip:port", default="0.0.0.0:14214",
        help="Bind and listen")
    ap.add_argument('-i', type=str, metavar="ifname", required=True,
        help="Specify tester interface")
    argparse_add_cpus(ap, cpus)
    ap.add_argument('-v', action='count', default=0, help="Be verbose")

    args = ap.parse_args()

    singleton.verbose = args.v

    cpus = argparse_get_cpus(args, cpus)

    socket = Socket()
    socket.listen(args.b)
    interface = Interface.create(args.i)

    while True:
        try:
            server = E2eServer.create_local(interface, cpus)
            sock = socket.accept()
            process_client(server, sock)
        except Exception as exc:
            print(exc)

if __name__ == "__main__":
    sys.exit(main())
