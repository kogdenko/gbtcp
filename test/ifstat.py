#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import sys
import math
import socket
import argparse
import enum

from common import *


class Ifstat:
    class Counter(enum.Enum):
        IBYTES = 0
        IPACKETS = enum.auto()
        OBYTES = enum.auto()
        OPACKETS = enum.auto()


    @property
    def ibytes(self):
        return self.counters[Ifstat.Counter.IBYTES.value]


    @property
    def ipackets(self):
        return self.counters[Ifstat.Counter.IPACKETS.value]


    @property
    def obytes(self):
        return self.counters[Ifstat.Counter.OBYTES.value]


    @property
    def opackets(self):
        return self.counters[Ifstat.Counter.OPACKETS.value]


    def reset_counters(self):
        self.counters = [0] * len(Ifstat.Counter)


    def __init__(self, interface):
        self.interface = interface
        self.reset_counters()


    def __sub__(self, right):
        res = Ifstat(self.interface)
        for i in Ifstat.Counter:
            res.counters[i.value] = self.counters[i.value] - right.counters[i.value]
        return res


    def __truediv__(self, dt):
        res = Ifstat(self.interface)
        for i in Ifstat.Counter:
            res.counters[i.value] = int(self.counters[i.value]/dt)
        return res


    def __str__(self):
        return ("ibytes: %d\n"
            "ipackets: %d\n"
            "obytes: %d\n"
            "opackets: %d\n" %
            (self.ibytes,
            self.ipackets,
            self.obytes,
            self.opackets))


    def __repr__(self):
        return self.__str__()


class LinuxIfstat(Ifstat):
    def read(self):
        self.reset_counters()
        with open('/proc/net/dev', 'r') as f:
            lines = f.readlines()
        for line in lines:
            columns = line.split()
            if columns[0].strip() == self.interface.name + ':':
                assert(len(columns) == 17)
                self.counters[Ifstat.Counter.IBYTES.value] = int(columns[1])
                self.counters[Ifstat.Counter.IPACKETS.value] = int(columns[2])
                self.counters[Ifstat.Counter.OBYTES.value] = int(columns[9])
                self.counters[Ifstat.Counter.OPACKETS.value] = int(columns[10])
                return
        raise RuntimeError("/proc/net/dev: invalid interface: '%s'" % self.interface.name)


class GbtcpIfstat(Ifstat):
    def __init__(self, interface, gbtcp):
        super().__init__(interface)
        self.gbtcp = gbtcp


    def parse(self, lines):
        for line in lines[1:]:
            columns = line.split()
            assert(len(columns) == 7)
            if columns[0].strip() == self.interface.name:
                self.counters[Ifstat.Counter.IBYTES.value] = int(columns[3])
                self.counters[Ifstat.Counter.IPACKETS.value] = int(columns[1])
                self.counters[Ifstat.Counter.OBYTES.value] = int(columns[6])
                self.counters[Ifstat.Counter.OPACKETS.value] = int(columns[4])
                return
        raise RuntimeError("gbtcp-netstat: invalid interface: '%s'" % self.interface.name)


    def read(self):
        self.reset_counters()
        cmd = self.gbtcp.path + "/bin/gbtcp-netstat -bI " + self.interface.name
        self.parse(self.gbtcp.system(cmd)[1].splitlines())


class CongenIfstat(Ifstat):
    def __init__(self, interface, pid):
        super().__init__(interface)
        self.pid = pid


    def parse(self, lines):
        found = False
        for line in lines[1:]:
            columns = line.split()
            assert(len(columns) == 7)
            # TODO: check interface name
            found = True
            self.counters[Ifstat.Counter.IBYTES.value] += int(columns[3])
            self.counters[Ifstat.Counter.IPACKETS.value] += int(columns[1])
            self.counters[Ifstat.Counter.OBYTES.value] += int(columns[6])
            self.counters[Ifstat.Counter.OPACKETS.value] += int(columns[4])
        if not found:
            raise RuntimeError("con-gen: invalid interfacs: '%s'" % self.interface.name)


    def read(self):
        assert(self.pid)
        self.reset_counters()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect("/var/run/con-gen.%d.sock" % self.pid)
        send_string(sock, "i")
        self.parse(recv_lines(sock))


def main():
    class PseudoInterface:
        def __init__(self, name):
            self.name = name

    def create_ifstat(t, interface, gbtcp, pid):
        if t == "linux":
            return LinuxIfstat(interface)
        elif t == "gbtcp":
            return GbtcpIfstat(interface, gbtcp)
        elif t == "con-gen":
            return CongenIfstat(interface, pid)
        else:
            assert(0)

    ap = argparse.ArgumentParser()
    ap.add_argument("--type", type=str, choices=["linux", "gbtcp", "con-gen"],
            required=True)
    ap.add_argument("--pid", metavar="num", type=int, default=None)
    ap.add_argument("-i", type=str, required=True)

    gbtcp = Project()

    args = ap.parse_args()
    interface = PseudoInterface(args.i)
    ifstat = create_ifstat(args.type, interface, gbtcp, args.pid)
    ifstat.read()
    print(ifstat)


if __name__ == "__main__":
    sys.exit(main())
