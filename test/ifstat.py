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


    def read(self):
        try:
            ok = self.vread()
        except Exception as e:
            raise RuntimeError("Ifstat: Internal error: '%s'" % str(e))
        if not ok:
            raise RuntimeError("Ifstat: Invalid interface: '%s'" % self.interface.name)


class LinuxIfstat(Ifstat):
    def vread(self):
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
                return True
        return False


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
                return True
        return False


    def vread(self):
        self.reset_counters()
        cmd = self.gbtcp.path + "/bin/gbtcp-netstat -bI " + self.interface.name
        return self.parse(self.gbtcp.system(cmd)[1].splitlines())


class CongenIfstat(Ifstat):
    def __init__(self, interface, pid):
        super().__init__(interface)
        self.pid = pid


    def parse(self, lines):
        for line in lines[1:]:
            columns = line.split()
            assert(len(columns) == 4)
            self.counters[Ifstat.Counter.IPACKETS.value] += int(columns[0])
            self.counters[Ifstat.Counter.IBYTES.value] += int(columns[1])
            self.counters[Ifstat.Counter.OPACKETS.value] += int(columns[2])
            self.counters[Ifstat.Counter.OBYTES.value] += int(columns[3])
            return True
        return False


    def vread(self):
        assert(self.pid)

        self.reset_counters()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sun_path = "/var/run/con-gen.%d.sock" % self.pid
        sock.connect(sun_path)
        send_string(sock, "i")

        lines = recv_lines(sock)
        return self.parse(lines)


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

    gbtcp = Repository()

    args = ap.parse_args()
    interface = PseudoInterface(args.i)
    ifstat = create_ifstat(args.type, interface, gbtcp, args.pid)
    ifstat.read()
    print(ifstat)


if __name__ == "__main__":
    sys.exit(main())
