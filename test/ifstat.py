#!/usr/bin/python

# SPDX-License-Identifier: LGPL-2.1-only

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

    def __init__(self):
        self.reset_counters()

    def __sub__(self, right):
        res = Ifstat()
        for i in Ifstat.Counter:
            res.counters[i.value] = self.counters[i.value] - right.counters[i.value]
        return res

    def __truediv__(self, dt):
        res = Ifstat()
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

    def read(self, app):
        return self.vread(app)

class LinuxIfstat(Ifstat):
    def vread(self, app):
        self.reset_counters()
        with open('/proc/net/dev', 'r') as f:
            lines = f.readlines()
        for line in lines:
            columns = line.split()
            if columns[0].strip() == app.network.interface.name + ':':
                assert(len(columns) == 17)
                self.counters[Ifstat.Counter.IBYTES.value] = int(columns[1])
                self.counters[Ifstat.Counter.IPACKETS.value] = int(columns[2])
                self.counters[Ifstat.Counter.OBYTES.value] = int(columns[9])
                self.counters[Ifstat.Counter.OPACKETS.value] = int(columns[10])
                return
        assert(0)

class GbtcpIfstat(Ifstat):
    def __init__(self):
        super().__init__()

    def parse(self, interface, lines):
        for line in lines[1:]:
            columns = line.split()
            assert(len(columns) == 7)
            if interface == None or columns[0].strip() == interface.name:
                self.counters[Ifstat.Counter.IBYTES.value] = int(columns[3])
                self.counters[Ifstat.Counter.IPACKETS.value] = int(columns[1])
                self.counters[Ifstat.Counter.OBYTES.value] = int(columns[6])
                self.counters[Ifstat.Counter.OPACKETS.value] = int(columns[4])
                return
        assert(0)

    def vread(self, app):
        self.reset_counters()
        cmd = singleton.builddir + "/gbtcp-netstat -bI " + app.network.interface.name
        lines = system(cmd)[1].splitlines()
        return self.parse(app.network.interface, lines)

class CongenIfstat(Ifstat):
    def __init__(self):
        super().__init__()

    def parse(self, interface, lines):
        if len(lines) < 2:
            raise RuntimeError(f"ifstat: `con-gen` truncated output: {lines}")

        columns = lines[1].split()
        if len(columns) != 4:
            raise RuntimeError(f"ifstat: `con-gen` unexpected output: {lines[1]}")

        self.counters[Ifstat.Counter.IPACKETS.value] += int(columns[0])
        self.counters[Ifstat.Counter.IBYTES.value] += int(columns[1])
        self.counters[Ifstat.Counter.OPACKETS.value] += int(columns[2])
        self.counters[Ifstat.Counter.OBYTES.value] += int(columns[3])            

    def vread(self, app):
        self.reset_counters()
        fd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock = Socket(fd)

        if not app.is_running():
            fd.close()
            app.wait_process()
            raise RuntimeError(f"ifstat: `con-gen` died")

        sun_path = f"/var/run/con-gen.{app.proc.pid}.sock"
        sock.connect(sun_path)
        sock.send("i")

        lines = sock.recv()
        fd.close()
        self.parse(None, lines)

def create_ifstat(t):
    if t == "linux":
        return LinuxIfstat()
    elif t == "gbtcp":
        return GbtcpIfstat()
    elif t == "con-gen":
        return CongenIfstat()
    else:
        assert(0)
