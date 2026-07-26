# SPDX-License-Identifier: LGPL-2.1-only

import os
import re
import sys
import time
import psutil
import socket
import argparse
import ipaddress
import threading
import numpy
import signal
import singleton
import git
import platform

if platform.system() == 'Linux':
    import linux
else:
    import freebsd

from util import (
    Enum,
    EnvVar,
    start_process,
    wait_process,
    log_info,
    log_error,
)

import gbtcp.config

class Mode(Enum):
    CLIENT = "client"
    SERVER = "server"

class Transport(Enum):
    DEFAULT = "default"
    NATIVE = "native"
    NETMAP = "netmap"
    XDP = "xdp"


class Impl(Enum):
    GBTCP = "gbtcp"
    BSD44 = "bsd44"

class mac_address:
    @staticmethod
    def create(s):
        error = ValueError("Invalid literal for mac_address(): '%s'" % s)

        six = s.split(':')
        if len(six) != 6:
            raise error;

        for i, x in enumerate(six):
            if len(x) != 2:
                raise error;
            try:
                six[i] = int(x, 16)
            except ValueError:
                raise error;

        return mac_address(*six)

    def __init__(self, a, b, c, d, e, f):
        self.__data = (a, b, c, d, e, f)

    def __str__(self):
        return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
            self.__data[0], self.__data[1], self.__data[2],
            self.__data[3], self.__data[4], self.__data[5])
   
    def __repr__(self):
        return __str__(self)

class Socket:
    def __init__(self, sock=None):
        self.sock = sock
        if self.sock == None:
            self.sock =socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._buffer = ""

    def connect(self, address):
        self.sock.connect(address)

    def listen(self, address):
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(address)
        self.sock.listen(5)

    def accept(self):
        sock, _ = self.sock.accept()
        return Socket(sock)

    def connect(self, addr):
        self.sock.connect(addr)

    def set_timeout(self, timeout):
        self.sock.settimeout(timeout)

    def _split_lines(self, message):
        lines = message.splitlines()
        if '' in lines:
            lines.remove('')

        return lines

    def _recv_return(self, s):
        res = s.splitlines()
        if '' in res:
            res.remove('')
        return res

    def recv(self):
        while True:
            i = self._buffer.find("\n\n")
            if i >= 0:
                res = self._buffer[:i]
                self._buffer = self._buffer[i + 2:]
                return self._recv_return(res)

            data = self.sock.recv(1024)
            #print("recv", data)
            if len(data) == 0:
                res = self._recv_return(self._buffer)
                self.close()
                return res

            self._buffer += data.decode('utf-8')

    def _send(self, s):
        data = s.encode('utf-8')
        rc = self.sock.send(data)
        assert(rc == len(data))

    def send(self, args):
        s = ""
        for arg in args:
            while arg[-1] == '\n':
                arg = arg[:-1]
            s += arg + "\n"

        eof = "\n"
        if len(args) == 0:
            eof += "\n"
        s += eof

        self._send(s)

    def close(self):
        self._buffer = ""
        self.sock.close()

def round_std(std):
    assert(type(std) == int)
    assert(std >= 0)
    s = str(std)
    l = len(s)
    if l < 2:
        return std, 0
    if s[0] == '1' or s[0] == '2':
        z = 2
    else:
        z = 1
    r = s[0:z] + '0' * (l - z)
    return (int(r), l - z)

def round_val(val, std):
    assert(type(val) == int)
    assert(val >= 0)
    std_rounded, n = round_std(std)
    val_rounded = round(val, -n)
    return val_rounded, std_rounded


def parse_sockaddr_in(value):
    try:
        address, port = value.split(':', 1)
        socket.inet_aton(address)
        port = int(port)
        if not (0 < port <= 65535):
            raise argparse.ArgumentTypeError(f"Port must be in range 1-65535, got {port}")
        return address, port
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid format. Expected 'address:port', got '{value}'")
    except socket.error:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {address}")

def parse_cpulist(value, cpus):
    try:
        cpulist = [int(x.strip()) for x in value.split(',')]
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not a comma-separated list of cpus")
        cpulist = list(set(cpulist))

    for cpu in cpulist:
        if not cpu in cpus:
            raise argparse.ArgumentTypeError(f"CPU {cpu} is not available. Available CPUs: {cpus}")

    return cpulist

def argparse_add_cpus(parser, cpus, cfg):
    parser.add_argument('--cpus', type=lambda x: parse_cpulist(x, cpus),
        default=cfg.get('cpus'),
        help=f"Specify cpus ({' '.join(str(cpu) for cpu in cpus)})") 
    parser.add_argument('-c', type=int, metavar=f"1-{len(cpus)}",
        choices=range(1, len(cpus) + 1),
        default=cfg.get('cpu_count'),
        help="Specify number of cpus")

def argparse_get_cpus(args, cpus):
    if args.cpus:
        return list(set(args.cpus))
    else:
        return cpus[len(cpus) - args.c:len(cpus)]

def get_cpus():
    if platform.system() == 'Linux':
        return linux.get_cpus()
    else:
        return freebsd.get_cpus()

class Interface:
    @staticmethod
    def create(name):
        if platform.system() == 'Linux':
            return linux.Interface.create(name)
        else:
            return freebsd.Interface.create(name)


def set_cpus_scaling_governor(cpus):
    if platform.system() == 'Linux':
        for cpu in cpus:
            linux.set_cpu_scaling_governor(cpu)   

def find_outliers(reps, std):
    if std == None:
        std = [numpy.std(reps)] * len(reps)
    mean = numpy.mean(reps)
    # 3 sigma method
    outliers = []
    for i in range(0, len(reps)):
        if abs(mean - reps[i]) > 3 * std[i]:
            outliers.append(i)
    return outliers

class Top:
    def __init__(self, cpus, duration):
        self.cpus = cpus
        self.duration = duration
        self.thread = threading.Thread(name="top", target=self.measure)
        self.thread.start()

    def measure(self):
        percent = psutil.cpu_percent(self.duration, True)
        self.load = []
        for cpu in self.cpus:
            self.load.append(percent[cpu])

    def join(self):
        self.thread.join()

