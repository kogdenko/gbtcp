#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import getopt
import argparse

from common import *

# { 'Ip': [['Forwarding', 'DefaultTTL', ... ], [2, 64, ... ]],
#   'Icmp': [['InMsgs', 'InErrors', ...], [59610, 25, ... ]]
#   ...
# }

class Netstat:
    def read_file(self, path):
        f = open(path, 'r')
        lines = f.readlines()
        f.close()
        for line in lines:
            tmp = line.split(':')
            assert(len(tmp) == 2)
            first = tmp[0] 
            if self.map.get(first) == None:
                self.map[first] = [[],[]]
                for second in tmp[1].split():
                    self.map[first][0].append(second)
            else:
                for val in tmp[1].split():
                    self.map[first][1].append(int(val))
                assert(len(self.map[first][0]) == len(self.map[first][1]))

    def read(self):
        self.map = {}
        self.read_file('/proc/net/snmp')
        self.read_file('/proc/net/netstat')

    def __init__(self, empty=False):
        self.map = {}
        if not empty:
            self.read()

    def get(self, first, second):
        for i in range(len(self.map[first][0])):
            if self.map[first][0][i] == second:
                return self.map[first][1][i]
        return None

    def __sub__(self, other):
        res = Netstat(True)
        for first, pair in self.map.items():
            for i in range(0, len(pair[0])):
                second = pair[0][i]
                other_val = other.get(first, second)
                if other_val != None:
                    if first not in res.map:
                        res.map[first] = [[], []]
                    res.map[first][0].append(second)
                    res.map[first][1].append(pair[1][i] - other_val)
        return res;

    def to_string(self, hide_zeroes=True):
        s = ""
        for first, pair in self.map.items():
            printed = False
            for i in range(len(pair[0])):
                val = pair[1][i]
                if hide_zeroes and not val:
                    continue
                if not printed:
                    printed = True
                    s += "%s:\n" % first
                s += "    %s: %d\n" % (pair[0][i], pair[1][i])
        return s

        

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rate", help="number of secods between reports", type=int)
    ap.add_argument("-D", metavar="mac", required=True, type=argparse_mac)
    args = ap.parse_args()
    print(args.mac)
    return 0; 
    if args.rate:
        while True:
            save = Netstat()
            time.sleep(args.rate)
            print("Netstat rate:")
            print((Netstat() - save).to_string())
            print("_______________")
    else:
        print(Netstat().to_string())

    return 0

if __name__ == "__main__":
    sys.exit(main())
