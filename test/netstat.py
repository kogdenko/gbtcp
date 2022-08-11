#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import math
import getopt
import argparse

from common import *

class Netstat:
    @staticmethod
    def rate(a, b, dt):
        rate = Netstat()
        for table_a in a.tables:
            table_b = b.get(table_a.name)
            assert(table_b != None)
            table_rate = Netstat.Table.rate(rate, table_a, table_b, dt)
            rate.tables.append(table_rate)
        return rate


    class Table:
        @staticmethod
        def rate(netstat, a, b, dt):
            rate = Netstat.Table(netstat, a.name)
            for entry_a in a.entries:
                entry_b = b.get(entry_a.name)
                assert(entry_b != None)
                entry_rate = Netstat.Table.Entry(entry_a.name)
                entry_rate.value = math.ceil((entry_b.value - entry_a.value) / dt)
                rate.entries.append(entry_rate)
            return rate


        class Entry:
            def __init__(self, name):
                self.name = name
                self.value = None


        def __init__(self, netstat, name):
            self.netstat = netstat
            self.name = name
            self.entries = []


        def get(self, entry_name):
            for entry in self.entries:
                if entry.name == entry_name:
                    return entry
            return None


        def write(self, db, sample_id, role):
            table = "netstat_" + self.netstat.name + "_" + self.name
            new_columns = []
            if not db.is_table_exists(table):
                for entry in self.entries:
                    new_columns.append(entry.name)
                db.create_netstat_table(table, new_columns)
            else:
                old_columns = db.get_columns(table)
                for entry in self.entries:
                    if entry.name not in old_columns:
                        new_columns.append(entry.name)
                db.add_netstat_columns(table, new_columns)

            db.insert_into_netstat(table, sample_id, role, self.entries)


        def __str__(self):
            s = ""
            for e in self.entries:
                if e.value != 0 or not self.netstat.hide_zeroes:
                    s += "    %s: %d\n" % (e.name, e.value)
            return s


        def __repr__(self):
            return __str__(self)


    def get(self, table_name):
        for table in self.tables:
            if table.name == table_name:
                return table
        return None


    def read_file(self, path):
        with open(path, 'r') as f:
            lines = f.readlines()

        for line in lines:
            tmp = line.split(':')
            assert(len(tmp) == 2)
            table = self.get(tmp[0])
            if table == None:
                table = Netstat.Table(self, tmp[0])
                keys = tmp[1].split()
                for key in keys:
                    table.entries.append(Netstat.Table.Entry(key))
                self.tables.append(table)
            else:
                values = tmp[1].split()
                assert(len(table.entries) == len(values))
                for i, value in enumerate(values):
                    table.entries[i].value = int(value)


    def write(self, db, sample_id, role):
        for table in self.tables:
            table.write(db, sample_id, role)


    def read(self):
        self.tables = []
        self.read_file('/proc/net/snmp')
        self.read_file('/proc/net/netstat')


    def __init__(self):
        self.name = "linux"
        self.hide_zeroes = False
        self.tables = []


    def __str__(self):
        s = ""
        for table in self.tables:
            tmp = str(table)
            if len(tmp):
                s += table.name + "\n" + tmp
        return s


    def __repr__(self):
        return self.__str__()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rate", metavar="seconds", type=int,
            help="Number of seconds between reports")
    ap.add_argument("--database", action='store_true',
            help="Write netstat to database")
    args = ap.parse_args()

    if args.rate:
        while True:
            ns0 = Netstat()
            ns0.read()
            time.sleep(args.rate)
            print("Netstat rate:")
            ns1 = Netstat()
            ns1.read()
            rate = Netstat.rate(ns0, ns1, args.rate)
            rate.hide_zeroes = True
            print(rate)
            print("_______________")
    else:
        ns = Netstat()
        ns.read()
        if args.database:
            db = Database("")
            ns.write(db, 1, 0)
        print(ns)

    return 0

if __name__ == "__main__":
    sys.exit(main())
