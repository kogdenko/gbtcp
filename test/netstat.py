#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import os
import math
import socket
import argparse

from common import *
from database import Database


class Netstat:
    class Table:
        class Entry:
            def __init__(self, name, value=None):
                self.name = name
                self.value = value


        def __init__(self, name):
            self.hide_zeroes = False
            self.name = name
            self.entries = []


        def get(self, entry_name):
            for entry in self.entries:
                if entry.name == entry_name:
                    return entry
            return None


        def __sub__(self, right):
            res = Netstat.Table(self.name)
            for entry in self.entries:
                value = entry.value
                if right:
                    right_entry = right.get(entry.name)
                    if right_entry:
                        value -= right_entry.value
                res.entries.append(Netstat.Table.Entry(entry.name, value))
            return res


        def __truediv__(self, dt):
            res = Netstat.Table(self.name)
            for entry in self.entries:
                value = math.ceil(entry.value / dt)
                res.entries.append(Netstat.Table.Entry(entry.name, value))
            return res


        def insert_into_database(self, db, db_table_name, sample_id, role):
            new_columns = []
            if not db.is_table_exists(db_table_name):
                for entry in self.entries:
                    new_columns.append(entry.name)
                db.create_netstat_table(db_table_name, new_columns)
            else:
                old_columns = db.get_columns(db_table_name)
                for entry in self.entries:
                    if entry.name not in old_columns:
                        new_columns.append(entry.name)
                db.alter_netstat_add_columns(db_table_name, new_columns)

            db.insert_into_netstat(db_table_name, sample_id, role, self.entries)


        def __str__(self):
            s = ""
            for e in self.entries:
                if e.value != 0 or not self.hide_zeroes:
                    s += "    %s: %d\n" % (e.name, e.value)
            return s


        def __repr__(self):
            return __str__(self)


    def get(self, table_name):
        for table in self.tables:
            if table.name == table_name:
                return table
        return None


    def set_hide_zeroes(self, hide_zeroes):
        for table in self.tables:
            table.hide_zeroes = hide_zeroes


    def insert_into_database(self, db, sample_id, role):
        for table in self.tables:
            table_name = "netstat_" + self.name + "_" + table.name
            table.insert_into_database(db, table_name, sample_id, role)


    def __init__(self, name):
        self.name = name
        self.tables = []


    def __sub__(self, right):
        res = Netstat(self.name)
        for table in self.tables:
            res.tables.append(table - right.get(table.name))
        return res


    def __truediv__(self, dt):
        res = Netstat(self.name)
        for table in self.tables:
            res.tables.append(table / dt)
        return res


    def __str__(self):
        s = ""
        for table in self.tables:
            tmp = str(table)
            if len(tmp):
                s += table.name + "\n" + tmp
        return s


    def __repr__(self):
        return self.__str__()


class LinuxNetstat(Netstat):
    def __init__(self):
        Netstat.__init__(self, "linux")


    def read_file(self, path):
        with open(path, 'r') as f:
            lines = f.readlines()

        for line in lines:
            if not line:
                continue
            tmp = line.split(':')
            if len(tmp) != 2:
                continue
            table = self.get(tmp[0])
            if table == None:
                table = Netstat.Table(tmp[0])
                keys = tmp[1].split()
                for key in keys:
                    table.entries.append(Netstat.Table.Entry(key))
                self.tables.append(table)
            else:
                values = tmp[1].split()
                assert(len(table.entries) == len(values))
                for i, value in enumerate(values):
                    table.entries[i].value = int(value)

    def read(self):
        self.tables = []
        self.read_file('/proc/net/snmp')
        self.read_file('/proc/net/netstat')


class BSDNetstat(Netstat):
    @staticmethod
    def search(table, line, pattern, args):
        assert(args)
        result = re.search(pattern, line)
        if result != None and len(result.groups()) == len(args):
            for i in range(0, len(args)):
                entry = table.get(args[i])
                if entry == None:
                    entry = Netstat.Table.Entry(args[i])
                    table.entries.append(entry)
                entry.value = int(result.groups()[i])
            return True
        else:
            return False


    def __init__(self):
        Netstat.__init__(self, "bsd")
        self.protocols = {
            'arp': [
                [r"(\d+) ARP requests sent", "txrequests"],
                [r"(\d+) ARP replies sent", "txreplies"],
                [r"(\d+) ARP replies tx dropped", "txrepliesdropped"],
                [r"(\d+) ARP requests received", "rxrequests"],
                [r"(\d+) ARP replies received", "rxreplies"],
                [r"(\d+) ARP packets received", "received"],
                [r"(\d+) ARP packets bypassed", "bypassed"],
                [r"(\d+) ARP packets filtered", "filtered"],
                [r"(\d+) total packets dropped due to no ARP entry", "dropped"],
                [r"(\d+) ARP entries timed out", "timeouts"],
            ],
            'ip': [
                [r"(\d+) total packets received", "total"],
                [r"(\d+) bad header checksums", "badsum"],
                [r"(\d+) with size smaller than minimum", "toosmall"],
                [r"(\d+) with data size < data length", "tooshort"],
                [r"(\d+) with ip length > max ip packet size", "toolong"],
                [r"(\d+) with header length < data size", "badhlen"],
                [r"(\d+) with data length < header length", "badlen"],
                [r"(\d+) with incorrect version number", "badvers"],
                [r"(\d+) fragments received", "fragments"],
                [r"(\d+) fragments dropped (dup or out of space)", "fragdropped"],
                [r"(\d+) packets for this host", "delivered"],
                [r"(\d+) packets for unknown/unsupported protocol", "noproto"],
                [r"(\d+) packets sent from this host", "localout"],
                [r"(\d+) output packets discarded due to no route", "noroute"],
                [r"(\d+) output datagrams fragmented", "fragmented"],
                [r"(\d+) datagrams that can't be fragmented", "cantfrag"],
            ],
            'tcp': [
                [r"(\d+) packets sent", "sndtotal"],
                [r"(\d+) data packets \((\d+) bytes\)", "sndpack", "sndbyte"],
                [r"(\d+) data packets \((\d+) bytes\) retransmitted",
                    "sndrexmitpack", "sndrexmitbyte"],
                [r"(\d+) ack-only packets \((\d+) delayed\)", "sndacks" , "delack"],
                [r"(\d+) URG only packets", "sndurg"],
                [r"(\d+) window probe packets", "sndprobe"],
                [r"(\d+) window update packets", "sndwinup"],
                [r"(\d+) control packets", "sndctrl"],
                [r"(\d+) packets received", "rcvtotal"],
                [r"(\d+) acks \(for (\d+) bytes\)", "rcvackpack", "rcvackbyte"],
                [r"(\d+) duplicate acks", "rcvdupack"],
                [r"(\d+) acks for unsent data", "rcvacktoomuch"],
                [r"(\d+) packets \((\d+) bytes\) received in-sequence", "rcvpack", "rcvbyte"],
                [r"(\d+) completely duplicate packets \((\d+) bytes\)",
                    "rcvduppack", "rcvdupbyte"],
                [r"(\d+) old duplicate packets", "pawsdrop"],
                [r"(\d+) packets with some dup. data \((\d+) bytes duped\)",
                    "rcvpartduppack", "rcvpartdupbyte"],
                [r"(\d+) out-of-order packets \((\d+) bytes\)", "rcvoopack", "rcvoobyte"],
                [r"(\d+) packets \((\d+) bytes\) of data after window",
                    "rcvpackafterwin", "rcvbyteafterwin"],
                [r"(\d+) window probes", "rcvwinprobe"],
                [r"(\d+) window update packets", "rcvwinupd"],
                [r"(\d+) packets received after close", "rcvafterclose"],
                [r"(\d+) discarded for bad checksums", "rcvbadsum"],
                [r"(\d+) discarded for bad header offset fields", "rcvbadoff"],
                [r"(\d+) discarded because packet too short", "rcvshort"],
                [r"(\d+) discarded due to memory problems", "rcvmemdrop"],
                [r"(\d+) connection requests", "connattempt"],
                [r"(\d+) connection accepts", "accepts"],
                [r"(\d+) bad connection attempts", "badsyn"],
                [r"(\d+) listen queue overflows", "listendrop"],
                [r"(\d+) connections established \(including accepts\)", "connects"],
                [r"(\d+) connections closed \(including (\d+) drops\)", "closed", "drops"],
                [r"(\d+) embryonic connections dropped", "conndrops"],
                [r"(\d+) segments updated rtt \(of (\d+) attempts\)", "rttupdated", "segstimed"],
                [r"(\d+) retransmit timeouts", "rexmttimeo"],
                [r"(\d+) connections dropped by rexmit timeout", "timeoutdrop"],
                [r"(\d+) persist timeouts", "persisttimeo"],
                [r"(\d+) keepalive timeouts", "keeptimeo"],
                [r"(\d+) keepalive probes sent", "keepprobe"],
                [r"(\d+) connections dropped by keepalive", "keepdrops"],
                [r"(\d+) correct ACK header predictions", "predack"],
                [r"(\d+) correct data packet header predictions", "preddat"],
            ],
            'udp': [
                [r"(\d+) datagrams received", "ipackets"],
                [r"(\d+) with incomplete header", "hdrops"],
                [r"(\d+) with bad data length field", "badlen"],
                [r"(\d+) with bad checksum", "badsum"],
                [r"(\d+) with no checksum", "nosum"],
                [r"(\d+) dropped due to no socket", "noport"],
                [r"(\d+) dropped due to full socket buffers", "fullsock"],
                [r"(\d+) delivered", "delivered"],
                [r"(\d+) datagrams output", "opackets"],
            ],
        }


    def parse(self, lines):
        table = None
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line[-1] == ':':
                table = None
                for proto, patterns in self.protocols.items():
                    if proto == line[:-1]:
                        table = self.get(proto)
                        if table == None:
                            table = Netstat.Table(proto)
                            table.patterns = patterns
                            self.tables.append(table)
                        break
            elif table != None:
                found = False
                for pattern in patterns:
                    if BSDNetstat.search(table, line, pattern[0], pattern[1:]):
                        found = True
                        break
                if not found:
                    print_log("unknown bsd statistic variable: '%s:%s'" % (table.name, line))


class GbtcpNetstat(BSDNetstat):
    def __init__(self, gbtcp):
        BSDNetstat.__init__(self)
        self.gbtcp = gbtcp


    def read(self):
        cmd = self.gbtcp.path + "/bin/gbtcp-netstat -nss"
        self.parse(self.gbtcp.system(cmd)[1].splitlines())


class CongenNetstat(BSDNetstat):
    def __init__(self, pid):
        BSDNetstat.__init__(self)
        self.pid = pid


    def read(self):
        assert(self.pid)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect("/var/run/con-gen.%d.sock" % self.pid)
        #send_string(sock, "s")
        sock.send(("s\n").encode('utf-8'))

        self.parse(recv_lines(sock))


def create_netstat(t, gbtcp, pid):
    if t == "linux":
        return LinuxNetstat()
    elif t == "gbtcp":
        return GbtcpNetstat(gbtcp)
    elif t == "con-gen":
        return CongenNetstat(pid)
    else:
        assert(0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--type", type=str, choices=["linux", "gbtcp", "con-gen"],
            required=True)
    ap.add_argument("--pid", metavar="num", type=int, default=None)
    ap.add_argument("--rate", metavar="seconds", type=int,
            help="Number of seconds between reports")
    ap.add_argument("--database", action='store_true',
            help="Write netstat to database")
    args = ap.parse_args()

    gbtcp = Project() 

    if args.rate:
        while True:
            ns0 = create_netstat(args.type, gbtcp, args.pid)
            ns0.read()
            time.sleep(args.rate)
            print("Netstat rate:")
            ns1 = create_netstat(args.type, gbtcp, args.pid)
            ns1.read()
            rate = (ns1 - ns0) / args.rate
            rate.set_hide_zeroes(True)
            print(rate)
            print("_______________")
    else:
        ns = create_netstat(args.type, gbtcp, args.pid)
        ns.read()
        if args.database:
            db = Database("")
            sample = Database.Sample()
            sample.test_id = 4
            sample.duration = 10
            sample.tester_cpu_percent = 0
            sample.runner_cpu_percent = 0
            db.add_sample(sample)
            ns.insert_into_database(db, sample.id, Database.Role.TESTER)
        print(ns)

    return 0

if __name__ == "__main__":
    sys.exit(main())
