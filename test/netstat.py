#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import math
import getopt
import argparse

from common import *

class Netstat:
    @staticmethod
    def rate(a, b, dt):
        assert(type(a) == type(b))
        rate = type(a)()
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


    def write(self, db, sample_id, role):
        for table in self.tables:
            table.write(db, sample_id, role)


    def __init__(self, name):
        self.name = name
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


class LinuxNetstat(Netstat):
    def __init__(self):
        Netstat.__init__(self, "linux")


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

    def read(self):
        self.tables = []
        self.read_file('/proc/net/snmp')
        self.read_file('/proc/net/netstat')


class BsdNetstat(Netstat):
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


    @staticmethod
    def __init__(self, name):
        Netstat.__init__(self, name)
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


    def parse(self, text):
        lines = text.split('\n')
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
                            table = Netstat.Table(self, proto)
                            table.patterns = patterns
                            self.tables.append(table)
                        break
            elif table != None:
                found = False
                for pattern in patterns:
                    if BsdNetstat.search(table, line, pattern[0], pattern[1:]):
                        found = True
                        break
                if not found:
                    print_log("Unknown BSD '%s' stat: '%s'" % (table.name, line))


class GbtcpNetstat(BsdNetstat):
    def __init__(self):
        BsdNetstat.__init__(self, "gbtcp")
        self.project = Project()


    def read(self):
        cmd = self.project.path + "/bin/gbtcp-netstat -nss"
        self.parse(self.project.system(cmd)[1])


def create_netstat(t):
    if t == "linux":
        return LinuxNetstat()
    elif t == "gbtcp":
        return GbtcpNetstat()
    else:
        assert(0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--type", type=str, choices=["linux", "gbtcp"], default="linux")
    ap.add_argument("--rate", metavar="seconds", type=int,
            help="Number of seconds between reports")
    ap.add_argument("--database", action='store_true',
            help="Write netstat to database")
    args = ap.parse_args()

    if args.rate:
        while True:
            ns0 = create_netstat(args.type)
            ns0.read()
            time.sleep(args.rate)
            print("Netstat rate:")
            ns1 = create_netstat(args.type)
            ns1.read()
            rate = Netstat.rate(ns0, ns1, args.rate)
            rate.hide_zeroes = True
            print(rate)
            print("_______________")
    else:
        ns = create_netstat(args.type)
        ns.read()
        if args.database:
            db = Database("")
            ns.write(db, 1, 0)
        print(ns)

    return 0

if __name__ == "__main__":
    sys.exit(main())
