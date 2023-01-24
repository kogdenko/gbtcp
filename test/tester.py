#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import getopt
import socket
import traceback
import numpy

import ifstat
from common import *
from network import Network


g_debug = True
g_project = Project()


def add_request_arguments(ap):
    ap.add_argument("--dst-mac", metavar="mac", type=mac_address.argparse,
            required=True,
            help="Destination MAC address in colon notation (e.g., aa:bb:cc:dd:ee:00)")

    ap.add_argument("--application", metavar="name", choices=["con-gen", "epoll"],
            required=True,
            help = "The application to be executed by tester")

    ap.add_argument("--network", metavar="ip", type=argparse_ip_network,
            required=True,
            help=("Private network for testing"))

    argparse_add_duration(ap)

    ap.add_argument("--concurrency", metavar="num", type=int,
            choices=range(1, CONCURRENCY_MAX),
            required=True,
            help="Number of parallel connections")
 

def print_report(proc, top, rc):
    report = "%s: CPU=%s ... " % (proc.args[0], str(top))
    if rc == 0:
        report += "Ok"
    else:
        report += "Failed"
    print_log(report)


class Tester:
    class con_gen:
        def __init__(self, outer):
            self.tester = outer


        def run(self, req):
            dst_ip = self.tester.network.server
            cmd = "con-gen"
            cmd += (" --print-report 0 -v -S %s -D %s --reports %d -N -p 80 -d %s" %
                (self.tester.interface.mac, str(req.dst_mac), req.duration, dst_ip))

            n = len(self.tester.cpus)
            for i in range(n):
                concurrency_per_cpu = req.concurrency / n
                if i == 0:
                    concurrency_per_cpu += req.concurrency % n
                else:
                    cmd += " --"
                cmd += " -i %s-%d" % (self.tester.interface.name, i)
                cmd += " -c %d" % concurrency_per_cpu
                cmd += " -a %d" % self.tester.cpus[i]
                cmd += " -s %s-%s" % (
                        self.tester.network.clients[i][0],
                        self.tester.network.clients[i][1])

                        
            return start_process(cmd)



    def process_req(self, args):
        class ArgumentParser(argparse.ArgumentParser):
            def error(self, message):
                raise RuntimeError(message)

        ap = ArgumentParser()
        add_request_arguments(ap)
        req = ap.parse_args(args)

        self.network.set_ip_network(req.network) 
        self.network.set_routing(False)
        self.network.configure(Mode.CLIENT, req.concurrency, len(self.cpus))

        app = Tester.con_gen(self)
        proc = app.run(req)
        top = Top(self.cpus, req.duration)

        time.sleep(1)
        ifstat_old = None
        
        pps = []
                
        for _ in range(2, req.duration - 1):
            time.sleep(1)
            ms_new = milliseconds()
            ifstat_new = ifstat.CongenIfstat(self.interface, proc.pid)
            ifstat_new.read()
            if ifstat_old:
                ifstat_rate = (ifstat_new - ifstat_old) / ((ms_new - ms_old) / 1000)
                pps.append(ifstat_rate.ipackets + ifstat_rate.opackets)
            ms_old = ms_new
            ifstat_old = ifstat_new

        top.join()

        rc, lines = wait_process(proc)
        print_report(proc, top.usage, rc)
        if rc == 0:
            return "\n".join(lines) + "\n"
        else:
            return None


    def loop(self):
        if self.__args.listen == None:
            listen_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                os.unlink(SUN_PATH)
            except:
                pass
            listen_sock.bind(SUN_PATH)
        else:
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.bind(str(self.__args.listen), 9999)
        listen_sock.listen()
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        while True:
            try:
                sock, _ = listen_sock.accept()
                while True:
                    lines = recv_lines(sock)
                    if not lines:
                        break
                    reply = ""
                    header = lines[0].lower()
                    if header == 'hello' and len(lines) > 1:
                        self.network.next_hop = mac_address.create(lines[1])
                        reply += "hello\n"
                        reply += str(self.interface.mac) + "\n"
                    elif header == 'run' and len(lines) > 1:
                        args = lines[1].strip().split()
                        reply = self.process_req(args)
                        
                        if reply == None:
                            sock.close()
                            break
                        print("reply-----")
                        print(reply)
                        print("__________")
                    else:
                        break
                    send_string(sock, reply)

                sock.close()
                
            except socket.error as e:
                print_log("Connection failed: '%s'" % str(e))


    def __init__(self):
        ap = argparse.ArgumentParser()

        argparse_add_reload_netmap(ap)
        argparse_add_cpu(ap)

        ap.add_argument("--listen", metavar="ip", type=argparse_ip_address,
                help="")

        ap.add_argument("-i", metavar="interface", required=True, type=argparse_interface,
                help="")

        self.__args = ap.parse_args()
        self.interface = self.__args.i
        self.cpus = self.__args.cpu
        self.network = Network()
        self.network.set_interface(self.interface)

        for cpu in self.cpus:
            set_cpu_scaling_governor(cpu)

        if self.__args.reload_netmap:
            reload_netmap(self.__args.reload_netmap, self.interface)

        self.interface.set_channels(self.cpus)

        system("ip a flush dev %s" % self.interface.name)
        system("ip r flush dev %s" % self.interface.name)


def main():
    tester = Tester()
    tester.loop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as exc:
        if g_debug:
            traceback.print_exception(exc)
        pass
