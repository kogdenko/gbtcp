#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import getopt
import socket
import traceback
import numpy

import ifstat
from common import *
from network import Network
import application


g_debug = True
g_repo = Repository()


def print_err(exc, s):
    print_log(s + " ('" + str(exc) + "')")
    traceback.print_exception(exc)


def add_req_arguments(ap):
    ap.add_argument("--application", metavar="name", choices=["con-gen", "epoll"],
            required=True,
            help = "The application to be executed by tester")

    argparse_add_duration(ap)

    ap.add_argument("--concurrency", metavar="num", type=int,
            choices=range(1, CONCURRENCY_MAX),
            required=True,
            help="Number of parallel connections")
 

def print_report(app, top, rc):
    report = "%s: CPU=%s ... " % (str(app), str(top))
    if rc == 0:
        report += "Ok"
    else:
        report += "Failed"
    print_log(report)


class Tester:

    def process_req(self, args):
        ap = ArgumentParser()
        add_req_arguments(ap)
        req = ap.parse_args(args)

        app = application.con_gen(g_repo, self.network, Mode.CLIENT)
        app.start(req.concurrency, self.cpus)

        top = Top(self.cpus, req.duration)

        time.sleep(1)
        ifstat_old = None
        
        pps = []
                
        for _ in range(2, req.duration - 1):
            time.sleep(1)
            ms_new = milliseconds()
            ifstat_new = app.create_ifstat()
            ifstat_new.read()
            if ifstat_old:
                ifstat_rate = (ifstat_new - ifstat_old) / ((ms_new - ms_old) / 1000)
                pps.append(ifstat_rate.ipackets + ifstat_rate.opackets)
            ms_old = ms_new
            ifstat_old = ifstat_new

        top.join()

        rc, lines = app.stop()
        print_report(app, top.usage, rc)
        if rc == 0:
            return "\n".join(lines) + "\n"
        else:
            return None

    
    def process_client(self, sock):
        try:
            while True:
                lines = recv_lines(sock)
                if not lines:
                    break

                if len(lines) < 2:
                    break;

                header = lines[0].lower()
                args = lines[1].strip().split()

                if header == 'hello':
                    process_hello(self.network, args) 
                    reply = make_hello(self.network)
                elif header == 'run' and len(lines) > 1:
                    reply = self.process_req(args)
                else:
                    break

                if reply == None:
                    break
                send_string(sock, reply)
        except socket.error as e:
            print_err(e, "Connection failed")
        except Exception as e:
            print_err(e, "Internal error")


    def loop(self):
        if self.args.listen == None:
            listen_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                os.unlink(SUN_PATH)
            except:
                pass
            listen_sock.bind(SUN_PATH)
        else:
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.bind(str(self.args.listen), 9999)
        listen_sock.listen()
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        while True:
            sock, _ = listen_sock.accept()
            self.process_client(sock)
            sock.close()


    def __init__(self):
        ap = argparse.ArgumentParser()

        argparse_add_reload_netmap(ap)
        argparse_add_cpu(ap)

        ap.add_argument("--listen", metavar="ip", type=argparse_ip_address,
                help="")

        ap.add_argument("-i", metavar="interface", required=True, type=argparse_interface,
                help="")

        self.args = ap.parse_args()
        self.cpus = self.args.cpu
        self.network = Network()
        self.network.set_interface(self.args.i)

        for cpu in self.cpus:
            set_cpu_scaling_governor(cpu)

        if self.args.reload_netmap:
            reload_netmap(self.args.reload_netmap, self.network.interface)

        self.network.interface.set_channels(self.cpus)


def main():
    tester = Tester()
    tester.loop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as exc:
        print_err(exc, "Keyboard interrupt")
        pass
