#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import getopt
import socket
import numpy
from common import *

g_project = Project()

def run_epoll(interface, subnet, reports, concurrency):
    ifname = interface.name

    system("ip a flush dev %s" % ifname)
    system("ip r flush dev %s" % ifname)
    for i in range(1, 255):
        system("ip a a dev %s %d.%d.1.%d " % (ifname, subnet[0], subnet[1], i))
    system("ip r a dev %s %d.%d.0.0/16" % (ifname, subnet[0], subnet[1]))

    n = len(g_cpus)
    concurrency_per_cpu = concurrency / n
    if concurrency_per_cpu == 0:
        concurrency_per_cpu = 1

    cmd = g_project.path + "/bin/gbtcp-epoll-helloworld "
    cmd += "-c %d -n %d -a " % (concurrency_per_cpu, reports)
    for cpu in g_cpus:
        cmd += ",%d" % cpu
    cmd += " %s" % get_runner_ip(subnet)

    return g_project.start_process(cmd, False)


def add_request_arguments(ap):
    ap.add_argument("--dst-mac", metavar="mac", type=MacAddress.argparse,
            required=True,
            help="Destination MAC address in colon notation (e.g., aa:bb:cc:dd:ee:00)")

    ap.add_argument("--application", metavar="name", choices=["con-gen", "epoll"],
            required=True,
            help = "The application to be executed by tester")

    ap.add_argument("--subnet", metavar="ip", type=argparse_ip,
            required=True,
            help=("Private /16 subnet for testing, server acquired x.x.%d.%d" %
                (SERVER_IP_C, SERVER_IP_D)))

    argparse_add_delay(ap)
    argparse_add_duration(ap)

    ap.add_argument("--concurrency", metavar="num", type=int,
            choices=range(1, CONCURRENCY_MAX),
            required=True,
            help="Number of parallel connections")
 

def parse_output(lines, delay, duration):
    if len(lines) != duration:
        print_log("Invalid number of reports (%d, should be %d)" % (len(lines), duration))
        return None
    records = [[] for i in range(Database.Sample.CONCURRENCY + 1)]
    for line in lines:
        cols = line.split()
        if len(cols) != 9:
            print_log(("Invalid number of columns (%d, should be 9)\n%s" % (len(cols), line)))
            return None
        records[Database.Sample.CPS].append(int(cols[0]))
        records[Database.Sample.IPPS].append(int(cols[1]))
        records[Database.Sample.IBPS].append(int(cols[2]))
        records[Database.Sample.OPPS].append(int(cols[3]))
        records[Database.Sample.OBPS].append(int(cols[4]))
        records[Database.Sample.RXMTPS].append(int(cols[7]))
        records[Database.Sample.CONCURRENCY].append(int(cols[8]))
    record = records[Database.Sample.CPS][delay:]
    outliers = find_outliers(record, None)

    results = []
    for record in records:
        results.append(int(numpy.mean(record)))

    return results


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
            dst_ip = get_runner_ip(req.subnet)
            cmd = "con-gen "
        #    cmd += "--toy "
            cmd += "--print-banner 0 --print-statistics 0 --report-bytes 1 "
            cmd += ("-S %s -D %s --reports %d -N -p 80 -d %s" %
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
                cmd += " -s %d.%d.%d.1-%d.%d.%d.255" % (
                        req.subnet[0], req.subnet[1], i + 1,
                        req.subnet[0], req.subnet[1], i + 1)
            return g_project.start_process(cmd, False)


    @staticmethod
    def get_request(listen_sock):
        class ArgumentParser(argparse.ArgumentParser):
            def error(self, message):
                raise RuntimeError(message)

        while True:
            try:
                sock, _ = listen_sock.accept()
                req = ""
                while True:
                    req += sock.recv(1024).decode('utf-8')
                    if '\n' in req:
                        ap = ArgumentParser()
                        add_request_arguments(ap)
                        return sock, ap.parse_args(req.strip().split())
            except (socket.error, RuntimeError) as e:
                print_log("Error while reading request: '%s'" % str(e))


    def run(self, req):
        app = Tester.con_gen(self)
        return app.run(req)


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
            listen_sock.bind((make_ip(self.__args.listen), 9999))
        listen_sock.listen()
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        while True:
            try:
                sock, req = Tester.get_request(listen_sock)
                
                proc = self.run(req)

                top = cpu_percent(req.duration, req.delay, self.cpus)

                rc, lines = g_project.wait_process(proc)
                if rc == 0:
                    results = parse_output(lines, req.delay, req.duration)
                else:
                    results = None

                print_report(proc, top, rc)

                if rc == 0 and results != None:
                    reply = "Ok"
                    for result in results:
                        reply += " " + str(result)
                else:
                    reply = "Failed"
                sock.send(reply.encode('utf-8'))
                sock.close()
            except socket.error as e:
                print_log("Connection failed: '%s'" % str(e))


    def __init__(self):
        ap = argparse.ArgumentParser()

        argparse_add_reload_netmap(ap)
        argparse_add_cpu(ap)

        ap.add_argument("--listen", metavar="ip", type=argparse_ip,
                help="")

        ap.add_argument("-i", metavar="interface", required=True, type=argparse_interface,
                help="")

        self.__args = ap.parse_args()
        self.interface = self.__args.i
        self.cpus = self.__args.cpu

        for cpu in self.cpus:
            set_cpu_scaling_governor(cpu)

        if self.__args.reload_netmap:
            reload_netmap(self.__args.reload_netmap, self.interface.driver)

        self.interface.set_channels(self.cpus)


def main():
    tester = Tester()
    tester.loop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
