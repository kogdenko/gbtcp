#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import os
import sys
import time
import math
import atexit
import errno
import getopt
import socket
import subprocess
import platform
import importlib
import multiprocessing
import re

import numpy

from common import *
from netstat import *

COOLING_MIN = 0
COOLING_MAX = 3*60
COOLING_DEFAULT = 20

g_subnet = (10, 20, 0, 0)

g_project = Project()
g_db = Database("")

class Simple:
    def __init__(self, name):
        self.name = name


    def get_name(self):
        return self.name


    def run(self):
        g_runner.ts_planned += 1
        proc = g_project.start_process(g_project.path + '/bin/' + self.name, False)
        if wait_process(proc)[0] == 0:
            g_runner.ts_pass += 1
            status = "Pass"
        else:
            g_runner.ts_failed += 1
            status = "Failed"
        print_log("%s ... %s" % (self.name, status), True)

class Application:
    MODE_CLIENT = 0
    MODE_SERVER = 1
    
    '''@staticmethod
    # Application can be represented in 4 forms:
    # netmap:con-gen:client
    # con-gen
    # con-gen:client
    # netmap:con-gen
    def create(s):
        transport_id = None
        error = RuntimeError("")
        parts = s.split(':')
        if len(parts) == 1:
            Application.create1(parts[0])
        elif len(parts) == 2:
        elif len(parts) == 3:
            transport_id = get_dict_id(transport_dict, parts[0])
            if transport_id == None:
                raise error
            
        else
            raise error'''        


    def __init__(self):
        self.id = g_db.get_app_id(self.get_name(), self.get_version())

    def __str__(self):
        pass

    def __repr__(self):
        return self.__str__(self)


    def read_netstat(self):
        netstat = None
        if self.transport == Transport.NATIVE:
            if platform.system() == 'Linux':
                netstat = LinuxNetstat()
            else:
                assert(0)
        else:
            netstat = GbtcpNetstat()
        netstat.read()
        return netstat


    def start_process(self, transport, cmd):
        self.transport = transport
        if self.transport == Transport.NATIVE:
            preload = False
        else:
            preload = True
        return g_project.start_process(cmd, preload)


    def parse_version(self, s):
        m = re.search(r'[0-9]+\.[0-9]+\.[0-9]+', s.strip())
        if m == None:
            raise RuntimeError("%s: Cannot extract version" % s)
        return m.group(0)


class nginx(Application):
    def get_name(self):
        return "nginx"


    def get_version(self):
        s = system("nginx -v")[2]
        return self.parse_version(s)


    def stop(self):
        system("nginx -s quit", True)


    def start(self, transport, concurrency, cpus):
        worker_cpu_affinity = ""

        n = len(cpus)
        assert(n > 0)

        cpu_count = multiprocessing.cpu_count()
        templ = [ '0' for i in range(0, cpu_count) ]
        for i in cpus:
            templ[cpu_count - 1 - i] = '1'
            worker_cpu_affinity += " " + "".join(templ)
            templ[cpu_count - 1 - i] = '0'

        worker_connections = upper_pow2_32(concurrency)
        if worker_connections < 1024:
            worker_connections = 1024

        nginx_conf = (
            "user root;\n"
            "daemon off;\n"
            "master_process on;\n"
            "\n"
            "worker_processes %d;\n"
            "worker_cpu_affinity %s;\n"
            "worker_rlimit_nofile %d;\n"
            "events {\n"
            "    use epoll;\n"
            "    multi_accept on;\n"
            "    worker_connections %d;\n"
            "}\n"
            "\n"
            "http {\n"
            "    access_log off;\n"
            "    tcp_nopush on;\n"
            "    tcp_nodelay on;\n"
            "    keepalive_timeout 65;\n"
            "    types_hash_max_size 2048;\n"
            "    reset_timedout_connection on;\n"
            "    send_timeout 2;\n"
            "    client_body_timeout 10;\n"
            "    include /etc/nginx/conf.d/*.conf;\n"
            "    server {\n"
            "        listen %s:80 reuseport;\n"
            "        server_name  _;\n"
            "        location / {\n"
            "            return 200 'Hello world!!!';\n"
            "        }\n"
            "    }\n"
            "}\n"
            % (n,
                worker_cpu_affinity,
                worker_connections,
                worker_connections,
                get_runner_ip(g_subnet)))

        nginx_conf_path = g_project.path + "/test/nginx.conf"

        with open(nginx_conf_path, 'w') as f:
            f.write(nginx_conf)

        return self.start_process(transport, "nginx -c %s" % nginx_conf_path)


    def __init__(self):
        Application.__init__(self)


class gbtcp_base_helloworld(Application):
    def get_version(self):
        cmd = "%s -v" % self.path
        s = g_project.system(cmd)[1]
        for line in s.splitlines():
            if line.startswith("version: "):
                return self.parse_version(line)
        raise RuntimeError("%s: Cannot extract version" % cmd)


    def stop(self):
        g_project.system("%s -S" % self.path, True)


    def start(self, transport, concurrency, cpus):
        cmd = "%s -l -a " % self.path
        for i in range(len(cpus)):
            if i != 0:
                cmd += ","
            cmd += str(cpus[i])
        return self.start_process(transport, cmd)


    def __init__(self):
        self.path = g_project.path + "/bin/" + self.get_name()
        Application.__init__(self)


class gbtcp_epoll_helloworld(gbtcp_base_helloworld):
    def get_name(self):
        return "gbtcp-epoll-helloworld"


class gbtcp_aio_helloworld(gbtcp_base_helloworld):
    def get_name(self):
        return "gbtcp-aio-helloworld"


class Runner:
    @staticmethod
    def add_test(d, test):
        d[test.get_name()] = test


    def print_test_statistics(self):
        print("Planned: ", self.ts_planned)
        print("Pass: ", self.ts_pass)
        print("Failed: ", self.ts_failed)


    def __init__(self): 
        self.ts_planned = 0
        self.ts_pass = 0
        self.ts_failed = 0

        tests = {}
        for f in os.listdir(g_project.path + '/bin'):
            if f[:10] == "gbtcp-test":
                if os.path.isfile(g_project.path + '/test/' + f + '.pkt'):
                    #Runner.add_test(tests, Tcpkt(f))
                    pass
                else:
                    Runner.add_test(tests, Simple(f))
        Runner.add_test(tests, nginx())
        Runner.add_test(tests, gbtcp_epoll_helloworld())
        Runner.add_test(tests, gbtcp_aio_helloworld())

        # Assume that last test ended at least 10 seconds ago
        self.stop_ms = milliseconds() - 10000

        ap = argparse.ArgumentParser()

        argparse_add_reload_netmap(ap)
        argparse_add_cpu(ap);
        argparse_add_duration(ap, TEST_DURATION_DEFAULT)

        ap.add_argument("-i", metavar="interface", required=True, type=argparse_interface,
                help="")

        ap.add_argument("--dry-run", action='store_true',
                help="")

        ap.add_argument("--cpu-count", metavar="num", type=int, nargs='+',
                action=UniqueAppendAction,
                choices=range(1, multiprocessing.cpu_count()),
                help="")

        ap.add_argument("--connect", metavar="ip", type=argparse_ip,
                help="")

        ap.add_argument("--sample", metavar="count", type=int,
                choices=range(TEST_SAMPLE_MIN, TEST_SAMPLE_MAX),
                default=TEST_SAMPLE_DEFAULT,
                help="")

        ap.add_argument("--cooling", metavar="seconds", type=int,
                choices=range(COOLING_MIN, COOLING_MAX),
                default=COOLING_DEFAULT,
                help="")

        ap.add_argument("--concurrency", metavar="num", type=int, nargs='+',
                action=UniqueAppendAction,
                default=[CONCURRENCY_DEFAULT],
                help="Number of parallel connections")

        ap.add_argument("--transport", metavar="name", type=Transport, nargs='+',
                choices=g_project.transports,
                default=[g_project.transports[-1]],
                help="")

        ap.add_argument("--test", metavar="name", type=str, nargs='+',
                choices = [ k for (k, v) in tests.items() ],
                help="")

        self.__args = ap.parse_args()
        self.concurrency = self.__args.concurrency
        self.dry_run = self.__args.dry_run
        self.duration = self.__args.duration
        self.sample = self.__args.sample
        self.interface = self.__args.i
        self.cpus = self.__args.cpu
        self.transport = self.__args.transport
        self.cpu_count = self.__args.cpu_count

        for cpu in self.cpus:
            set_cpu_scaling_governor(cpu)

        if not self.cpu_count:
            self.cpu_count = [ * range(1, len(self.cpus) + 1) ]
        else:
            for count in self.__args.cpu_count:
                if count < 0 and count >= len(self.cpus):
                    self.cpu_count.remove(count)
 
        if self.__args.reload_netmap:
            reload_netmap(self.__args.reload_netmap, self.interface)

        self.tests = []
        for test in self.__args.test:
            self.tests.append(tests[test])

        if self.__args.connect:
            self.__sock = socket.create_connection((make_ip(self.__args.connect), 9999))
        else:
            self.__sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.__sock.connect(SUN_PATH)
        self.__sock.settimeout(10)


    def stop(self):
        self.stop_mss = milliseconds()


    def cooling(self):
        ms = milliseconds() - self.stop_ms
        if ms < self.__args.cooling * 1000:
            t = int(math.ceil((self.__args.cooling * 1000 - ms) / 1000))
            time.sleep(t)


    def send_req(self, concurrency):
        req = ("--dst-mac %s "
                "--subnet %d.%d.0.0 "
                "--duration %d "
                "--concurrency %d "
                "--application con-gen\n\n" % (
                str(self.interface.mac),
                g_subnet[0], g_subnet[1],
                self.duration,
                concurrency))
        self.__sock.send(req.encode('utf-8'))


    def recv_msg(self):
        return recv_lines(self.__sock)

g_runner = Runner()




def parse_reply(reply, test_id, duration):
    print(">>>>>>>>>> reply")
    print(reply)
    print("<<<<<<<<<<<<")
    sample = Database.Sample()
    sample.test_id = test_id
    sample.duration = duration
    return sample


def print_report(test_id, sample, app, concurrency, transport, cpu_usage):
    s = ""
    if sample != None:
        s += ("%d/%d: " % (test_id, sample.id))

    s += ("%s:%s: c=%d, CPU=%s" %
        (transport.value, app, concurrency, str(cpu_usage)))

#    if sample != None:
#        pps = sample.results[Database.Sample.IPPS] + sample.results[Database.Sample.OPPS]
#        s += ", %.2f mpps" % (pps/1000000)
#        if False:
#            rxmtps = sample.results[Database.Sample.RXMTPS]
#            s += ", %.2f rxmtps" % (rxmtps/1000000)

    s += " ... "

    if sample == None:
        s += "Error"
    elif sample.runner_cpu_percent < 98:
        s += "Failed"
    else:
        s += "Passed"

    print_log(s, True)


def run_sample(app, test_id, transport, concurrency, cpus):
    app.stop()

    proc = app.start(transport, concurrency, cpus)

    # Wait netmap interface goes up
    time.sleep(2)
    g_runner.cooling()
    g_runner.send_req(concurrency)

    netstat_begin = app.read_netstat()
    top = cpu_percent(g_runner.duration, cpus)

    reply = g_runner.recv_msg()
    if not reply:
        raise RuntimeError("Lost connection to tester")

    netstat_end = app.read_netstat()

    app.stop()
    g_runner.stop()
    wait_process(proc)

    sample = parse_reply(reply, test_id, g_runner.duration)

    sample.runner_cpu_percent = int(numpy.mean(top))
    sample.tester_cpu_percent = 0

    if sample != None:
        sample.id = g_db.add_sample(sample)
        netstat_rate = Netstat.rate(netstat_begin, netstat_end, g_runner.duration)
        netstat_rate.write(g_db, sample.id, Database.ROLE_RUNNER)

    print_report(test_id, sample, app.get_name(), concurrency, transport, top)

    if sample == None and sample.runner_cpu_percent < 98:
        g_runner.ts_failed += 1
    else:
        g_runner.ts_pass += 1


def run_application(app, cpus, transport, concurrency):
    if g_runner.dry_run:
        test_id = -1
        sample_count = 0
    else:
        if transport == Transport.NATIVE:
            commit = ""
        else:
            commit = g_project.commit

        cpu_mask = make_cpu_mask(cpus)
        test_id, sample_count = g_db.add_test(commit, TESTER_LOCAL_CON_GEN, app.id,
            transport, g_runner.interface.driver_id, concurrency, cpu_mask, g_runner.duration)

    g_runner.ts_planned += g_runner.sample

    for j in range (0, g_runner.sample - sample_count):
        g_runner.interface.set_channels(cpus)
        run_sample(app, test_id, transport, concurrency, cpus)



################ MAIN ####################


system("ip a flush dev %s" % g_runner.interface.name)
system("ip a a dev %s %s/32" % (g_runner.interface.name, get_runner_ip(g_subnet)))
system("ip r flush dev %s" % g_runner.interface.name)
system("ip r d %d.%d.1.1/32" % (g_subnet[0], g_subnet[1]), True)
system("ip r a dev %s %d.%d.1.1/32 initcwnd 1" %
    (g_runner.interface.name, g_subnet[0], g_subnet[1]))
system("ip r d %d.%d.0.0/15" % (g_subnet[0], g_subnet[1]), True)
system(("ip r a dev %s %d.%d.0.0/15 via %d.%d.1.1 initcwnd 1" %
    (g_runner.interface.name, g_subnet[0], g_subnet[1], g_subnet[0], g_subnet[1])))


g_project.write_gbtcp_conf(g_runner.transport[0], g_runner.interface.name)

for test in g_runner.tests:
    if issubclass(type(test), Simple):
        test.run()

for test in g_runner.tests:
    if issubclass(type(test), Application):
        for i in g_runner.cpu_count:
            cpus = g_runner.cpus[:i]
            for transport in g_runner.transport:
                g_project.write_gbtcp_conf(transport, g_runner.interface.name)
                for concurrency in g_runner.concurrency:
                    run_application(test, cpus, transport, concurrency)
