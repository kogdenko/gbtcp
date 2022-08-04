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
import netstat

g_subnet = (10, 20, 0, 0)
g_connect = None
g_interface_name = None
g_transport = []
g_concurrency = []
g_cpus = None
g_cpu_count = None
g_report_count = 10
g_delay = 2
g_sample_count = Database.SAMPLE_COUNT_MAX
g_cooling_time = 2
g_stop_at_milliseconds = None
g_dry_run = False
g_preload = True
g_apps = []
g_tests = []
g_simple_test = []
g_tcpkt_test = []


g_project = Project()
g_db = Database("")

class Runner:
   def __init__(self): 
        self.ts_planned = 0
        self.ts_pass = 0
        self.ts_failed = 0

g_runner = Runner()

def usage():
    print("Usage: runner [options] {[--netmap-dir|-N] path}")
    print("")
    print("Options:")
    print("\t-h, --help: Print this help")
    print("\t-i {interface}: For performance testing")
    print("\t--cpu {a-b,c,d}: Bind applications on this cpus")

def is_local(address):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((address, 9999))
    except socket.error as e:
        if e.errno == errno.EADDRINUSE:
            return True
        else:
            return False
    return True

def fill_test_list():
    for f in os.listdir(g_project.path + '/bin'):
        if f[:10] == "gbtcp-test":
            if os.path.isfile(g_project.path + '/test/' + f + '.pkt'):
                g_tcpkt_test.append(f)
            else:
                g_simple_test.append(f)

def test_exists(test):
    if test in g_simple_test:
        return True
    if  test in [app.get_name() for app in g_apps]:
            return True
    return False

def configure_transport():
    if len(g_transport) == 0:
        if g_project.have_netmap:
            g_transport.append("netmap")
        elif g_project.have_xdp:
            g_transport.append("xdp")
        else:
            die("No transport supported")

def configure_cpu_count():
    global g_cpu_count

    if g_cpu_count == None or len(g_cpu_count) == 0:
        g_cpu_count = [ * range(1, len(g_cpus) + 1) ]
    else:
        if g_cpu_count[-1] > len(g_cpus):
            die("--cpu-count: Should be less then number of specified cpus (see '--cpu')")
        if g_cpu_count[0] <= 0:
            die("--cpu-count: Should be greater then 0")

def sendto_tester(concurrency):
    args = ("--dst-mac %s "
        "--subnet %d.%d.0.0 "
        "--delay %d "
        "--duration %d "
        "--concurrency %d "
        "--application con-gen" % (
        str(g_runner.interface.mac),
        g_subnet[0], g_subnet[1],
        g_delay,
        g_report_count,
        concurrency))
    try:
        tester = socket.create_connection((g_connect, 9999))
    except socket.error as e:
        die("Cannot connect to '%s': %s" % (g_connect, str(e)))
    tester.send((args + "\n").encode('utf-8'))
    return tester

def recvfrom_tester(s):
    # We should get bytes from recv() without any delay,
    # because time passed in measure_cpu_usage() called before
    s.settimeout(10)
    data = bytearray()
    while True:
        buf = s.recv(1024)
        if not buf:
            s.close()
            return data
        data += bytearray(buf)
    return data

def print_invalid_tester_reply(s):
    print_log("Invalid tester reply:\n%s" % s)

def parse_tester_reply(reply_ba, test_id, duration):
    reply = reply_ba.decode('utf-8').strip()

    rows = reply.split('\n')
    if len(rows) != 1:
        print_invalid_tester_reply(reply)       
        return None
    cols = rows[0].split()
    if len(cols) == 1:
        return None
    if len(cols) != Database.Sample.CONCURRENCY + 2:
        print_invalid_tester_reply(reply)
        return None

    sample = Database.Sample()
    sample.test_id = test_id
    sample.duration = duration
    sample.results = []
    for i in range(1, len(cols)):
        if not is_int(cols[i]):
            print_invalid_tester_reply(reply)
            return None
        sample.results.append(int(cols[i]))
    return sample

def set_stop_time():
    global g_stop_at_milliseconds
    g_stop_at_milliseconds = milliseconds()

def cooling():
    ms = milliseconds() - g_stop_at_milliseconds
    if ms < g_cooling_time * 1000:
        t = int(math.ceil((g_cooling_time * 1000 - ms) / 1000))
        time.sleep(t)

def print_report(test_id, sample, app, preload, concurrency, transport, cpu_usage, low):
    if not preload:
        transport = "native"

    s = ""
    if sample != None and not low:
        s += ("%d/%d: " % (test_id, sample.id))

    s += ("%s:%s: c=%d, CPU=%s" %
        (transport, app, concurrency, str(cpu_usage)))

    if sample != None:
        pps = sample.results[Database.Sample.IPPS] + sample.results[Database.Sample.OPPS]
        s += ", %.2f mpps" % (pps/1000000)
        if False:
            rxmtps = sample.results[Database.Sample.RXMTPS]
            s += ", %.2f rxmtps" % (rxmtps/1000000)

    s += " ... "

    if sample == None:
        s += "Error"
    elif low:
        s += "Failed"
    else:
        s += "Passed"

    print_log(s, True)

last_used_cpus = None

def do_test(app, cpus, preload, transport, concurrency):
    global last_used_cpus

    if g_dry_run:
        test_id = -1
        sample_count = 0
    else:
        if preload:
            commit = g_project.commit
            transport_id = get_dict_id(transport_dict, transport)
            assert(transport_id != None)
        else:
            if not app.support_native():
                return
            commit = ""
            transport_id = TRANSPORT_NATIVE

        test_id, sample_count = g_db.add_test(commit, g_tester_id, app.id,
            transport_id, g_runner.interface.driver_id, concurrency, len(cpus), g_report_count)

    g_runner.ts_planned += g_sample_count

    for j in range (0, g_sample_count - sample_count):
        if last_used_cpus != cpus:
            last_used_cpus = cpus
            # Wait interface become available
            time.sleep(2)
            g_runner.interface.set_channels(cpus)

        rc = app.start_test(test_id, transport, concurrency, cpus, preload)
        if rc:
            g_runner.ts_pass += 1
        else:
            g_runner.ts_failed += 1

class application:
    id = None

    def __init__(self):
        self.id = g_db.get_app_id(self.get_name(), self.get_version())

    def support_native(self):
        return True

    def parse_version(self, s):
        m = re.search(r'[0-9]+\.[0-9]+\.[0-9]+', s.strip())
        if m == None:
            die("%s: Cannot get version" % s)
        return m.group(0)

    def start_test(self, test_id, transport, concurrency, cpus, preload):
        self.stop()

        if not preload:
            ns = netstat.read()

        proc = self.start(concurrency, cpus, preload)

        # Wait netmap interface goes up
        time.sleep(2)
        cooling()
        tester = sendto_tester(concurrency)

        # FIXME: Wait ARP negotiaition
        cpu_usage = cpu_percent(g_report_count, g_delay, cpus)

        data = recvfrom_tester(tester)

        low = False
        for j in cpu_usage:
            if j < 98:
                low = True
                break

        self.stop()
        g_project.wait_process(proc)
        set_stop_time()

        sample = parse_tester_reply(data, test_id, g_report_count)

        if sample != None and not low:
            sample.id = g_db.add_sample(sample)

        print_report(test_id, sample, self.get_name(), preload, concurrency, transport, cpu_usage, low)

        if not preload:
            ns2 = netstat.read()
            ns = netstat.diff(ns, ns2)
            s = netstat.to_string(ns)
            print_log("netstat:\n%s" % s)

        if sample == None or low:
            return False
        else:
            return True

class nginx(application):

    def get_name(self):
        return "nginx"

    def get_version(self):
        s = system("nginx -v")[2]
        return self.parse_version(s)

    def stop(self):
        system("nginx -s quit", True)

    def start(self, concurrency, cpus, preload):

        worker_cpu_affinity = ""

        n = len(cpus)
        assert(n > 0)

        cpu_count = multiprocessing.cpu_count()
        templ = list()
        for i in range(0, cpu_count):
            templ.append('0')
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

        f = open(nginx_conf_path, 'w')
        f.write(nginx_conf)
        f.close()

        return g_project.start_process("nginx -c %s" % nginx_conf_path, preload)

    def __init__(self):
        application.__init__(self)

class gbtcp_base_helloworld(application):
    path = None

    def get_version(self):
        cmd = "%s -v" % self.path
        s = g_project.system(cmd)[1]
        for line in s.splitlines():
            if line.startswith("version: "):
                return self.parse_version(line)
        die("%s: Invalid output" % cmd)

    def stop(self):
        g_project.system("%s -S" % self.path, True)

    def start(self, concurrency, cpus, preload):
        cmd = "%s -l -a " % self.path
        for i in range(len(cpus)):
            if i != 0:
                cmd += ","
            cmd += str(cpus[i])
        return g_project.start_process(cmd, preload)

    def __init__(self):
        self.path = g_project.path + "/bin/" + self.get_name()
        application.__init__(self)

class gbtcp_epoll_helloworld(gbtcp_base_helloworld):
    def get_name(self):
        return "gbtcp-epoll-helloworld"

class gbtcp_aio_helloworld(gbtcp_base_helloworld):
    def get_name(self):
        return "gbtcp-aio-helloworld"

    def support_native(self):
        return False


################ MAIN ####################
fill_test_list()
g_apps.append(nginx())
g_apps.append(gbtcp_epoll_helloworld())
g_apps.append(gbtcp_aio_helloworld())

try:
    opts, args = getopt.getopt(sys.argv[1:], "hvi:", [
        "help",
        "dry-run",
        "listen=",
        "connect=",
        "cpu=",
        "cpu-count=",
        "concurrency=",
        "transport=",
        "reports=",
        "delay=",
        "sample=",
        "cooling-time=",
        "reload-netmap=",
        "test=",
        "preload=",
        ])
except getopt.GetoptError as err:
    print(err)
    usage()
    sys.exit(1)
for o, a in opts:
    if o in ("-h", "--help"):
        usage()
        sys.exit(0)
    elif o in ("--dry-run"):
        g_dry_run = True
    elif o in ("-i"):
        g_interface_name = a
    elif o in ("--cpu"):
        try:
            g_cpus = make_integer_list(a)
            set_cpus_scaling_governor(g_cpus)
        except Exception as error:
            print("!!!!!!!!!!!!!")                
            #invalid_argument(o, a, error)
            #sys.exit(1)
            #die("--cpu: Invalid argument: '%s'" % a)
    elif o in ("--connect"):
        g_connect = a
    elif o in ("--reports"):
        g_report_count = int(a)
    elif o in ("--delay"):
        g_delay = int(a)
    elif o in ("--sample"):
        g_sample_count = int(a)
    elif o in ("--cooling-time"):
        g_cooling_time = int(a)
    elif o in ("--cpu-count"):
        g_cpu_count = make_integer_list(a)
    elif o in ("--concurrency"):
        g_concurrency = make_integer_list(a)
    elif o in ("--transport"):
        for transport in a.split(','):
            if get_dict_id(transport_dict, transport) == None:
                die("Unknown '--transport' argument")
            if not transport in g_transport:
                g_transport.append(transport)
    elif o in ("--preload"):
        g_preload = bool(int(a) != 0)
    elif o in ("--test"):
        for test in a.split(','):
            if test != "":
                if test_exists(test):
                    if not test in g_tests:
                        g_tests.append(test)
                else:
                    die("Test '%s' doesn't exists" % test)

if g_interface_name == None:
    die("Interface not specified (see '-i')")

if g_cpus == None:
    die("No cpu specified (see '--cpu'")

driver = get_interface_driver(g_interface_name)

g_runner.interface = create_interface(g_interface_name, driver)

if g_connect == None:
    die("'--connect' must be specified")

if len(g_tests) == 0:
    die("No tests specified (see '--test')")

if len(g_concurrency) == 0:
    g_concurrency.append(1000)

configure_transport()

if is_local(g_connect):
    g_tester_id = TESTER_LOCAL_CON_GEN
else:
    g_tester_id = TESTER_REMOTE_CON_GEN

configure_cpu_count()

system("ip a flush dev %s" % g_runner.interface.name)
system("ip a a dev %s %s/32" % (g_runner.interface.name, get_runner_ip(g_subnet)))
system("ip r flush dev %s" % g_runner.interface.name)
system("ip r d %d.%d.1.1/32" % (g_subnet[0], g_subnet[1]), True)
system("ip r a dev %s %d.%d.1.1/32 initcwnd 1" %
    (g_runner.interface.name, g_subnet[0], g_subnet[1]))
system("ip r d %d.%d.0.0/15" % (g_subnet[0], g_subnet[1]), True)
system(("ip r a dev %s %d.%d.0.0/15 via %d.%d.1.1 initcwnd 1" %
    (g_runner.interface.name, g_subnet[0], g_subnet[1], g_subnet[0], g_subnet[1])))

# Assume that last test ended at least 10 seconds ago
g_stop_at_milliseconds = milliseconds() - 10000

g_project.write_gbtcp_conf(g_transport[0], g_runner.interface.name)

for test in g_tests:
    if test in g_simple_test:
        g_runner.ts_planned += 1
        proc = g_project.start_process(g_project.path + '/bin/' + test, False)
        if g_project.wait_process(proc)[0] == 0:
            g_runner.ts_pass += 1
            status = "Pass"
        else:
            g_runner.ts_failed += 1
            status = "Failed"
        print_log("runner: %s ... %s" % (test, status), True)
    else:
        for app in g_apps:
            if test == app.get_name():
                for i in g_cpu_count:
                    cpus = g_cpus[:i]
                    for transport in g_transport:
                        g_project.write_gbtcp_conf(transport, g_runner.interface.name)
                        for concurrency in g_concurrency:
                            do_test(app, cpus, g_preload, transport, concurrency)
                break

print("Planned: ", g_runner.ts_planned)
print("Pass: ", g_runner.ts_pass)
print("Failed: ", g_runner.ts_failed)
