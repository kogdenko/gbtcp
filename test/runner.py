#!/usr/bin/python

import os
import sys
import time
import math
import atexit
import getopt
import socket
import subprocess
import platform
import importlib
import multiprocessing
import psutil
import re
import numpy

from common import *

subnet = "10.20"
g_listen = None
g_connect = None
g_interface = None
g_tester_interface = None
g_runner_interface = None
g_drivers = []
g_concurrency = []
g_cpu_list = None
g_tester_cpus = None
g_runner_cpus = None
tester_mac = None
device_mac = None
device_ip = None
g_report_count = 10
g_skip_reports = 2
g_sample_count = SAMPLE_COUNT_MAX
g_cooling_time = 2
g_cpu_count_min = 1
g_reload_netmap = None
g_stop_at_milliseconds = None
g_dry_run = False
g_apps = []
g_tests = []
g_simple_test = []
g_tcpkt_test = []

env = Environment()

def usage():
    print("Usage: runner [options] {[--netmap-dir|-N] path}")
    print("")
    print("Options:")
    print("\t-h, --help: Print this help")
    print("\t-i {interface}: For performance testing")
    print("\t--cpu-list {a-b,c,d}: Bind applications on this cpus")

def fill_test_list():
    for f in os.listdir(env.project_path + '/bin'):
        if f[:10] == "gbtcp-test":
            if os.path.isfile(env.project_path + '/test/' + f + '.pkt'):
                g_tcpkt_test.append(f)
            else:
                g_simple_test.append(f)

def test_exists(test):
    if test in g_simple_test:
        return True
    if  test in [app.get_name() for app in g_apps]:
            return True
    return False

def get_interface_mac(interface):
    f = open("/sys/class/net/%s/address" % interface)
    mac = f.read().strip()
    f.close()
    return mac

def get_device_ip(subnet):
    return subnet + ".255.1"

def insmod(module_name):
    if module_name == "ixgbe":
        module_dir = "ixgbe"
    else:
        module_dir = ""

    path = g_reload_netmap + "/" + module_dir + "/" + module_name + ".ko"

    system("insmod %s" % path)

def measure_cpu_usage(t, delay, cpus):
    # Skip last second
    assert(t > delay)
    time.sleep(delay)
    percent = psutil.cpu_percent(t - delay - 1, True)
    cpu_usage = []
    for cpu in cpus:
        cpu_usage.append(percent[cpu])
    return cpu_usage

def get_gbtcp_conf_path():
    return env.project_path + "/test/gbtcp.conf"

def write_gbtcp_conf(driver):
    gbtcp_conf_path = get_gbtcp_conf_path()

    gbtcp_conf = (
        "dev.transport=%s\n"
        "route.if.add=%s\n"
        % (driver, g_runner_interface))

    f = open(gbtcp_conf_path, 'w')
    f.write(gbtcp_conf)
    f.close()

def start_process(cmd, preload):
    e = os.environ.copy()
    e["LD_LIBRARY_PATH"] = env.project_path + "/bin"
    if preload:
        e["LD_PRELOAD"] = os.path.normpath(env.project_path + "/bin/libgbtcp.so")
        e["GBTCP_CONF"] = get_gbtcp_conf_path()

    proc = subprocess.Popen(cmd.split(), env = e,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    print_log("$ %s &\n[%d]" % (cmd, proc.pid))

    return proc

def wait_process(proc):
    proc.wait()
    lines = []
    for pipe in [proc.stdout, proc.stderr]:
        while True:
            line = pipe.readline()
            if not line:
                break
            lines.append(line.decode('utf-8').strip())
    print_log("$ [%d] Done + %d\n%s" % (proc.pid, proc.returncode, '\n'.join(lines)))
    return proc.returncode, lines

def run_tester(args):
    subnet = None
    reports = None
    device_mac = None
    concurrency = None

    try:
        opts, args = getopt.getopt(args.split(), "D:", [
            "subnet=",
            "reports=",
            "concurrency=",
            ])
    except getopt.GetoptError as err:
        print_log(err)
        die("tester: Invalid options")

    for o, a in opts:
        if o in ("-D"):
            device_mac = a
        elif o in ("--subnet"):
            subnet = a
        elif o in ("--reports"):
            reports = int(a)
        elif o in ("--concurrency"):
            concurrency = int(a)
   
    if (device_mac == None or subnet == None or
        reports == None or concurrency == None):
        die("tester: Missed required options")
    
    device_ip = get_device_ip(subnet)
    cmd = "con-gen "
#    cmd += "--toy "
    cmd += "--print-banner 0 --print-statistics 0 --report-bytes 1 "
    cmd += ("-S %s -D %s --reports %d -N -p 80 -d %s" %
        (tester_mac, device_mac, reports, device_ip))

    n = len(g_tester_cpus)
    for i in range(n):
        concurrency_per_cpu = concurrency / n
        if i == 0:
            concurrency_per_cpu += concurrency % n
        else:
            cmd += " --"
        cmd += " -i %s-%d" % (g_tester_interface, i)
        cmd += " -c %d" % concurrency_per_cpu
        cmd += " -a %d" % g_tester_cpus[i]
        cmd += " -s %s.%d.1-%s.%d.255" % (subnet, i + 1, subnet, i + 1)

    return (start_process(cmd, False), reports)

def start_tester(concurrency):
    assert(device_mac != None)
    args = ("-D %s --subnet %s --reports %d --concurrency=%d" %
        (device_mac, subnet, g_report_count, concurrency))
    if g_connect == None:
        if g_interface != None:
            die("'--connect' not specified")
        tester, _ = run_tester(args)
    else:
        try:
            tester = socket.create_connection((g_connect, 9999))
        except socket.error as e:
            die("Can't connect to tester: %s" % e)
        tester.send((args + "\n").encode('utf-8'))
    return tester

def wait_tester_socket(s):
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

def wait_tester_proc(tester, reports):
    # FIXME: Wait APR negotiaition
    cpu_usage = measure_cpu_usage(reports, 2, g_tester_cpus)

    rc, lines = wait_process(tester)

    data = bytearray()
    for line in lines:
        data += bytearray((line + "\n").encode('utf-8'))

    print_log("tester: %s: CPU=%s ... %s" %
        (tester.args[0], list_to_str(cpu_usage), "Ok" if rc == 0 else "Failed"), True)

    return data

def wait_tester(tester):
    if g_connect != None:
        return wait_tester_socket(tester)
    else:
        return wait_tester_proc(tester, g_report_count)

def tester_loop():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((g_listen, 9999))
    s.listen()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    while True:
        try:
            conn, addr = s.accept()
            data = ""
            done = False
            while not done:
                data += conn.recv(1024).decode('utf-8')
                for i in data:
                    if i == '\n':
                        done = True
                        break
            tester, reports = run_tester(data.strip())
            data = wait_tester_proc(tester, reports)
            conn.send(data)
            conn.close()
        except socket.error as exc:
            print_log("Connection failed: %s" % exc)

def bind_interrupts(interface, cpus):
    f = open("/proc/interrupts", 'r')
    lines = f.readlines()
    f.close()

    irqs = []

    p = re.compile("^%s-TxRx-[0-9]*$" % interface)
    for i in range (1, len(lines)):       
        columns = lines[i].split()
        for col in columns:
            m = re.match(p, col.strip())
            if m != None:
                irq = columns[0].strip(" :")
                if not irq.isdigit():
                    return 1
                irqs.append(int(irq))

    if len(cpus) != len(irqs):
        return 1

    for i in range(0, len(irqs)):
        f = open("/proc/irq/%d/smp_affinity" % irqs[i], 'w')
        f.write("%x" % (1 << cpus[i]))
        f.close()

    return 0

def set_txrx_queue_count(interface, cpus):
    if g_interface == None:
        # Use veth interfaces
        return
    system("ethtool -L %s combined %d" % (interface, len(cpus)))
    err = bind_interrupts(interface, cpus)
    if err != 0:
        die("%s: Failed to bind interrupts" % interface)

def reload_netmap():
    system("rmmod veth", True)
    system("rmmod netmap", True)
    insmod("netmap")
    insmod("veth")

def add_sample(data, reports, test_id, low):
    s = data.decode('utf-8').strip()

    rows = s.split('\n')
    if len(rows) != reports:
        print_log("runner: Invalid number of reports (%d, should be %d)" % (len(rows), reports))
        return None
    sample = Sample()
    sample.records = [[] for i in range(6)]
    for row in rows:
        cols = row.split()
        if len(cols) != 9:
            print_log(("runner: Invalid number of columns (%d, should be 9)\n%s" %
                (len(cols), row)))
            return None
        sample.records[CPS].append(int(cols[0]))
        sample.records[IPPS].append(int(cols[1]))
        sample.records[IBPS].append(int(cols[2]))
        sample.records[OPPS].append(int(cols[3]))
        sample.records[OBPS].append(int(cols[4]))
        sample.records[CONCURRENCY].append(int(cols[8]))
    sample.test_id = test_id
    record = sample.records[CPS][g_skip_reports:]
    sample.outliers, _ = find_outliers(record, None)
    if sample.outliers != None:
        sample.status = SAMPLE_STATUS_OUTLIERS
    elif low:
        sample.status = SAMPLE_STATUS_LOW_CPU_USAGE
    else:
        sample.status = SAMPLE_STATUS_OK
    sample.id = env.add_sample(sample)
    return sample

def set_stop_time():
    global g_stop_at_milliseconds
    g_stop_at_milliseconds = milliseconds()

def cool_down_cpu():
    ms = milliseconds() - g_stop_at_milliseconds
    if ms < g_cooling_time * 1000:
        t = int(math.ceil((g_cooling_time * 1000 - ms) / 1000))
        time.sleep(t)

def print_test(test_id, sample, env, preload, concurrency, driver, cpu_usage):
    if not preload:
        driver = "native"

    if sample == None:
        sample_id = "?"
        pps = None
    else:
        sample_id = str(sample.id)
        pps = []
        for i in range(len(sample.records[IPPS])):
            pps.append(sample.records[IPPS][i] + sample.records[OPPS][i])
        pps = numpy.mean(pps)

    s = ("runner: %d:%s: %s:%s: concurrency=%d, CPU=%s" %
        (test_id, sample_id, driver, env, concurrency, list_to_str(cpu_usage)))
    if pps != None:
        s += ", %.2f mpps" % (pps/1000000)

    s += " ... "

    if sample == None:
        s += "Failed (Bad sample)"
    elif sample.status == SAMPLE_STATUS_OK:
        s += "Passed"
    else:
        s += "Failed "
        if sample.status == SAMPLE_STATUS_OUTLIERS:
            s += ("(outliers=%s)" % list_to_str(sample.outliers))
        else:
            s += "(Low CPU usage)"

    print_log(s, True)

last_used_cpus = None

def do_test(app, cpus, preload, driver, concurrency):
    global last_used_cpus

    env.ts_planned += g_sample_count
    if g_dry_run:
        test_id = -1
        sample_count = 0
    else:
        if preload:
            commit = env.commit
            driver_id = get_driver_id(driver)
        else:
            commit = ""
            driver_id = 0

        test_id, sample_count = env.add_test(commit, app.id, driver_id, concurrency,
            len(cpus), g_report_count)

    for j in range (0, g_sample_count - sample_count):
        if last_used_cpus != cpus:
            last_used_cpus = cpus
            # Wait interface become available
            time.sleep(2)
            set_txrx_queue_count(g_runner_interface, cpus)

        rc = app.start_test(test_id, driver, concurrency, cpus, preload)
        if rc:
            env.ts_pass += 1
        else:
            env.ts_failed += 1

class application:
    id = None

    def __init__(self):
        self.id = env.app_get_id(self.get_name(), self.get_version())

    def parse_version(self, s):
        m = re.search(r'[0-9]+\.[0-9]+\.[0-9]+', s.strip())
        if m == None:
            die("Couldn't get nginx version from '%s'" % s)
        return m.group(0)

    def start_test(self, test_id, driver, concurrency, cpus, preload):
        self.stop()

        proc = self.start(concurrency, cpus, preload)

        # Wait netmap interface goes up
        time.sleep(2)
        cool_down_cpu()
        tester = start_tester(concurrency)

        # FIXME: Wait ARP negotiaition
        cpu_usage = measure_cpu_usage(g_report_count, g_skip_reports, cpus)

        data = wait_tester(tester)

        low = False
        for j in cpu_usage:
            if j < 98:
                low = True
                break

        self.stop()
        wait_process(proc)
        set_stop_time()

        sample = add_sample(data, g_report_count, test_id, low)

        print_test(test_id, sample, self.get_name(), preload, concurrency, driver, cpu_usage)

        if sample == None or sample.status != SAMPLE_STATUS_OK:
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

        templ = list()
        for i in range(0, g_cpu_count):
            templ.append('0')
        for i in cpus:
            templ[g_cpu_count - 1 - i] = '1'
            worker_cpu_affinity += " " + "".join(templ)
            templ[g_cpu_count - 1 - i] = '0'

        worker_connections = upper_pow2_32(concurrency/n)
        if worker_connections < 1024:
            worker_connections = 1024

        nginx_conf = (
            "user root;\n"
            "daemon off;\n"
            "master_process on;\n"
            "\n"
            "worker_processes %d;\n"
            "worker_cpu_affinity %s;\n"
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
            % (n, worker_cpu_affinity, worker_connections, device_ip))

        nginx_conf_path = env.project_path + "/test/nginx.conf"

        f = open(nginx_conf_path, 'w')
        f.write(nginx_conf)
        f.close()

        return start_process("nginx -c %s" % nginx_conf_path, preload)

    def __init__(self):
        application.__init__(self)

class gbtcp_base_helloworld(application):
    path = None

    def get_version(self):
        cmd = "%s -v" % self.path
        s = system(cmd)[1]
        for line in s.splitlines():
            if line.startswith("version: "):
                return self.parse_version(line)
        die("%s: Invalid output" % cmd)

    def stop(self):
        system("%s -S" % self.path, True)

    def start(self, concurrency, cpus, preload):
        cmd = "%s -l -a " % self.path
        for i in range(len(cpus)):
            if i != 0:
                cmd += ","
            cmd += str(cpus[i])
        return start_process(cmd, preload)

    def __init__(self):
        self.path = env.project_path + "/bin/" + self.get_name()
        application.__init__(self)

class gbtcp_epoll_helloworld(gbtcp_base_helloworld):
    def get_name(self):
        return "gbtcp-epoll-helloworld"

class gbtcp_aio_helloworld(gbtcp_base_helloworld):
    def get_name(self):
        return "gbtcp-aio-helloworld"

################ MAIN ####################
fill_test_list()
g_apps.append(nginx())
g_apps.append(gbtcp_epoll_helloworld())
g_apps.append(gbtcp_aio_helloworld())

try:
    opts, args = getopt.getopt(sys.argv[1:], "hvL:i:t:", [
        "help",
        "dry-run",
        "listen=",
        "connect=",
        "cpu-list=",
        "cpu-count-min=",
        "concurrency=",
        "drivers=",
        "reports=",
        "skip-reports=",
        "samples=",
        "cooling-time=",
        "reload-netmap=",
        "test=",
        ])
except getopt.GetoptError as err:
    print(err)
    usage()
    sys.exit(1)
for o, a in opts:
    if o in ("-h", "--help"):
        usage()
        sys.exit()
    elif o in ("--dry-run"):
        g_dry_run = True
    elif o in ("-i"):
        g_interface = a
    elif o in ("--cpu-list"):
        g_cpu_list = str_to_int_list(a)
        if g_cpu_list == None:
            die("--cpu-list: Invalid argument: '%s'" % a)
    elif o in ("-L", "--listen"):
        g_listen = a
    elif o in ("--connect"):
        g_connect = a
    elif o in ("--reload-netmap"):
        g_reload_netmap = os.path.abspath(a)
    elif o in ("--reports"):
        g_report_count = int(a)
    elif o in ("--skip-reports"):
        g_skip_reports = int(a)
    elif o in ("--samples"):
        g_sample_count = int(a)
    elif o in ("--cooling-time"):
        g_cooling_time = int(a)
    elif o in ("--cpu-count-min"):
        g_cpu_count_min = int(a)
    elif o in ("--concurrency"):
        g_concurrency = str_to_int_list(a)
    elif o in ("--drivers"):
        for driver in a.split(','):
            if driver == "xdp":
                if not env.have_xdp:
                    die("XDP driver not supported")
            elif driver == "netmap":
                if not env.have_netmap:
                    die("netmap driver not supported")
            else:
                    die("%s driver not supported" % driver)
            if not driver in g_drivers:
                g_drivers.append(driver)
    elif o in ("--test"):
        for test in a.split(','):
            if test != "":
                if test_exists(test):
                    if not test in g_tests:
                        g_tests.append(test)
                else:
                    die("Test '%s' doesn't exists" % test)

if g_listen == None and len(g_tests) == 0:
    die("No tests specified (see '--test')")

if len(g_concurrency) == 0:
    g_concurrency.append(1000)

if len(g_drivers) == 0:
    if env.have_netmap:
        g_drivers.append("netmap")
    elif env.have_xdp:
        g_drivers.append("xdp")
    else:
        die("No driver supported")

g_cpu_count = multiprocessing.cpu_count()
if g_cpu_list == None:
    g_cpu_list = list()
    for i in range(0, g_cpu_count):
        g_cpu_list.append(i)
else:
    for i in g_cpu_list:
        if i >= g_cpu_count:
            die("--cpu-list: CPU %d exceeds number of CPUs %d" % (i, g_cpu_count))

for i in g_cpu_list:
    path = "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor" % i
    f = open(path, 'w')
    f.write("performance")
    f.close()

if g_interface == None:
    if g_reload_netmap != None:
        reload_netmap()
else:
    try:
        path = "/sys/class/net/%s/device/driver" % g_interface
        path = os.readlink(path)
    except FileNotFoundError:
        die("Interface '%s' not found" % g_interface)
    except:
        die("readlink('%s') failed: %s" % (path, sys.exc_info()[0]))
    interface_module = os.path.basename(path)
    if g_reload_netmap != None:
        system("rmmod %s" % interface_module, True)
        reload_netmap()
        insmod(interface_module)
        # Wait interfaces after inserting module
        time.sleep(1)
    system("ethtool -K %s rx off tx off" % g_interface)
    system("ethtool -K %s gso off" % g_interface)
    system("ethtool -K %s ntuple on" % g_interface)
    system("ethtool --show-ntuple %s rx-flow-hash tcp4" % g_interface)
    system("ethtool -N %s rx-flow-hash tcp4 sdfn" % g_interface)
    system("ethtool -N %s rx-flow-hash udp4 sdfn" % g_interface)
    system("ethtool -G %s rx 2048 tx 2048" % g_interface)
    system("ip l s dev %s up" % g_interface)

if g_listen != None:
    if g_connect != None:
        die("--connect: Can't be specified with --listen option")
    if g_interface == None:
        die("-i: Should be specified with --listen option")

    g_tester_interface = g_interface
    tester_mac = get_interface_mac(g_tester_interface)
    g_tester_cpus = g_cpu_list
    set_txrx_queue_count(g_interface, g_tester_cpus)
    tester_loop()
    sys.exit(0)

if g_interface == None:
    if len(g_cpu_list) < 2:
        die("--cpu-list: Specify more then 1 cpu for testing on veth")

    vethc = "gt_veth_c"
    veths = "gt_veth_s"
    cmac = "72:9c:29:36:5e:02"
    smac = "72:9c:29:36:5e:01"

    system("ip l a dev %s type veth peer name %s" % (veths, vethc))
    system("ethtool -K %s rx off tx off" % veths)
    system("ethtool -K %s rx off tx off" % vethc)
    system("ip l s dev %s address %s up" % (veths, smac))
    system("ip l s dev %s address %s up" % (vethc, cmac))

    g_tester_cpus = g_cpu_list[1:2]
    g_runner_cpus = g_cpu_list[0:1]
    g_tester_interface = vethc
    g_runner_interface = veths
    tester_mac = cmac
    device_mac = smac

else:
    g_runner_cpus = g_cpu_list
    g_runner_interface = g_interface
    device_mac = get_interface_mac(g_runner_interface) 

device_ip = get_device_ip(subnet) 
system("ip a flush dev %s" % g_runner_interface)
#system("ip a d %s/32" % device_ip, True)
system("ip a a dev %s %s/32" % (g_runner_interface, device_ip))
system("ip r flush dev %s" % g_runner_interface)
system("ip r d %s.1.1/32" % subnet, True)
system("ip r a dev %s %s.1.1/32 initcwnd 1" % (g_runner_interface, subnet))
system("ip r d %s.0.0/15" % subnet, True)
system("ip r a dev %s %s.0.0/15 via %s.1.1 initcwnd 1" % (g_runner_interface, subnet, subnet))

# Assume that last test ended at least 10 seconds ago
g_stop_at_milliseconds = milliseconds() - 10000

write_gbtcp_conf(g_drivers[0])

for test in g_tests:
    if test in g_simple_test:
        env.ts_planned += 1
        proc = start_process(env.project_path + '/bin/' + test, False)
        if wait_process(proc)[0] == 0:
            env.ts_pass += 1
            status = "Pass"
        else:
            env.ts_failed += 1
            status = "Failed"
        print_log("runner: %s ... %s" % (test, status), True)
    else:
        for app in g_apps:
            if test == app.get_name():
                for i in range (g_cpu_count_min, len(g_runner_cpus) + 1):
                    cpus = g_runner_cpus[:i]
                    for driver in g_drivers:
                        write_gbtcp_conf(driver)
                        for concurrency in g_concurrency:
                            do_test(app, cpus, True, driver, concurrency)
                break

print("Planned: ", env.ts_planned)
print("Pass: ", env.ts_pass)
print("Failed: ", env.ts_failed)
