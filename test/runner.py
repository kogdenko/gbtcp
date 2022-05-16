#!/usr/bin/python

# /test/runner.py -v  -N ../../open_source/netmap/ -i eth2

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
import scipy

from common import *

netmap_dir = None
subnet = "10.20"
listen = None
connect = None
connect_sock = None
interface = None
interface_module = None
g_tester_interface = None
g_runner_interface = None
g_concurrency = []
g_cpu_list = None
g_tester_cpus = None
g_runner_cpus = None
tester_mac = None
device_mac = None
device_ip = None
scaling_governor = dict()
clean_on_exit = False
g_report_count = 10
g_skip_reports = 1
g_sample_count = 5
g_cooling_time = 2
g_cpu_count_min = 1
reload_modules = False
g_test_path = None
g_stop_at_milliseconds = None
g_dry_run = False

def usage():
    print("Usage: runner [options] {[--netmap-dir|-N] path}")
    print("")
    print("Options:")
    print("\t-h, --help: Print this help")
    print("\t-v, --verbose: Be verbose")
    print("\t-i {interface}: For performance testing")
    print("\t--cpu-list {a-b,c,d}: Bind applications on this cpus")
#    print("\t--clean-on-exit: Restore environment after runner finish w")



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

    path = netmap_dir + "/" + module_dir + "/" + module_name + ".ko"

    system("insmod %s" % path)


def measure_cpu_usage(reports, cpus):
    # Skip first and last seconds
    time.sleep(1)
    percent = psutil.cpu_percent(reports - 2, True)
    cpu_usage = []
    for cpu in cpus:
        cpu_usage.append(percent[cpu])
    return cpu_usage

def start_process(cmd, env=None, shell=False):
    if get_verbose() > 1:
        print("$", cmd, "&")
    proc = subprocess.Popen(cmd.split(), env=env, shell=shell,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc

def start_nginx(concurrency, cpu_list, native):
    worker_cpu_affinity = ""

    n = len(cpu_list)
    assert(n > 0)

    templ = list()
    for i in range(0, g_cpu_count):
        templ.append('0')
    for i in cpu_list:
        templ[g_cpu_count - 1 - i] = '1'
        worker_cpu_affinity += " " + "".join(templ)
        templ[g_cpu_count - 1 - i] = '0'

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
        %
        (n, worker_cpu_affinity, upper_pow2_32(concurrency/n), device_ip))

    gbtcp_conf = ("route.if.add=%s" % g_runner_interface)

    assert(netmap_dir != None)

    libgbtcp_path = os.path.normpath(g_test_path + "/../bin/libgbtcp.so")

    nginx_conf_path = g_test_path + "/nginx.conf"
    gbtcp_conf_path = g_test_path + "/gbtcp.conf"

    f = open(nginx_conf_path, 'w')
    f.write(nginx_conf)
    f.close()

    f = open(gbtcp_conf_path, 'w')
    f.write(gbtcp_conf)
    f.close()

    env = os.environ.copy()
    if not native:
        env["LD_PRELOAD"] = libgbtcp_path
        env["GBTCP_CONF"] = gbtcp_conf_path

    return start_process("nginx -c %s" % nginx_conf_path, env=env)

def stop_nginx():
    system("nginx -s quit", True)


def run_gen(args):
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
        print(err)
        die("generator: Invalid options")

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
        die("generator: Required option missed")
    
    device_ip = get_device_ip(subnet)
    cmd = "con-gen "
#    cmd += "--toy "
    cmd += "--print-banner 0 --print-statistics 0 --report-bytes 1 "
    cmd += ("-S %s -D %s --reports %d -N -p 80 -d %s" %
        (tester_mac, device_mac, reports, device_ip))

    n = len(g_tester_cpus)
    for i in range(n):
        cpu_concurrency = concurrency / n
        if i == 0:
            cpu_concurrency += concurrency % n
        else:
            cmd += " --"
        cmd += " -i %s-%d" % (g_tester_interface, i)
        cmd += " -c %d" % cpu_concurrency
        cmd += " -a %d" % g_tester_cpus[i]
        cmd += " -s %s.%d.1-%s.%d.255" % (subnet, i + 1, subnet, i + 1)

    return (start_process(cmd), reports)

def start_generator(concurrency):
    assert(device_mac != None)
    args = ("-D %s --subnet %s --reports %d --concurrency=%d" %
        (device_mac, subnet, g_report_count, concurrency))
    if connect == None:
        gen, _ = run_gen(args)
    else:
        try:
            gen = socket.create_connection((connect, 9999))
        except socket.error as e:
            die("Can't connect to tester: %s" % e)
        gen.send((args + "\n").encode('utf-8'))
    return gen

def wait_generator_socket(s):
    data = bytearray()
    while True:
        buf = s.recv(1024)
        if not buf:
            s.close()
            return data
        data += bytearray(buf)

def print_proc_output(proc):
    for pipe in [proc.stdout, proc.stderr]:
        while True:
            line = pipe.readline()
            if not line:
                break
            print(line)

def proc_wait(proc, proc_name):
    proc.wait()
    if proc.returncode != 0:
        print_proc_output(proc)
        die("%s: Failed, returncode %d" % (proc_name, proc.returncode))

def wait_generator_proc(con_gen, reports):
    # FIXME: Wait APR negotiaition
    time.sleep(2)
    cpu_usage = measure_cpu_usage(reports - 2, g_tester_cpus)

    proc_wait(con_gen, "generator")

    high = False 
    for i in cpu_usage:
        if i > 97:
            high = True
            break;
    if high:
        print("generator: Too high CPU usage", cpu_usage, ", Please, consider to add more CPUs")
    elif get_verbose() > 0:
        print("generator: Done, CPU usage", cpu_usage)

    data = bytearray()
    while True:
        line = con_gen.stdout.readline()
        if not line:
            break
        data += bytearray(line)
    return data

def wait_generator(con_gen):
    if connect != None:
        return wait_generator_socket(con_gen)
    else:
        return wait_generator_proc(con_gen, g_report_count)

def tester_loop():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((listen, 9999))
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
            con_gen, reports = run_gen(data.strip())
            data = wait_generator_proc(con_gen, reports)
            conn.send(data)
            conn.close()
        except socket.error as exc:
            print("Connection failed: %s" % exc)

app = App()

try:
    opts, args = getopt.getopt(sys.argv[1:], "hvN:L:C:i:t:", [
        "help",
        "verbose",
        "dry-run",
        "netmap=",
        "listen=",
        "connect=",
        "cpu-list=",
        "cpu-count-min=",
        "concurrency=",
        "reports=",
        "skip-reports=",
        "samples=",
        "cooling-time=",
        "reload-modules",
        ])
except getopt.GetoptError as err:
    print(err)
    usage()
    sys.exit(1)
for o, a in opts:
    if o in ("-h", "--help"):
        usage()
        sys.exit()
    elif o in ("-v", "--verbose"):
        set_verbose(get_verbose() + 1)
    elif o in ("--dry-run"):
        g_dry_run = True
    elif o in ("-i"):
        interface = a
    elif o in ("--cpu-list"):
        g_cpu_list = str_to_int_list(a)
        if g_cpu_list == None:
            print("--cpu-list: Invalid argument: '%s'" % a)
            sys.exit(3)
    elif o in ("-N", "--netmap"):
        netmap_dir = os.path.abspath(a)
    elif o in ("-L", "--listen"):
        listen = a
    elif o in ("-C", "--connect"):
        connect = a
    elif o in ("--reload-modules"):
        reload_modules = True
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

if len(g_concurrency) == 0:
    g_concurrency.append(1000)

g_test_path = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))

g_cpu_count = multiprocessing.cpu_count()
if g_cpu_list == None:
    g_cpu_list = list()
    for i in range(0, g_cpu_count):
        g_cpu_list.append(i)
else:
    for i in g_cpu_list:
        if i >= g_cpu_count:
            print("--cpu-list: CPU %d exceeds number of CPUs %d" % (i, g_cpu_count))
            sys.exit(3)

for i in g_cpu_list:
    path = "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor" % i
    f = open(path, 'r')
    scaling_governor[i] = f.read()
    f.close()
    f = open(path, 'w')
    f.write("performance")
    f.close()

if netmap_dir == None:
    usage()
    sys.exit(1)

stop_nginx()

def get_nginx_ver(app):
    s = system("nginx -v")[2]
    m = re.search(r'[0-9]+\.[0-9]+\.[0-9]+', s.strip())
    if m == None:
        die("Couldn't get nginx version from '%s'" % s)
    return m.group(0)

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
    system("ethtool -L %s combined %d" % (interface, len(cpus)))
    err = bind_interrupts(interface, cpus)
    if err != 0:
        die("%s: Failed to bind interrupts" % interface)

def reload_netmap():
    system("rmmod veth", True)
    system("rmmod netmap", True)
    insmod("netmap")

if interface == None:
    if reload_modules:
        reload_netmap()
else:
    try:
        path = "/sys/class/net/%s/device/driver" % interface
        path = os.readlink(path)
    except FileNotFoundError:
        print("Interface '%s' not found" % interface)
        sys.exit(4)
    except:
        print("readlink('%s') failed: %s" % (path, sys.exc_info()[0]))
        sys.exit(4)
    interface_module = os.path.basename(path)
    if reload_modules:
        system("rmmod %s" % interface_module, True)
        reload_netmap()
        insmod(interface_module)
        # Wait interfaces after inserting module
        time.sleep(1)
    system("ethtool -K %s rx off tx off" % interface)
    system("ethtool -K %s gso off" % interface)
    system("ethtool -K %s ntuple on" % interface)
    system("ethtool --show-ntuple %s rx-flow-hash tcp4" % interface)
    system("ethtool -N %s rx-flow-hash tcp4 sdfn" % interface)
    system("ethtool -N %s rx-flow-hash udp4 sdfn" % interface)
    system("ethtool -G %s rx 2048 tx 2048" % interface)
    system("ip l s dev %s up" % interface)

if listen != None:
    if connect != None:
        die("--connect: Can't be specified with --listen option")
    if interface == None:
        die("-i: Should be specified with --listen option")

    g_tester_interface = interface
    tester_mac = get_interface_mac(g_tester_interface)
    g_tester_cpus = g_cpu_list
    set_txrx_queue_count(interface, g_tester_cpus)
    tester_loop()
    sys.exit(0)

def parse_sample(data, reports, test_id, bad):
    s = data.decode('utf-8').strip()
    rows = s.split('\n')
    if len(rows) != reports:
        print(("Invalid number of reports (%d) in output, should be %d"
            % (len(rows), reports)))
        print("Output:")
        print(s)
        return None
    sample = Sample()
    sample.records = [[] for i in range(6)]
    for row in rows:
        cols = row.split()
        if len(cols) != 9:
            print("Invalid number of columns (%d) in report, should be 9" % len(cols))
            print("Report: '%s'" % row)
            return None
        sample.records[CPS].append(int(cols[0]))
        sample.records[IPPS].append(int(cols[1]))
        sample.records[IBPS].append(int(cols[2]))
        sample.records[OPPS].append(int(cols[3]))
        sample.records[OBPS].append(int(cols[4]))
        sample.records[CONCURRENCY].append(int(cols[8]))
    sample.test_id = test_id
    if bad:
        sample.status = 0
    else:
        sample.status = 1
        for i in range(len(sample.records)):
            record = sample.records[i][g_skip_reports:]
            sample.outliers = find_outliers(record, None)
            if sample.outliers != None:
                sample.status = 0
                break
    sample.id = app.add_sample(sample)
    return sample

def set_stop_time():
    global g_stop_at_milliseconds
    g_stop_at_milliseconds = milliseconds()

def cool_down_cpu():
    ms = milliseconds() - g_stop_at_milliseconds
    if ms < g_cooling_time * 1000:
        t = int(math.ceil((g_cooling_time * 1000 - ms) / 1000))
        time.sleep(t)

def test_nginx(app, test_id, concurrency, cpus, native):
    nginx = start_nginx(concurrency, cpus, native)
    # Wait netmap interface goes up
    time.sleep(2)
    cool_down_cpu()
    con_gen = start_generator(concurrency)

    # FIXME: Wait ARP negotiaition
    time.sleep(g_skip_reports)
    cpu_usage = measure_cpu_usage(g_report_count - 2, cpus)

    data = wait_generator(con_gen)

    low = False
    for j in cpu_usage:
        if j < 98:
            low = True
            break

    sample = parse_sample(data, g_report_count, test_id, low)
    if sample == None:
        die("Invalid generator output. Please, check tester")

    if nginx.poll() != None:
        print("NGINX already done !!!"  % nginx.returncode)
    stop_nginx()
    proc_wait(nginx, "nginx")
    set_stop_time()

    print("nginx%s: test_id=%d, sample_id=%d, c=%d, %sCPU usage"
        % ("(native)" if native else "", test_id, sample.id, concurrency,
        "low " if low else ""),
        cpu_usage)

    return 0

if interface == None:
    if len(cpu_list) < 2:
        print("--cpu-list: Specify more then 1 cpu for testing on veth")
        sys.exit(1)

    vethc = "gt_veth_c"
    veths = "gt_veth_s"
    cmac = "72:9c:29:36:5e:02"
    smac = "72:9c:29:36:5e:01"

    insmod("veth")
    system("ip l a dev %s type veth peer name %s" % (veths, vethc))
    system("ethtool -K %s rx off tx off" % veths)
    system("ethtool -K %s rx off tx off" % vethc)
    system("ip l s dev %s address %s" % (veths, smac))
    system("ip l s dev %s address %s" % (vethc, cmac))

    g_tester_cpus = g_cpu_list[1:2]
    g_runner_cpus = g_cpu_list[0:1]
    g_tester_interface = vethc
    g_runner_interface = veths
    tester_mac = cmac
    device_mac = smac

else:
    if connect == None:
        die("--connect|-C: Not specified")
    g_runner_cpus = g_cpu_list
    g_runner_interface = interface
    device_mac = get_interface_mac(g_runner_interface) 

device_ip = get_device_ip(subnet) 
system("ip a flush dev %s" % g_runner_interface)
system("ip a a dev %s %s/32" % (g_runner_interface, device_ip))
system("ip r flush dev %s" % g_runner_interface)
if True:
    system("ip r a dev %s %s.1.1/32 initcwnd 1" % (g_runner_interface, subnet))
    system("ip r a dev %s %s.0.0/15 via %s.1.1 initcwnd 1"
        % (g_runner_interface, subnet, subnet))
else:
    system("ip r a dev %s %s.0.0/16 initcwnd 1"
        % (g_runner_interface, subnet))


# TODO:
# echo 0 > /proc/sys/net/ipv4/tcp_syncookies

g_nginx_ver = get_nginx_ver(app)

last_used_cpus = None
# Assume that last test ended at least 10 seconds ago
g_stop_at_milliseconds = milliseconds() - 10000

app_id = app.app_get_id("nginx", g_nginx_ver)

use_native = False
for i in range (g_cpu_count_min, len(g_runner_cpus) + 1):
    cpus = g_runner_cpus[:i]
    if cpus != last_used_cpus:
        # Wait interface become available
        time.sleep(2)
        set_txrx_queue_count(g_runner_interface, cpus)
    for concurrency in g_concurrency:
        if g_dry_run:
            test_id = -1
            sample_count = 0
        else:
            desc = "native" if use_native else None
            test_id, sample_count = app.add_test(desc, app_id, concurrency,
                len(cpus), g_report_count)
        if sample_count >= g_sample_count:
            continue
        sample_count = g_sample_count - sample_count
        for j in range (0, sample_count):
            test_nginx(app, test_id, concurrency, cpus, use_native)
            last_used_cpus = cpus