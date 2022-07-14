#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import getopt
import socket
from common import *

g_listen = None
g_reload_netmap = None
g_interface_name = None
g_cpus = None

class Tester:
    pass

g_project = Project()
g_tester = Tester()

def run_con_gen(dst_mac, subnet, reports, concurrency):
    dst_ip = get_runner_ip(subnet)
    cmd = "con-gen "
#    cmd += "--toy "
    cmd += "--print-banner 0 --print-statistics 0 --report-bytes 1 "
    cmd += ("-S %s -D %s --reports %d -N -p 80 -d %s" %
        (g_tester.interface.mac, dst_mac, reports, dst_ip))

    n = len(g_cpus)
    for i in range(n):
        concurrency_per_cpu = concurrency / n
        if i == 0:
            concurrency_per_cpu += concurrency % n
        else:
            cmd += " --"
        cmd += " -i %s-%d" % (g_tester.interface.name, i)
        cmd += " -c %d" % concurrency_per_cpu
        cmd += " -a %d" % g_cpus[i]
        cmd += " -s %s.%d.1-%s.%d.255" % (subnet, i + 1, subnet, i + 1)
    return g_project.start_process(cmd, False)

def run_epoll(subnet, reports, concurrency):
    ifname = g_tester.interface.name

    system("ip a flush dev %s" % ifname)
    system("ip r flush dev %s" % ifname)
    for i in range(1, 255):
        system("ip a a dev %s %s.1.%d " % (ifname, subnet, i))
    system("ip r a dev %s %s.0.0/16" % (ifname, subnet))

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

def run_tester(args):
    subnet = None
    reports = None
    dst_mac = None
    concurrency = None
    tester = None

    try:
        opts, args = getopt.getopt(args.split(), "D:", [
            "tester=",
            "subnet=",
            "reports=",
            "concurrency=",
            ])
    except getopt.GetoptError as err:
        print_log(err)
        return None, 0

    for o, a in opts:
        if o in ("-D"):
            dst_mac = a
        elif o in ("--tester"):
            tester = a
        elif o in ("--subnet"):
            subnet = a
        elif o in ("--reports"):
            reports = int(a)
        elif o in ("--concurrency"):
            concurrency = int(a)
   
    if (dst_mac == None or subnet == None or
        reports == None or concurrency == None):
        die("Missed tester required options")
    
    if tester == "con-gen":
        proc = run_con_gen(dst_mac, subnet, reports, concurrency)
    elif tester == "epoll":
        proc = run_epoll(subnet, reports, concurrency)
    else:
        die("Unsupported")

    return (proc, reports)

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

            proc, reports = run_tester(data.strip())
            if proc == None:
                print_log("Invalid request, closing connection")
                conn.close()
                continue

            # FIXME: Wait APR negotiaition
            cpu_usage = measure_cpu_usage(reports, 2, g_cpus)

            rc, lines = g_project.wait_process(proc)

            data = bytearray()
            for line in lines:
                data += bytearray((line + "\n").encode('utf-8'))

            print_log("%s: CPU=%s ... %s" %
                (proc.args[0], list_to_str(cpu_usage), "Ok" if rc == 0 else "Failed"), True)

            conn.send(data)
            conn.close()
        except socket.error as exc:
            print_log("Connection failed: %s" % exc)

try:
    opts, args = getopt.getopt(sys.argv[1:], "hi:", [
        "help",
        "reload-netmap=",
        "listen=",
        "cpu=",
        ])
except getopt.GetoptError as err:
    print(err)
    usage()
    sys.exit(1)
for o, a in opts:
    if o in ("-h", "--help"):
        usage()
        sys.exit(0)
    elif o in ("-i"):
        g_interface_name = a
    elif o in ("--cpu"):
        g_cpus = str_to_int_list(a)
        if g_cpus == None:
            die("--cpu: Invalid argument: '%s'" % a)
    elif o in ("--listen"):
        g_listen = a
    elif o in ("--reload-netmap"):
        g_reload_netmap = os.path.abspath(a)

if g_listen == None:
    die("'--listen' must be specified ")

if g_interface_name == None:
    die("Interface not specified (see '-i')")

if g_cpus == None:
    die("No cpu specified (see '--cpu'")

init_cpus(g_cpus)

driver = get_interface_driver(g_interface_name)

if g_reload_netmap != None:
    reload_netmap(g_reload_netmap, driver)

g_tester.interface = create_interface(driver, g_interface_name);
g_tester.interface.set_channels(g_cpus)
tester_loop()
