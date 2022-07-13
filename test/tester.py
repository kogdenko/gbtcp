#!/usr/bin/python
import getopt
import socket
from common import *

g_listen = None
g_reload_netmap = None
g_interface_name = None
g_cpus = None

env = Environment()

def run_tester(args):
    subnet = None
    reports = None
    dst_mac = None
    concurrency = None

    try:
        opts, args = getopt.getopt(args.split(), "D:", [
            "subnet=",
            "reports=",
            "concurrency=",
            ])
    except getopt.GetoptError as err:
        print_log(err)
        die("Invalid tester options")

    for o, a in opts:
        if o in ("-D"):
            dst_mac = a
        elif o in ("--subnet"):
            subnet = a
        elif o in ("--reports"):
            reports = int(a)
        elif o in ("--concurrency"):
            concurrency = int(a)
   
    if (dst_mac == None or subnet == None or
        reports == None or concurrency == None):
        die("Missed tester required options")
    
    dst_ip = get_runner_ip(subnet)
    cmd = "con-gen "
#    cmd += "--toy "
    cmd += "--print-banner 0 --print-statistics 0 --report-bytes 1 "
    cmd += ("-S %s -D %s --reports %d -N -p 80 -d %s" %
        (env.interface.mac, dst_mac, reports, dst_ip))

    n = len(g_cpus)
    for i in range(n):
        concurrency_per_cpu = concurrency / n
        if i == 0:
            concurrency_per_cpu += concurrency % n
        else:
            cmd += " --"
        cmd += " -i %s-%d" % (env.interface.name, i)
        cmd += " -c %d" % concurrency_per_cpu
        cmd += " -a %d" % g_cpus[i]
        cmd += " -s %s.%d.1-%s.%d.255" % (subnet, i + 1, subnet, i + 1)

    return (env.start_process(cmd, False), reports)

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

            # FIXME: Wait APR negotiaition
            cpu_usage = measure_cpu_usage(reports, 2, g_cpus)

            rc, lines = env.wait_process(proc)

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

env.interface = create_interface(driver, g_interface_name);
env.interface.set_channels(g_cpus)
tester_loop()
