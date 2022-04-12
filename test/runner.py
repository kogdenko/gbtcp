#!/usr/bin/python

# /test/runner.py -v  -N ../../open_source/netmap/ -i eth2

import os
import sys
import time
import atexit
import getopt
import socket
import subprocess
import importlib
import multiprocessing
import psutil

verbose = 0
netmap_dir = None
listen = None
connect = None
connect_sock = None
interface = None
interface_module = None
tester_interface = None
device_interface = None
cpu_list = None
tester_cpu_list = None
device_cpu_list = None # Device under test
tester_mac = None
device_mac = None
tester_ip = None
device_ip = None
scaling_governor = dict()
clean_on_exit = False
reports = 5

def usage():
    print("Usage: runner [options]")
    print("")
    print("Options:")
    print("\t-h, --help: Print this help")
    print("\t-v, --verbose: Be verbose")
    print("\t-i {interface}: For performance testing")
    print("\t--cpu-list {a-b,c,d}: Bind applications on this cpus")
#    print("\t--clean-on-exit: Restore environment after runner finish w")

def bytes_to_string(b):
    return b.decode('UTF-8').strip()

def bytes_list_to_string_list(l):
    r = []
    for e in l:
        r.append(bytes_to_string(e))
    return r;

def parse_cpu_list(s):
    res = set()
    for item in s.split(','):
        if '-' in item:
            x, y = item.split('-')
            if not x.isdigit() or not y.isdigit():
                return None
            x = int(x)
            y = int(y)
            if x > y:
                return None
            for i in range(x, y + 1):
                res.add(i)
        else:
            if not item.isdigit():
                return None;
            res.add(int(item))
    return list(res)

def exec_cmd(cmd, exit_on_err=False):
    proc = subprocess.Popen(cmd.split(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = proc.communicate()
    except:
        proc.kill();
        print("$", cmd)
        print(sys.exc_info()[0])
        sys.exit(6)

    out = bytes_to_string(out)
    err = bytes_to_string(err)
    ret = proc.returncode
     
    if verbose > 0:
        print("$", cmd)
        if len(out):
            print("$", out)
        if len(err):
            print("$", err)
        print("$ echo ?$")
        print("$", ret)
    return ret, out, err

def find_file(path, filename):
    for root, dirs, files in os.walk(path):
        for name in files:
            if name == filename:
                return os.path.join(root, name)
    return None

def find_module(module_name):
    module_path = find_file(netmap_dir, "%s.ko" % module_name)
    if module_path == None:
        print("Module '%s' not found in '%s'" % (module_name, netmap_dir))
        sys.exit(5)
    return module_path

def insmod(module_name):
    module_path = find_module(module_name)
    exec_cmd("insmod %s" % module_path, True)

def run():
    path = os.path.dirname(os.path.realpath(__file__))
    for filename in os.listdir(path):
        if (os.path.isfile(os.path.join(path, filename)) and
            filename.startswith("gtt_") and
            filename.endswith(".py")):
            module_name = os.path.splitext(filename)[0]
            module = importlib.import_module(module_name)
            module.run()

def start_process(cmd, env=None, shell=False):
    if verbose > 0:
        print("$", cmd, "&")
    proc = subprocess.Popen(cmd.split(), env=env, shell=shell,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc

def check_process_running(proc):
    proc.poll()

def start_nginx(cpu_list):
    worker_cpu_affinity = ""

    assert(device_ip != None)
    assert(len(cpu_list) > 0)

    templ = list()
    for i in range(0, cpu_count):
        templ.append('0')
    for i in cpu_list:
        templ[cpu_count - 1 - i] = '1'
        worker_cpu_affinity += " " + "".join(templ)
        templ[i] = '0'
   
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
        "    worker_connections 4000;\n"
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
        (len(cpu_list), worker_cpu_affinity, device_ip))

    gbtcp_conf = ("route.if.add=%s" % device_interface)

    assert(netmap_dir != None)

    test_path = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
    libgbtcp_path = os.path.normpath(test_path + "/../bin/libgbtcp.so")

    nginx_conf_path = test_path + "/nginx.conf"
    gbtcp_conf_path = test_path + "/gbtcp.conf"

    f = open(nginx_conf_path, 'w')
    f.write(nginx_conf)
    f.close()

    f = open(gbtcp_conf_path, 'w')
    f.write(gbtcp_conf)
    f.close()

    env = os.environ.copy()
    env["LD_PRELOAD"] = libgbtcp_path
    env["GBTCP_CONF"] = gbtcp_conf_path

    print("--", libgbtcp_path, gbtcp_conf_path)

    return start_process("nginx -c %s" % nginx_conf_path, env=env)

def stop_nginx():
    exec_cmd("nginx -s quit")

def run_con_gen(args):
    argv = args.split()
    cmd = ("con-gen --toy -i %s -S %s --reports %d -c 1000 -N -p 80 -a %d -s 172.16.7.2 -d 172.16.7.1" %
        (tester_interface, tester_mac, reports, tester_cpu_list[0]))
    return start_process(cmd)



def start_con_gen():
    return run_con_gen("")

def print_list(prefix, l):
    for e in l:
        print(prefix, e)

def wait_con_gen_client(con_gen):
    con_gen.wait();

    err = bytes_list_to_string_list(con_gen.stderr.readlines())
    out = bytes_list_to_string_list(con_gen.stdout.readlines())

    def return_err():
        print_list("", err)
        print_list("", out)
        return 8        

    def return_bad_out():
        print("con-gen: Bad output")
        return return_err()

    if con_gen.returncode != 0:
        print("con-gen: Failed with code %d" % con_gen.returncode)
        return return_err()
    if len(out) < reports + 1:
        return return_bad_out()

    res = []    
    for i in range(1, reports):
        x = out[i].split()
        if len(x) != 6:
            return return_bad_out()
        res.append(x[3])

    res_sum = 0
    for i in res:
        res_sum += int(i)
    return (0, res_sum/len(res))


def tester_loop():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((listen, 9999))
    s.listen()
    while True:
        try:
            conn, addr = s.accept()
            data = conn.recv(1024)
            print(">>>", data)
        except socket.error as exc:
            print("Connection failed: %s" % exc)

try:
    opts, args = getopt.getopt(sys.argv[1:], "hvN:L:C:i:t:", [
        "help",
        "verbose",
        "no-veth",
        "netmap=",
        "listen=",
        "connect=",
        "cpu-list=",
        "clean-on-exit",
        "test="
        ])
except getopt.GetoptError as err:
    print(err)
    usage()
    sys.exit(2)
for o, a in opts:
    if o in ("-h", "--help"):
        usage()
        sys.exit()
    elif o in ("-v", "--verbose"):
        verbose += 1
    elif o in ("-i"):
        interface = a
    elif o in ("--cpu-list"):
        cpu_list = parse_cpu_list(a)
        if cpu_list == None:
            print("--cpu-list: Invalid argument: '%s'" % a)
            sys.exit(3)
    elif o in ("--clean-on-exit"):
        clean_on_exit = True
    elif o in ("-N", "--netmap"):
        netmap_dir = os.path.abspath(a)
    elif o in ("-L", "--listen"):
        listen = a
    elif o in ("-C", "--connect"):
        connect = a

cpu_count = multiprocessing.cpu_count()
if cpu_list == None:
    cpu_list = list()
    for i in range(0, cpu_count):
        cpu_list.append(i)
else:
    for i in cpu_list:
        if i >= cpu_count:
            print("--cpu-list: CPU %d exceeds number of CPUs %d" % (i, cpu_count))
            sys.exit(3)

def exit_handler():
    print("exit handle")
    if interface_module != None:
        exec_cmd("rmmod %s" % interface_module)
        exec_cmd("modprobe %s" % interface_module)
    for (k, v) in scaling_governor.items():
        path = "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor" % k
        f = open(path, 'w')
        f.write(v)
        f.close()

if clean_on_exit:
    atexit.register(exit_handler)

for i in cpu_list:
    path = "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor" % i
    f = open(path, 'r')
    scaling_governor[i] = f.read()
    f.close()
    f = open(path, 'w')
    f.write("performance")
    f.close()

if netmap_dir != None:
    exec_cmd("rmmod veth")
    exec_cmd("rmmod netmap")
    insmod("netmap")

    if interface != None:
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
        exec_cmd("rmmod %s" % interface_module)
        insmod(interface_module)

if listen != None:
    if interface == None:
        print("--interface|-i: Not specified")
        sys.exit(1)
    tester_cpu_list = cpu_list
    tester_loop()
    sys.exit(0)

def test_nginx():
    nginx = start_nginx(device_cpu_list)
    con_gen = start_con_gen()

    time.sleep(1)
    percent = psutil.cpu_percent(reports - 2, True)

    ret, pps = wait_con_gen_client(con_gen)
    stop_nginx();
    if ret == 0:
        print("pps=%d" % pps)
    for i in device_cpu_list:
        print("cpu usage: ", percent[i]);

if interface == None:
    if len(cpu_list) < 2:
        print("--cpu-list: Specify more then 1 cpu or run in --no-veth mode")
        sys.exit(1)
    insmod("veth")
    vethc = "gt_veth_c"
    cmac = "72:9c:29:36:5e:02"
    cli_ip = "172.16.7.2"
    veths = "gt_veth_s"
    smac = "72:9c:29:36:5e:01"
    srv_ip = "172.16.7.1"

    exec_cmd("ip l a dev %s type veth peer name %s" % (veths, vethc), True)
    exec_cmd("ethtool -K %s rx off tx off" % veths, True)
    exec_cmd("ethtool -K %s rx off tx off" % vethc, True)
    exec_cmd("ip l s dev %s address %s" % (veths, smac), True)
    exec_cmd("ip l s dev %s address %s" % (vethc, cmac), True)
    exec_cmd("ip l s dev %s up" % veths, True)
    exec_cmd("ip a a dev %s %s/32" % (veths, srv_ip), True)
    exec_cmd("ip r a dev %s 172.16.7.0/24 initcwnd 1" % veths, True)

    tester_cpu_list = cpu_list[1:2]
    device_cpu_list = cpu_list[0:1]
    tester_interface = vethc
    device_interface = veths
    tester_mac = cmac
    device_mac = smac
    tester_ip = cli_ip
    device_ip = srv_ip

else:
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    sys.exit(1)
    if connect == None:
        print("--connect|-C: Not specified")
        sys.exit(7)
    connect_sock = socket.create_connection((connect, 9999))
    device_cpu_list = cpu_list
    device_interface = interface
    #device_mac = 

test_nginx()
