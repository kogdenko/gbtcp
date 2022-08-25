#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import os
import re
import sys
import time
import psutil
import platform
import argparse
import subprocess
import traceback
import multiprocessing
import syslog
import sqlite3
import ipaddress
import numpy
from enum import Enum


SUN_PATH = "/var/run/gbtcp-tester.sock"

TEST_SAMPLE_MIN = 1
TEST_SAMPLE_MAX = 20
TEST_SAMPLE_DEFAULT = 5


class Mode(Enum):
    CLIENT = "client"
    SERVER = "server"


class Transport(Enum):
    NATIVE = "native"
    NETMAP = "netmap"
    XDP = "xdp"


class Driver(Enum):
    VETH = "veth"
    IXGBE = "ixgbe"


class Connectivity(Enum):
    LOCAL = "local"
    DIRECT = "direct"


TEST_DURATION_MIN = 10
TEST_DURATION_MAX = 10*60
TEST_DURATION_DEFAULT = 60

TEST_DELAY_MIN = 0
TEST_DELAY_MAX = TEST_DURATION_MIN - 1
TEST_DELAY_DEFAULT = 2

CONCURRENCY_DEFAULT=1000
CONCURRENCY_MAX=20000


def print_log(s, to_stdout=False):
    syslog.syslog(s)
    if to_stdout:
        print(s)


def dbg(*args):
    traceback.print_stack(limit=2)
    print(args)


class UniqueAppendAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        unique_values = list(set(values))
        unique_values.sort()
        setattr(namespace, self.dest, unique_values)


class mac_address:
    @staticmethod
    def create(s):
        error = ValueError("invalid literal for mac_address(): '%s'" % s)

        six = s.split(':')
        if len(six) != 6:
            raise error;

        for i, x in enumerate(six):
            if len(x) != 2:
                raise error;
            try:
                six[i] = int(x, 16)
            except ValueError:
                raise error;

        return mac_address(*six)
       

    @staticmethod
    def argparse(s):
        try:
            return mac_address.create(s)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("invalid MAC value '%s'" % s)


    def __init__(self, a, b, c, d, e, f):
        self.__data = (a, b, c, d, e, f)


    def __str__ (self):
        return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
            self.__data[0], self.__data[1], self.__data[2],
            self.__data[3], self.__data[4], self.__data[5])

   
    def __repr__(self):
        return __str__(self)
    

def argparse_ip_address(s):
    try:
        return ipaddress.ip_address(s)
    except Exception as exc:
        raise argparse.ArgumentTypeError(str(exc))


def argparse_ip_network(s):
    try:
        return ipaddress.ip_network(s, strict=False)
    except Exception as exc:
        raise argparse.ArgumentTypeError(str(exc))


def argparse_dir(s):
    error = argparse.ArgumentTypeError("invalid directory '%s'" % s)

    try:
        path = os.path.abspath(s)
        if os.path.isdir(path):
            return path
        else:
            raise error;
    except:
        raise error;


def argparse_interface(s):
    error = argparse.ArgumentTypeError("invalid interface '%s'" % s)

    try:
        driver = get_interface_driver(s)
        interface = Interface.create(s, driver)
    except RuntimeError as exc:
        traceback.print_exception(exc)
        raise error
    return interface


def argparse_add_reload_netmap(ap):
    ap.add_argument("--reload-netmap", metavar='path', type=argparse_dir,
            help="Reload required netmap modules from specified directory")


def argparse_add_cpu(ap):
    ap.add_argument("--cpu", metavar="cpu-id", type=int, nargs='+',
            action=UniqueAppendAction,
            required=True,
            choices=range(0, multiprocessing.cpu_count() - 1),
            help="")


def argparse_add_duration(ap, default=None):
    if default:
        required = False
    else:
        required = True
    ap.add_argument("--duration", metavar="seconds", type=int,
            choices=range(TEST_DURATION_MIN, TEST_DURATION_MAX),
            required=required, default=default,
            help="Test duration in seconds")


def upper_pow2_32(x):
    x = int(x)
    x -= 1
    x |= x >>  1
    x |= x >>  2
    x |= x >>  4
    x |= x >>  8
    x |= x >> 16
    x += 1
    return x;


def bytes_to_str(b):
    return b.decode('utf-8').strip()


def make_cpu_mask(cpus):
    cpu_mask = ""
    for i in range(0, multiprocessing.cpu_count()):
        if i in cpus:
            cpu_mask += "1"
        else:
            cpu_mask += "0"
    return cpu_mask


def system(cmd, fault_tollerance=False, env=None):
    proc = subprocess.Popen(cmd.split(), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = proc.communicate(timeout = 5)
    except Exception as exc:
        proc.kill();
        print_log("Command '%s' failed: '%s'" % (cmd, sys.exc_info()[0]))
        raise exc

    out = bytes_to_str(out)
    err = bytes_to_str(err)
    rc = proc.returncode
     
    print_log("$ %s # $? = %d\n%s\n%s" % (cmd, rc, out, err))

    if rc != 0 and not fault_tollerance:
        raise RuntimeError("Command '%s' failed with code '%d'" % (cmd, rc))
        
    return rc, out, err


def rmmod(module):
    rc, _, err = system("rmmod %s" % module, True)
    if rc == 0:
        return True
    lines = err.splitlines()
    if len(lines) == 1:
        msg = lines[0].strip()
        p = "rmmod: ERROR: Module %s is not currently loaded" % module
        m = re.search(p, msg)
        if m != None:
            return False
        p = "rmmod: ERROR: Module %s is in use by: " % module
        m = re.search(p, msg)
        if m != None and rmmod(msg[len(p):]):
            rmmod(module)
            return True
    raise RuntimeError("Cannot remove module '%s" % module)


def insmod(netmap_path, module_name):
    if module_name == "ixgbe":
        module_dir = "ixgbe"
    else:
        module_dir = ""
    path = netmap_path + "/" + module_dir + "/" + module_name + ".ko"
    system("insmod %s" % path)


def reload_netmap(netmap_path, interface):
    rmmod(interface.driver.value)
    rmmod("netmap")
    insmod(netmap_path, "netmap")
    insmod(netmap_path, interface.driver.value)
    # Wait interfaces after inserting module
    time.sleep(1)
    interface.up()


def round_std(std):
    assert(type(std) == int)
    assert(std >= 0)
    s = str(std)
    l = len(s)
    if l < 2:
        return std, 0
    if s[0] == '1' or s[0] == '2':
        z = 2
    else:
        z = 1
    r = s[0:z] + '0' * (l - z)
    return (int(r), l - z)


def round_val(val, std):
    assert(type(val) == int)
    assert(val >= 0)
    std_rounded, n = round_std(std)
    val_rounded = round(val, -n)
    return val_rounded, std_rounded


SERVER_IP_C = 255
SERVER_IP_D = 1

def get_runner_ip(subnet):
    return "%d.%d.%d.%d" % (subnet[0], subnet[1], SERVER_IP_C, SERVER_IP_D)


def cpu_percent(t, cpus):
    # Skip last second
    assert(t > 2)
    percent = psutil.cpu_percent(t - 1, True)
    cpu_usage = []
    for cpu in cpus:
        cpu_usage.append(percent[cpu])
    return cpu_usage


def set_irq_affinity(interface, cpus):
    with open("/proc/interrupts", 'r') as f:
        lines = f.readlines()

    irqs = []

    p = re.compile("^%s-TxRx-[0-9]*$" % interface)
    for i in range(1, len(lines)):       
        columns = lines[i].split()
        for column in columns:
            m = re.match(p, column.strip())
            if m != None:
                irq = columns[0].strip(" :")
                if not irq.isdigit():
                    raise RuntimeError("invalid irq: /proc/interrupts:%d" % i + 1)
                irqs.append(int(irq))

    if len(cpus) != len(irqs):
        raise RuntimeError("invalid number of irqs: %d" % len(irqs))

    for i in range(0, len(irqs)):
        with open("/proc/irq/%d/smp_affinity" % irqs[i], 'w') as f:
            f.write("%x" % (1 << cpus[i]))


def set_cpu_scaling_governor(cpu):
    path = "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor" % cpu
    with open(path, 'w') as f:
        f.write("performance")


def get_interface_driver(name):
    cmd = "ethtool -i %s" % name
    rc, out, _ = system(cmd)
    for line in out.splitlines():
        if line.startswith("driver: "):
            return line[8:].strip()
    raise RuntimeError("invalid ethtool driver: '%s'" % name )


def recv_lines(sock):
    message = None
    while True:
        s = sock.recv(1024).decode('utf-8')
        if not s:
            if not message:
                return None
            break
        if not message:
            message = s
        else:
            message += s
        if '\n\n' in message:
            break

    lines = message.splitlines()
    if '' in lines:
        lines.remove('')
    return lines


def send_string(sock, s):
    while s[-1] == '\n':
        s = s[:-1]
    sock.send((s + "\n\n").encode('utf-8'))


def milliseconds():
    return int(time.monotonic_ns() / 1000000)


def get_cpu_model():
    if platform.system() == "Windows":
        return platform.processor()
    elif platform.system() == "Darwin":
        cmd ="sysctl -n machdep.cpu.brand_string"
        return system(command)[1].strip()
    elif platform.system() == "Linux":
        f = open("/proc/cpuinfo");
        lines = f.readlines()
        f.close()
        for line in lines:
            if "model name" in line:
                return re.sub( ".*model name.*:", "", line, 1).strip()
    raise RuntimeError("Cannot determine CPU model")


def git_rev_parse(rev):
    cmd = "git rev-parse %s" % rev
    commit = system(cmd)[1].strip()
    if len(commit) != 40:
        raise RuntimeError("%s: Cannot extract git commit " % cmd)
    return commit


def find_outliers(sample, std):
    if std == None:
        std = [numpy.std(sample)] * len(sample)
    mean = numpy.mean(sample)
    # 3 sigma method
    outliers = []
    for i in range(0, len(sample)):
        if abs(mean - sample[i]) > 3 * std[i]:
            outliers.append(i)
    return outliers


def start_process(cmd, env=None):
    proc = subprocess.Popen(cmd.split(), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print_log("$ %s &\n[%d]" % (cmd, proc.pid))
    return proc


def wait_process(proc):
    lines = []
    t0 = milliseconds()
    try:
        proc.wait(timeout=5)
    except Exception as e:
        t1 = milliseconds()
        dt = t1 - t0
        assert(dt * 1000 > 4.5)
        print_log("$ [%d] Timeouted" % proc.pid)
        proc.terminate()
        proc.wait(timeout=5)

    for pipe in [proc.stdout, proc.stderr]:
        while True:
            line = pipe.readline()
            if not line:
                break
            lines.append(line.decode('utf-8').strip())

    print_log("$ [%d] Done + %d\n%s" % (proc.pid, proc.returncode, '\n'.join(lines)))
    return proc.returncode, lines


class Interface:
    @staticmethod
    def create(name, driver_value):
        driver = Driver(driver_value)
        for instance in Interface.__subclasses__():
            if instance.driver == driver:
                interface = instance(name)
                return interface
        assert(0)


    def __init__(self, name):
        self.name = name
        with open("/sys/class/net/%s/address" % name) as f:
            self.mac = f.read().strip()
        self.up()


    def up(self):
        system("ip l s dev %s up" % self.name)


class ixgbe(Interface):
    driver = Driver.IXGBE

    def get_channels(self):
        cmd = "ethtool -l %s" % self.name
        out = system(cmd)[1]
        current_hardware_settings = False
        Combined = "Combined:"
        for line in out.splitlines():
            if line.startswith("Current hardware settings:"):
                current_hardware_settings = True
            if line.startswith(Combined) and current_hardware_settings:
                return int(line[len(Combined):])
        raise RuntimeError("'%s': No current hardware setting for 'Combined' ring" % cmd)


    def __init__(self, name):
        Interface.__init__(self, name)
        system("ethtool -K %s rx off tx off" % name)
        system("ethtool -K %s gso off" % name)
        system("ethtool -K %s ntuple on" % name)
        system("ethtool -N %s rx-flow-hash tcp4 sdfn" % name)
        system("ethtool -N %s rx-flow-hash udp4 sdfn" % name)
        system("ethtool -G %s rx 2048 tx 2048" % name)


    def set_channels(self, cpus):
        system("ethtool -L %s combined %d" % (self.name, len(cpus)))
        set_irq_affinity(self.name, cpus)


class veth(Interface):
    driver = Driver.VETH

    def __init__(self, name):
        Interface.__init__(self, name)
        system("ethtool -K %s rx off tx off" % name)
        system("ethtool -K %s gso off" % name)
        system("ethtool -N %s rx-flow-hash tcp4 sdfn" % name)
        system("ethtool -N %s rx-flow-hash udp4 sdfn" % name)

    def set_channels(self, cpus):
        if len(cpus) != 1:
            raise RuntimeError("veth interface doesn't support multiqueue mode")


class Project:
    def system(self, cmd, fault_tollerance=False):
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = self.path + "/bin"
        return system(cmd, fault_tollerance, env)


    def __init__(self):
        self.path = os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + "/../")
        self.config_path = self.path + "/test/gbtcp.conf"
        self.interface = None

        self.commit = None
        self.transports = [Transport.NATIVE]

        cmd = self.path + "/bin/gbtcp-aio-helloworld -v"
        _, out, _ = self.system(cmd)
        for line in out.splitlines():
            if line.startswith("gbtcp: "):
                self.commit = git_rev_parse(line[7:])
            elif line.startswith("config: "):
                if re.search("HAVE_XDP", line) != None:
                    self.transports.append(Transport.XDP)    
                if re.search("HAVE_NETMAP", line) != None:
                    self.transports.append(Transport.NETMAP)

        if self.commit == None:
            raise RuntimeError("invalid command output: '%s'" % cmd)


    def set_interface(self, interface):
        self.interface = interface
        self.write_config()


    def write_config(self, transport=None):
        assert(self.interface)
        config = ""
        if transport:
            config += "dev.transport=%s\n" % transport
        config += "route.if.add=%s\n" % self.interface.name
        config += "arp.add=10.20.1.1,00:1b:21:95:69:65\n" # FIXME

        with open(self.config_path, 'w') as f:
            f.write(config)


    def start_process(self, cmd, transport=Transport.NATIVE):
        e = os.environ.copy()
        e["LD_LIBRARY_PATH"] = self.path + "/bin"
        if transport != Transport.NATIVE:
            self.write_config(transport)
            e["LD_PRELOAD"] = os.path.normpath(self.path + "/bin/libgbtcp.so")
            e["GBTCP_CONF"] = self.config_path
        return start_process(cmd, e)
