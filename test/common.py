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
import mysql.connector
import numpy


SUN_PATH = "/var/run/gbtcp-tester.sock"

TEST_SAMPLE_MIN = 1
TEST_SAMPLE_MAX = 20
TEST_SAMPLE_DEFAULT = 5


TESTER_LOCAL_CON_GEN = 1
TESTER_REMOTE_CON_GEN = 2

tester_dict = {
    TESTER_LOCAL_CON_GEN: "local:con-gen",
    TESTER_REMOTE_CON_GEN: "con-gen",
}

TRANSPORT_NATIVE = 0
TRANSPORT_NETMAP = 1
TRANSPORT_XDP = 2

transport_dict = {
    TRANSPORT_NATIVE: "native",
    TRANSPORT_NETMAP: "netmap",
    TRANSPORT_XDP: "xdp",
}

DRIVER_VETH = 1
DRIVER_IXGBE = 2

driver_dict = {
    DRIVER_VETH: "veth",
    DRIVER_IXGBE: "ixgbe",
}

TEST_DURATION_MIN = 10
TEST_DURATION_MAX = 10*60
TEST_DURATION_DEFAULT = 60

TEST_DELAY_MIN = 0
TEST_DELAY_MAX = TEST_DURATION_MIN - 1
TEST_DELAY_DEFAULT = 2

CONCURRENCY_DEFAULT=1000
CONCURRENCY_MAX=20000

def print_log(s, to_stdout = False):
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


class MacAddress:
    @staticmethod
    def argparse(s):
        error = argparse.ArgumentTypeError("invalid MAC value '%s'" % s)

        six = s.split(':')
        if len(six) != 6:
            raise error;

        for i, x in enumerate(six):
            if len(x) != 2:
                raise error;
            try:
                six[i] = int(x, 16)
            except:
                raise error;

        return MacAddress(*six)


    def __init__(self, a, b, c, d, e, f):
        self.__data = (a, b, c, d, e, f)


    def __str__ (self):
        return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
            self.__data[0], self.__data[1], self.__data[2],
            self.__data[3], self.__data[4], self.__data[5])

   
    def __repr__(self):
        return __str__(self)
    

def argparse_ip(s):
    error = argparse.ArgumentTypeError("invalid IP value '%s'" % s)

    ip = s.split('.')
    if len(ip) != 4:
        raise error;

    for i, d in enumerate(ip):
        try:
            ip[i] = int(d)
            if ip[i] < 0 or ip[i] > 255:
                raise error;
        except:
            raise error;

    return tuple(ip)


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


def make_ip(t):
#    return "{a}.{b}.{c}.{d}".format(a=t[0], b=t[1], c=t[2], d=t[3])
    return "%d.%d.%d.%d" % (t[0], t[1], t[2], t[3])

def get_dict_id(d, name):
    for key, value in d.items():
        if value == name:
            return key
    return None


def system(cmd, fault_tollerance = False, env = None):
    proc = subprocess.Popen(cmd.split(), env = env,
        stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    try:
        out, err = proc.communicate(timeout = 5)
    except Exception as exc:
        proc.kill();
        print_log("Command '%s' failed, exception: '%s'" % (cmd, sys.exc_info()[0]))
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
    rmmod(interface.driver)
    rmmod("netmap")
    insmod(netmap_path, "netmap")
    insmod(netmap_path, interface.driver)
    # Wait interfaces after inserting module
    time.sleep(1)
    interface.up()


def get_sample_result(sample, i):
    assert(len(sample.results) == 7)
    assert(i <= BPS)
    if i == PPS:
        a = IPPS
        b = OPPS
    elif i == BPS:
        a = IBPS
        b = OBPS
    else:
        return sample.results[i]
    return sample.results[a] + sample.results[b]


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


def int_list_to_bytearray(il, sizeof):
    ba = bytearray()
    for i in il:
        ba += bytearray(i.to_bytes(sizeof, "big"))
    return ba


def bytearray_to_int_list(ba, sizeof):
    il = []
    for i in range(0, len(ba), sizeof):
        il.append(int.from_bytes(ba[i:i + sizeof], "big"))
    return il


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
    f = open("/proc/interrupts", 'r')
    lines = f.readlines()
    f.close()

    irqs = []

    p = re.compile("^%s-TxRx-[0-9]*$" % interface)
    for i in range(1, len(lines)):       
        columns = lines[i].split()
        for column in columns:
            m = re.match(p, column.strip())
            if m != None:
                irq = columns[0].strip(" :")
                if not irq.isdigit():
                    raise RuntimeError("/proc/interrupts:%d: Invalid irq id" % i + 1)
                irqs.append(int(irq))

    if len(cpus) != len(irqs):
        raise RuntimeError("Unexpected number of irqs (%d), shoud be %d" % (len(irqs), len(cpus)))

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
    raise RuntimeError("'%s': No 'driver'" % cmd)


def recv_line(sock):
    line = ""
    while True:
        s = sock.recv(1024).decode('utf-8')
        if not s:
            return None
        line += s
        if '\n' in s:
            return line.strip()


def milliseconds():
    return int(time.monotonic_ns() / 1000000)


def get_cpu_name():
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


def wait_process(proc):
    lines = []
    t0 = milliseconds()
    try:
        proc.wait(timeout = 5)
    except Exception as e:
        t1 = milliseconds()
        dt = t1 - t0
        assert(dt * 1000 > 4.5)
        print_log("$ [%d] Timeouted" % proc.pid)
        proc.terminate()
        return 256, lines    

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
    def create(name, driver):
        driver_id = get_dict_id(driver_dict, driver)
        if driver_id == None:
            raise NotImplementedError("Driver '%s' not supported" % driver)
        instance = globals().get(driver)
        assert(instance != None)
        interface = instance(name)
        interface.driver = driver
        interface.driver_id = driver_id
        return interface


    def __init__(self, name):
        self.name = name
        with open("/sys/class/net/%s/address" % name) as f:
            self.mac = f.read().strip()
        self.up()


    def up(self):
        system("ip l s dev %s up" % self.name)


class ixgbe(Interface):
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
    def system(self, cmd, fault_tollerance = False):
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = self.path + "/bin"
        return system(cmd, fault_tollerance, env)

    def __init__(self):
        self.path = os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + "/../")
        self.gbtcp_conf_path = self.path + "/test/gbtcp.conf"

        self.commit = None
        self.transports = [transport_dict[TRANSPORT_NATIVE]]

        cmd = self.path + "/bin/gbtcp-aio-helloworld -v"
        _, out, _ = self.system(cmd)
        for line in out.splitlines():
            if line.startswith("gbtcp: "):
                self.commit = git_rev_parse(line[7:])
            elif line.startswith("config: "):
                if re.search("HAVE_XDP", line) != None:
                    self.transports.append(transport_dict[TRANSPORT_XDP])    
                if re.search("HAVE_NETMAP", line) != None:
                    self.transports.append(transport_dict[TRANSPORT_NETMAP])

        if self.commit == None:
            raise RuntimeError("Command '%s' returns unexpected output" % cmd)


    def write_gbtcp_conf(self, transport, ifname):
        gbtcp_conf = (
            "dev.transport=%s\n"
            "route.if.add=%s\n"
            "arp.add=10.20.1.1,00:1b:21:95:69:65\n" # FIXME
            % (transport, ifname))

        with open(self.gbtcp_conf_path, 'w') as f:
            f.write(gbtcp_conf)


    def start_process(self, cmd, preload):
        e = os.environ.copy()
        e["LD_LIBRARY_PATH"] = self.path + "/bin"
        if preload:
            e["LD_PRELOAD"] = os.path.normpath(self.path + "/bin/libgbtcp.so")
            e["GBTCP_CONF"] = self.gbtcp_conf_path

        proc = subprocess.Popen(cmd.split(), env = e,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        print_log("$ %s &\n[%d]" % (cmd, proc.pid))

        return proc


class Database:
    TABLE_TEST = "test"
    TABLE_SAMPLE = "sample"

    ROLE_RUNNER = 0
    ROLE_TESTER = 1

    class Cpu_model:
        pass

    class Sample:

        CPS = 0
        IPPS = 1
        IBPS = 2
        OPPS = 3
        OBPS = 4
        RXMTPS = 5
        CONCURRENCY = 6
        PPS = 7
        BPS = 8

        def __init__(self):
            self.results = []

    class Test:
        attrs = [
            "commit",
            "tester",
            "os",
            "app",
            "cpu_model",
            "transport",
            "driver",
            "concurrency",
        ]

        def __init__(self):
            self.samples = []

    def create_core_tables(self):
        self.execute("create table if not exists %s ("
                "id int auto_increment,"
                "test_id int,"
                "duration int,"
                "runner_cpu_percent int,"
                "tester_cpu_percent int,"
                "primary key(id),"
                "foreign key(test_id) references test(id)"
                ")" % Database.TABLE_SAMPLE)


    def __init__(self, address):
        #self.sql_conn = sqlite3.connect(address)
        self.sql_conn = mysql.connector.connect(user = 'root', database='gbtcp')
        self.os_id = self.get_os_id(platform.system(), platform.release())
        self.cpu_model_id = self.get_cpu_model_id(get_cpu_name())

        self.create_core_tables()


    def execute(self, cmd, *args):
        try:
            sql_cursor = self.sql_conn.cursor(buffered = True)
            sql_cursor.execute(cmd, *args);
        except mysql.connector.errors.ProgrammingError as exc:
            raise RuntimeError("mysql query '%s' failed" % cmd) from exc
        return sql_cursor


    def fetchid(self, sql_cursor):
        row = sql_cursor.fetchone()
        assert(row != None)
        assert(len(row) == 1)
        assert(type(row[0]) == int)
        return int(row[0])


    def add_test(self, commit, tester_id, app_id,
            transport_id, driver_id, concurrency, cpu_mask, duration):

        where = ("gbtcp_commit=\"%s\" and tester_id=%d and os_id=%d and app_id=%d and "
            "transport_id=%d and driver_id=%d and concurrency=%d and cpu_model_id=%d and "
            "cpu_mask=\"%s\"" %
            (commit, tester_id, self.os_id, app_id,
            transport_id, driver_id, concurrency, self.cpu_model_id,
            cpu_mask))

        cmd = ("insert into %s "
            "(gbtcp_commit, tester_id, os_id, app_id, "
            "transport_id, driver_id, concurrency, cpu_model_id, cpu_mask) "
            "select \"%s\", %d, %d, %d, %d, %d, %d, %d, \"%s\" where not exists "
            "(select 1 from %s where %s)" % (
            Database.TABLE_TEST, commit, tester_id, self.os_id, app_id,
            transport_id, driver_id, concurrency, self.cpu_model_id, cpu_mask,
            Database.TABLE_TEST, where))
        self.execute(cmd)

        cmd = "select id from %s where %s" % (Database.TABLE_TEST, where)
        sql_cursor = self.execute(cmd)
        self.sql_conn.commit()
        test_id = self.fetchid(sql_cursor)

        sample_count = 0
        samples = self.get_samples(test_id)

        for sample in samples:
            if sample.duration >= duration:
                sample_count += 1

        return test_id, sample_count


    def del_sample(self, sample_id):
        cmd = "delete from %s where id = %d" % (Database.TABLE_SAMPLE, sample_id)
        self.execute(cmd)
        self.sql_conn.commit()


    def add_sample(self, sample):
        sample.id = None
        if sample.test_id < 0:
            # dry-run
            return -1
        samples = self.get_samples(sample.test_id)
        while len(samples) > TEST_SAMPLE_MAX:
            candidate = sample
            for i in range(len(samples)):
                if samples[i].duration < candidate.duration:
                    candidate = samples[i]
            if candidate == sample:
                return 0
            self.del_sample(candidate.id)
            samples.remove(candidate)

        cmd = ("insert into %s "
            "(test_id, duration, runner_cpu_percent, tester_cpu_percent) "
            "values (%d, %d, %d, %d)" %
            (Database.TABLE_SAMPLE,
            sample.test_id,
            sample.duration,
            sample.runner_cpu_percent,
            sample.tester_cpu_percent))
        sql_cursor = self.execute(cmd)
        self.sql_conn.commit()
        return sql_cursor.lastrowid


    def fetch_sample(self, sql_cursor):
        row = sql_cursor.fetchone()
        if row == None:
            return None
        assert(len(row) == 5)
        sample = Database.Sample()
        sample.id = int(row[0])
        sample.test_id = int(row[1])
        sample.duration = int(row[2])
        sample.runner_cpu_percent = int(row[3])
        sample.tester_cpu_percent = int(row[4])
        return sample


    def fetch_test(self, sql_cursor):
        row = sql_cursor.fetchone()
        if row == None:
            return None
        assert(len(row) == 10)
        test = Database.Test()
        test.id = int(row[0])
        test.commit = row[1]
        test.tester_id = int(row[2])
        test.os_id = int(row[3])
        test.app_id = int(row[4])
        test.transport_id = int(row[5])
        test.driver_id = int(row[6])
        test.concurrency = int(row[7])
        test.cpu_model_id = int(row[8])
        test.cpu_mask = row[9]

        test.tester = tester_dict.get(test.tester_id)
        assert(test.tester)

        name, ver = self.get_os(test.os_id)
        assert(name)
        test.os = name + "-" + ver

        name, ver = self.get_app(test.app_id)
        assert(name)
        test.app = name + "-" + ver

        test.transport = transport_dict.get(test.transport_id)
        assert(test.transport)

        test.driver = driver_dict.get(test.driver_id)
        assert(test.driver)

        cpu_models = self.get_cpu_model(test.cpu_model_id)
        assert(cpu_models)
        alias = cpu_models[0].alias
        name = cpu_models[0].name
        if alias == None or len(alias) == 0:
            test.cpu_model = name
        else:
            test.cpu_model = alias

        return test;


    def get_sample(self, sample_id):
        cmd = "select * from %s where id=%d" % (Database.TABLE_SAMPLE, sample_id)
        sql_cursor = self.execute(cmd)
        return self.fetch_sample(sql_cursor)

    def get_samples(self, test_id):
        cmd = "select * from %s where test_id=%d" % (Database.TABLE_SAMPLE, test_id)
        sql_cursor = self.execute(cmd)
        samples = []
        while True:
            sample = self.fetch_sample(sql_cursor)
            if sample == None:
                return samples
            samples.append(sample)


    def get_table_id(self, table, name, ver):
        cmd = ("insert into %s(name, ver) select \"%s\", \"%s\" "
            "where not exists (select 1 from %s where name=\"%s\" and ver=\"%s\");"
            % (table, name, ver, table, name, ver))
        self.execute(cmd)
        cmd = "select id from %s where name=\"%s\" and ver=\"%s\"" % (table, name, ver)
        sql_cursor = self.execute(cmd)
        self.sql_conn.commit()
        return self.fetchid(sql_cursor)


    def get_cpu_model_id(self, cpu_model_name, cpu_model_alias=None):
        assert(cpu_model_alias == None)
        cmd = ("insert into cpu_model(name) select \"%s\" "
            "where not exists (select 1 from cpu_model where name=\"%s\")"
            % (cpu_model_name, cpu_model_name))
        self.execute(cmd)
        cmd = "select id from cpu_model where name=\"%s\"" % cpu_model_name
        sql_cursor = self.execute(cmd)
        self.sql_conn.commit()
        return self.fetchid(sql_cursor)


    def set_cpu_model_alias(self, cpu_model_id, cpu_model_alias):
        cmd = "update cpu_model set alias = '%s' where id = %d" % (cpu_model_alias, cpu_model_id)
        self.execute(cmd)
        self.sql_conn.commit();


    def get_app_id(self, name, ver):
        return self.get_table_id("app", name, ver)


    def get_os_id(self, name, ver):
        return self.get_table_id("os", name, ver)


    def get_tests(self, commit):
        tests = []
        cmd = "select * from %s where gbtcp_commit='%s'" % (Database.TABLE_TEST, commit)
        sql_cursor = self.execute(cmd)
        while True:
            test = self.fetch_test(sql_cursor)
            if test == None:
                return tests
            tests.append(test)
        return tests


    def get_os(self, os_id):
        cmd = "select name, ver from os where id=%d" % os_id
        sql_cursor = self.execute(cmd)
        row = sql_cursor.fetchone()
        if row == None:
            return None, None
        assert(len(row) == 2)
        return row[0], row[1]


    def get_app(self, app_id):
        cmd = "select name, ver from app where id=%d" % app_id
        sql_cursor = self.execute(cmd)
        row = sql_cursor.fetchone()
        if row == None:
            return None, None
        assert(len(row) == 2)
        return row[0], row[1]

   
    def get_cpu_model(self, cpu_model_id = None):
        cpu_models = []
        if cpu_model_id == None:
            cmd = "select * from cpu_model"
        else:
            cmd = "select * from cpu_model where id=%d" % cpu_model_id
        sql_cursor = self.execute(cmd)
        while True:
            row = sql_cursor.fetchone()
            if row == None:
                break
            assert(len(row) == 3)
            cpu_model = Database.Cpu_model()
            cpu_model.id = int(row[0])
            cpu_model.name = row[1]
            cpu_model.alias = row[2]
            cpu_models.append(cpu_model)
        return cpu_models


    def get_columns(self, table):
        cmd = "show columns from %s" % table

        columns = []
        sql_cursor = self.execute(cmd)
        while True:
            row = sql_cursor.fetchone()
            if row == None:
                break
            columns.append(row[0])
        return columns


    def is_table_exists(self, table):
        cmd = "show tables like '%s'" % table
        sql_cursor = self.execute(cmd)
        row = sql_cursor.fetchone()
        if row == None:
            return False
        else:
            return True


    def create_netstat_table(self, table, columns):
        cmd = "create table if not exists %s (sample_id int, role int" % table 
        for column in columns:
            cmd += ", %s bigint" % column
        cmd += ", primary key(sample_id, role), foreign key(sample_id) references sample(id))"
        self.execute(cmd)


    def add_netstat_column(self, table, column):
        cmd = "alter table %s add column %s bigint" % (table, column)
        self.execute(cmd)


    def add_netstat_columns(self, table, columns):
        if not columns:
            return
        cmd = "alter table %s" % table
        for i, column in enumerate(columns):
            if i:
                cmd += ", "
            else:
                cmd += " "
            cmd += "add column %s bigint" % column
        self.execute(cmd)


    def insert_into_netstat(self, table, sample_id, role, entries):
        assert(entries)
        cmd = "insert into %s (sample_id, role" % table
        for entry in entries:
            cmd += ", %s" % entry.name
        cmd += ") values (%d, %d" % (sample_id, role)
        for entry in entries:
            cmd += ", %d" % entry.value
        cmd += ")"
        self.execute(cmd)
