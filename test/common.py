# SPDX-License-Identifier: GPL-2.0
import os
import re
import sys
import time
import psutil
import platform
import subprocess
import multiprocessing
import syslog
import sqlite3
import mysql.connector
import numpy

CPS = 0
IPPS = 1
IBPS = 2
OPPS = 3
OBPS = 4
RXMTPS = 5
CONCURRENCY = 6
PPS = 7
BPS = 8

SAMPLE_COUNT_MAX = 20
SAMPLE_TABLE = "sample"
TEST_TABLE = "test"

SAMPLE_STATUS_OK = 0
SAMPLE_STATUS_OUTLIERS = 1
SAMPLE_STATUS_LOW_CPU_USAGE = 2

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

g_reload_netmap = None

def print_log(s, to_stdout = False):
    syslog.syslog(s)
    if to_stdout:
        print(s)

def die(s):
    print_log(s, True)
    sys.exit(1)

def is_int(s):
    try:
        i = int(s)
    except:
        return False
    return True

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

def str_to_int_list(s):
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
    res = list(res)
    res.sort()
    return res

def list_to_str(l):
    n = 0
    s = "["
    for i in l:
        if n > 0:
            s += ", "
        n += 1
        s += str(i)
    s += "]"
    return s

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
    except:
        proc.kill();
        die("Command '%s' failed, exception: '%s'" % (cmd, sys.exc_info()[0]))

    out = bytes_to_str(out)
    err = bytes_to_str(err)
    rc = proc.returncode
     
    print_log("$ %s # $? = %d\n%s\n%s" % (cmd, rc, out, err))

    if rc != 0 and not fault_tollerance:
        die("Command '%s' failed with code '%d'" % (cmd, rc))
        
    return rc, out, err

def rmmod(netmap_path, module):
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
    die("Cannot remove module '%s" % module)

def insmod(netmap_path, module_name):
    if module_name == "ixgbe":
        module_dir = "ixgbe"
    else:
        module_dir = ""
    path = netmap_path + "/" + module_dir + "/" + module_name + ".ko"
    system("insmod %s" % path)

def reload_netmap(netmap_path, driver):
    rmmod(driver)
    rmmod("netmap")
    insmod(netmap_path, "netmap")
    insmod(netmap_path, driver)
    # Wait interfaces after inserting module
    time.sleep(1)

# FIXME: to dict
def get_record_name(i):
    if i == CPS:
        return "cps"
    elif i == IPPS:
        return "ipps"
    elif i == IBPS:
        return "ibps"
    elif i == OPPS:
        return "opps"
    elif i == OBPS:
        return "obps"
    elif i == CONCURRENCY:
        return "concurrency"
    elif i == RXMTPS:
        return "rxmtps"
    elif i == PPS:
        return "pps"
    elif i == BPS:
        return "bps"
    else:
        return None

def get_sample_record(sample, i):
    assert(len(sample.records) == 7)
    assert(i <= BPS)
    if i == PPS:
        a = IPPS
        b = OPPS
    elif i == BPS:
        a = IBPS
        b = OBPS
    else:
        return sample.records[i]
    assert(len(sample.records[a]) == len(sample.records[b]))
    record = []
    for i in range(len(sample.records[a])):
        record.append(sample.records[a][i] + sample.records[b][i])
    return record

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

def get_runner_ip(subnet):
    return subnet + ".255.1"

def measure_cpu_usage(t, delay, cpus):
    # Skip last second
    assert(t > delay)
    time.sleep(delay)
    percent = psutil.cpu_percent(t - delay - 1, True)
    cpu_usage = []
    for cpu in cpus:
        cpu_usage.append(percent[cpu])
    return cpu_usage

def set_irqs(interface, cpus):
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
                    die("Bad irq at /proc/interrupts:%d" % i + 1)
                irqs.append(int(irq))

    if len(cpus) != len(irqs):
        die("Unexpected number of irqs (%d), shoud be %d" % (len(irqs), len(cpus)))

    for i in range(0, len(irqs)):
        f = open("/proc/irq/%d/smp_affinity" % irqs[i], 'w')
        f.write("%x" % (1 << cpus[i]))
        f.close()

def init_cpus(cpus):
    cpu_count = multiprocessing.cpu_count()

    for cpu in cpus:
        if cpu >= cpu_count:
            die("CPU %d exceeds number of CPUs %d" % (cpu, cpu_count))

    for cpu in cpus:
        path = "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor" % cpu
        f = open(path, 'w')
        f.write("performance")
        f.close()

def get_interface_driver(name):
    cmd = "ethtool -i %s" % name
    rc, out, _ = system(cmd, True)
    if rc != 0:
        die("Unknown interface '%s'" % name)
    for line in out.splitlines():
        if line.startswith("driver: "):
            return line[8:].strip()
    die("Cannot get interface '%s' driver" % name)

def create_interface(driver, name):
    driver_id = get_dict_id(driver_dict, driver)
    if driver_id == None:
        die("Unsupported driver '%s'", driver)        
    instance = globals().get(driver)
    assert(instance != None)
    interface = instance(name)
    interface.driver_id = driver_id
    system("ip l s dev %s up" % interface.name)
    return interface

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
    die("Couldn't get CPU model name")

def git_rev_parse(rev):
    commit = system("git rev-parse %s" % rev)[1].strip()
    if len(commit) != 40:
        die("Invalid git revision '%s'" % rev)
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
    # Aproximate with line and watch on the angle
    x = numpy.arange(0, len(sample))
    y = numpy.array(sample)
    kb = numpy.polyfit(x, y, 1)
    k = kb[0]
    b = kb[1]
    x0 = 0
    x1 = len(sample) - 1
    y0 = k * x0 + b
    y1 = k * x1 + b
    angle = abs(y1 - y0)/((y1 + y0) / 2) * 100
    # angle < 3 to be sure there is no throttling
    # Many valid samples got bad status due big angles.
    # Need mor investigation
    if True or angle < 3:
        return None, angle
    else:
        return range(0, len(sample)), angle




###############################
class interface:
    def __init__(self, name):
        self.name = name
        f = open("/sys/class/net/%s/address" % name)
        self.mac = f.read().strip()
        f.close()

class ixgbe(interface):
    def get_driver(self):
        return "ixgbe"

    def __init__(self, name):
        interface.__init__(self, name)
        system("ethtool -K %s rx off tx off" % name)
        system("ethtool -K %s gso off" % name)
        system("ethtool -K %s ntuple on" % name)
        system("ethtool -N %s rx-flow-hash tcp4 sdfn" % name)
        system("ethtool -N %s rx-flow-hash udp4 sdfn" % name)
        system("ethtool -G %s rx 2048 tx 2048" % name)

    def set_channels(self, cpus):
        system("ethtool -L %s combined %d" % (self.name, len(cpus)))
        set_irqs(self.name, cpus)

class veth(interface):
    def get_driver(self):
        return "veth"

    def set_channels_max(self):
        return 1;

    def __init__(self, name):
        interface.__init__(self, name)
        system("ethtool -K %s rx off tx off" % name)
        system("ethtool -K %s gso off" % name)
        system("ethtool -N %s rx-flow-hash tcp4 sdfn" % name)
        system("ethtool -N %s rx-flow-hash udp4 sdfn" % name)

    def set_channels(self, cpus):
        if len(cpus) != 1:
            die("veth interface doesn't support multiqueue mode. Please, use single cpu")

class Project:
    def system(self, cmd, fault_tollerance = False):
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = self.path + "/bin"
        return system(cmd, fault_tollerance, env)

    def __init__(self):
        self.path = os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + "/../")
        self.gbtcp_conf_path = self.path + "/test/gbtcp.conf"

        self.commit = None
        self.have_xdp = None
        self.have_netmap = None

        cmd = self.path + "/bin/gbtcp-aio-helloworld -v"
        _, out, _ = self.system(cmd)
        for line in out.splitlines():
            if line.startswith("gbtcp: "):
                self.commit = git_rev_parse(line[7:])
            elif line.startswith("config: "):
                if re.search("HAVE_XDP", line) != None:
                    self.have_xdp = True
                else:
                    self.have_xdp = False
                if re.search("HAVE_NETMAP", line) != None:
                    self.have_netmap = True
                else:
                    self.have_netmap = False

        if self.commit == None or self.have_xdp == None or self.have_netmap == None:
            die("%s: Parse error"  % cmd)

    def write_gbtcp_conf(self, transport, ifname):
        gbtcp_conf = (
            "dev.transport=%s\n"
            "route.if.add=%s\n"
            % (transport, ifname))

        f = open(self.gbtcp_conf_path, 'w')
        f.write(gbtcp_conf)
        f.close()

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

    def wait_process(self, proc):
        t0 = milliseconds()
        try:
            proc.wait(timeout = 5)
        except Exception as e:
            t1 = milliseconds()
            print("dt = %d milliseconds" % (t1 - t0))
            raise e
        lines = []
        for pipe in [proc.stdout, proc.stderr]:
            while True:
                line = pipe.readline()
                if not line:
                    break
                lines.append(line.decode('utf-8').strip())
        print_log("$ [%d] Done + %d\n%s" % (proc.pid, proc.returncode, '\n'.join(lines)))
        return proc.returncode, lines

class Database:
    class Cpu_model:
        pass

    class Sample:
        def __init__(self):
            self.records = []

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

    def log_invalid_test_field(test, field):
        print_log("Invalid field '%s' in table '%s' where 'test_id=%d'" %
            (field, TEST_TABLE, test.id), True)

    def __init__(self, address):
        #self.sql_conn = sqlite3.connect(address)
        self.sql_conn = mysql.connector.connect(user = 'root', database='gbtcp')
        self.os_id = self.get_os_id(platform.system(), platform.release())
        self.cpu_model_id = self.get_cpu_model_id(get_cpu_name())

    def execute(self, cmd, *args):
        sql_cursor = self.sql_conn.cursor(buffered = True)
        sql_cursor.execute(cmd, *args);
        return sql_cursor

    def fetchid(self, sql_cursor):
        row = sql_cursor.fetchone()
        assert(row != None)
        assert(len(row) == 1)
        assert(type(row[0]) == int)
        return int(row[0])

    def add_test(self, commit, tester_id, app_id,
            transport_id, driver_id, concurrency, cpu_count, report_count):
        assert(commit != None)
        assert(tester_id != None)
        assert(app_id != None)
        assert(transport_id != None)
        assert(driver_id != None)
        assert(concurrency != None)
        assert(cpu_count != None)
        assert(report_count != None)
        where = ("gbtcp_commit=\"%s\" and tester_id=%d and os_id=%d and app_id=%d and "
            "transport_id=%d and driver_id=%d and concurrency=%d and cpu_model_id=%d and "
            "cpu_count=%d" %
            (commit, tester_id, self.os_id, app_id,
            transport_id, driver_id, concurrency, self.cpu_model_id,
            cpu_count))

        cmd = ("insert into %s "
            "(gbtcp_commit, tester_id, os_id, app_id, "
            "transport_id, driver_id, concurrency, cpu_model_id, cpu_count) "
            "select \"%s\", %d, %d, %d, %d, %d, %d, %d, %d where not exists "
            "(select 1 from %s where %s)" % (
            TEST_TABLE, commit, tester_id, self.os_id, app_id,
            transport_id, driver_id, concurrency, self.cpu_model_id, cpu_count,
            TEST_TABLE, where))
        self.execute(cmd)

        cmd = "select id from %s where %s" % (TEST_TABLE, where)
        sql_cursor = self.execute(cmd)
        self.sql_conn.commit()
        test_id = self.fetchid(sql_cursor)

        sample_count = 0
        samples = self.get_samples(test_id)

        for sample in samples:
            if (sample.status == SAMPLE_STATUS_OK and len(sample.records[CPS]) >= report_count):
                sample_count += 1

        return test_id, sample_count

    def del_sample(self, sample_id):
        cmd = "delete from %s where id = %d" % (SAMPLE_TABLE, sample_id)
        self.execute(cmd)
        self.sql_conn.commit()

    def add_sample(self, sample):
        sample.id = None
        if sample.test_id < 0:
            # dry-run
            return -1
        samples = self.get_samples(sample.test_id)
        while len(samples) > SAMPLE_COUNT_MAX:
            candidate = sample
            for i in range(len(samples)):
                if samples[i].status != SAMPLE_STATUS_OK:
                    candidate = samples[i]
                    break
                if len(samples[i].records) < len(candidate.records):
                    candidate = samples[i]
            if candidate == sample:
                print_log("%d: Don't add sample due existing samples are better then this one"
                    % sample.test_id)
                return 0
            self.del_sample(candidate.id)
            samples.remove(candidate)

        # Use '?' instead of '%%s' for sqlite3
        cmd = ("insert into %s "
            "(test_id,status,cps,ipps,ibps,opps,obps,rxmtps,concurrency) "
            "values (%d,%d,%%s,%%s,%%s,%%s,%%s,%%s,%%s)" %
            (SAMPLE_TABLE, sample.test_id, sample.status))
        sql_cursor = self.execute(cmd, (
            int_list_to_bytearray(sample.records[CPS], 4),
            int_list_to_bytearray(sample.records[IPPS], 4),
            int_list_to_bytearray(sample.records[IBPS], 6),
            int_list_to_bytearray(sample.records[OPPS], 4),
            int_list_to_bytearray(sample.records[OBPS], 6),
            int_list_to_bytearray(sample.records[RXMTPS], 4),
            int_list_to_bytearray(sample.records[CONCURRENCY], 4)
            ))
        self.sql_conn.commit()
        return sql_cursor.lastrowid

    def fetch_sample(self, sql_cursor):
        row = sql_cursor.fetchone()
        if row == None:
            return None
        assert(len(row) == 10)
        sample = Database.Sample()
        sample.id = int(row[0])
        sample.test_id = int(row[1])
        sample.status = int(row[2])
        sample.records.append(bytearray_to_int_list(row[3], 4))
        sample.records.append(bytearray_to_int_list(row[4], 4))
        sample.records.append(bytearray_to_int_list(row[5], 6))
        sample.records.append(bytearray_to_int_list(row[6], 4))
        sample.records.append(bytearray_to_int_list(row[7], 6))
        sample.records.append(bytearray_to_int_list(row[8], 4))
        sample.records.append(bytearray_to_int_list(row[9], 4))
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
        test.cpu_count = int(row[9])

        test.tester = tester_dict.get(test.tester_id)
        if test.tester == None:
            log_invalid_test_field(test, 'tester_id')
            return None

        name, ver = self.get_os(test.os_id)
        if name == None:
            log_invalid_test_field(test, 'os_id')
            return None
        test.os = name + "-" + ver

        name, ver = self.get_app(test.app_id)
        if name == None:
            log_invalid_test_field(test, 'app_id')
            return None
        test.app = name + "-" + ver

        test.transport = transport_dict.get(test.transport_id)
        if test.transport == None:
            log_invalid_test_field(test, 'transport_id')

        test.driver = driver_dict.get(test.driver_id)
        if test.driver == None:
            log_invalid_test_field(test, 'driver_id')
            return None

        cpu_models = self.get_cpu_model(test.cpu_model_id)
        if len(cpu_models) == 0:
            log_invalid_test_field(test, 'cpu_model_id')
            return None
        else:
            alias = cpu_models[0].alias
            name = cpu_models[0].name
            if alias == None or len(alias) == 0:
                test.cpu_model = name
            else:
                test.cpu_model = alias

        return test;

    def get_sample(self, sample_id):
        cmd = "select * from %s where id=%d" % (SAMPLE_TABLE, sample_id)
        sql_cursor = self.execute(cmd)
        return self.fetch_sample(sql_cursor)

    def get_samples(self, test_id):
        cmd = "select * from %s where test_id=%d" % (SAMPLE_TABLE, test_id)
        sql_cursor = self.execute(cmd)
        samples = []
        while True:
            sample = self.fetch_sample(sql_cursor)
            if sample == None:
                return samples
            samples.append(sample)

    def clean_samples(self, test_id):
        cmd = "delete from %s where test_id=%d and status != 0" % (SAMPLE_TABLE, test_id)
        self.execute(cmd)
        self.sql_conn.commit() 

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
        cmd = "select * from %s where gbtcp_commit='%s'" % (TEST_TABLE, commit)
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
