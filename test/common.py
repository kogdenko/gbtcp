# GPL V2 License
import os
import re
import sys
import time
import platform
import subprocess
#import datetime
import syslog
import sqlite3
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

def print_log(s, to_stdout = False):
    #now = datetime.datetime.now()
    #s = now.strftime("%Y-%m-%d %H:%M:%S.%f: ")
    #sys.stdout.write(s)
    syslog.syslog(s)
    if to_stdout:
        print(s)

def die(s):
    print_log(s, True)
    sys.exit(1)

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

TRANSPORT_NATIVE = 0
TRANSPORT_NETMAP = 1
TRANSPORT_XDP = 2

transport_dict = {
    TRANSPORT_NATIVE: "native",
    TRANSPORT_NETMAP: "netmap",
    TRANSPORT_XDP: "xdp",
}

def get_dict_id(d, name):
    for id, name in d.items():
        if name == name:
            return id
    return None

DRIVER_VETH = 1
DRIVER_IXGBE = 2

driver_dict = {
    DRIVER_VETH: "driver",
    DRIVER_IXGBE: "ixgbe",
}

tester_dict = {
    TESTER_LOCAL_CON_GEN: "local:con-gen",
    TESTER_REMOTE_CON_GEN: "con-gen",
}

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
    assert(len(sample.records) == 6)
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

def milliseconds():
    return int(time.monotonic_ns() / 1000000)

def get_project_path():
    return os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + "/../")

def system(cmd, fault_tollerance = False):
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = get_project_path() + "/bin"

    proc = subprocess.Popen(cmd.split(), env = env,
        stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    try:
        out, err = proc.communicate()
    except:
        proc.kill();
        die("Command '%s' failed, exception: '%s'" % (cmd, sys.exc_info()[0]))

    out = bytes_to_str(out)
    err = bytes_to_str(err)
    rc = proc.returncode
     
    print_log("$ %s # $? = %d\n%s\n%s" % (cmd, rc, out, err))

    if rc != 0 and not fault_tollerance:
        die("Command '%s' failed, return code: %d" % (cmd, rc))
        
    return rc, out, err

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

def log_invalid_test_field(test, field):
    print_log("Invalid field '%s' in table '%s' where 'test_id=%d'" %
        (field, TEST_TABLE, test.id), True)

class Sample:
    def __init__(self):
        self.records = []

class Test:
    def __init__(self):
        self.samples = []

class Environment:
    project_path = None
    sql_conn = None
    sql_cursor = None
    commit = None
    os_id = None
    cpu_model_id = None

    def fetchid(self):
        row = self.sql_cursor.fetchone()
        assert(row != None)
        assert(len(row) == 1)
        assert(type(row[0]) == int)
        return int(row[0])

    def add_test(self, commit, tester_id, app_id,
            driver_id, transport_id, concurrency, cpu_count, report_count):
        assert(commit != None)
        assert(tester_id != None)
        assert(app_id != None)
        assert(driver_id != None)
        assert(transport_id != None)
        assert(concurrency != None)
        assert(cpu_count != None)
        assert(report_count != None)
        where = ("gbtcp_commit=\"%s\" and tester_id=%d and os_id=%d and app_id=%d and "
            "driver_id=%d and transport_id=%d and concurrency=%d and cpu_model_id=%d and "
            "cpu_count=%d" %
            (commit, tester_id, self.os_id, app_id,
            driver_id, transport_id, concurrency, self.cpu_model_id,
            cpu_count))

        cmd = ("insert into %s "
            "(gbtcp_commit, tester_id, os_id, app_id, "
            "driver_id, transport_id, concurrency, cpu_model_id, cpu_count) "
            "select \"%s\", %d, %d, %d, %d, %d, %d, %d, %d where not exists "
            "(select 1 from %s where %s)" % (
            TEST_TABLE, commit, tester_id, self.os_id, app_id,
            driver_id, transport_id, concurrency, self.cpu_model_id, cpu_count,
            TEST_TABLE, where))
        self.sql_cursor.execute(cmd)

        cmd = "select id from %s where %s" % (TEST_TABLE, where)
        self.sql_cursor.execute(cmd)
        self.sql_conn.commit()
        test_id = self.fetchid()

        sample_count = 0
        samples = self.get_samples(test_id)

        for sample in samples:
            if (sample.status == SAMPLE_STATUS_OK and len(sample.records[CPS]) >= report_count):
                sample_count += 1

        return test_id, sample_count

    def del_sample(self, sample_id):
        cmd = "delete from %s where id = %d" % (SAMPLE_TABLE, sample_id)
        self.sql_cursor.execute(cmd)
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

        cmd = ("insert into %s "
            "(test_id,status,cps,ipps,ibps,opps,obps,rxmtps,concurrency) "
            "values (%d,%d,?,?,?,?,?,?,?)" %
            (SAMPLE_TABLE, sample.test_id, sample.status))
        self.sql_cursor.execute(cmd, (
            int_list_to_bytearray(sample.records[CPS], 4),
            int_list_to_bytearray(sample.records[IPPS], 4),
            int_list_to_bytearray(sample.records[IBPS], 6),
            int_list_to_bytearray(sample.records[OPPS], 4),
            int_list_to_bytearray(sample.records[OBPS], 6),
            int_list_to_bytearray(sample.records[RXMTPS], 4),
            int_list_to_bytearray(sample.records[CONCURRENCY], 4)
            ))
        self.sql_conn.commit()
        return self.sql_cursor.lastrowid

    def fetch_sample(self):
        row = self.sql_cursor.fetchone()
        if row == None:
            return None
        assert(len(row) == 10)
        sample = Sample()
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

    def fetch_test(self):
        row = self.sql_cursor.fetchone()
        if row == None:
            print("a")
            return None
        assert(len(row) == 10)
        test = Test()
        test.id = int(row[0])
        test.commit = row[1]
        test.tester_id = int(row[2])
        test.os_id = int(row[3])
        test.app_id = int(row[4])
        test.driver_id = int(row[5])
        test.transport_id = int(row[6])
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

        test.driver = driver_dict.get(test.driver_id)
        if test.driver == None:
            log_invalid_test_field(test, 'driver_id')
            return None

        test.transport = transport_dict.get(test.transport_id)
        if test.transport == None:
            log_invalid_test_field(test, 'transport_id')

        name, alias = self.get_cpu_model(test.cpu_model_id)
        if name == None:
            log_invalid_test_field(test, 'cpu_model_id')
            return None
        else:
            if alias == None or len(alias) == 0:
                test.cpu_model = name
            else:
                test.cpu_model = alias

        return test;

    def get_sample(self, sample_id):
        cmd = "select * from %s where id=%d" % (SAMPLE_TABLE, sample_id)
        self.sql_cursor.execute(cmd)
        return self.fetch_sample()

    def get_samples(self, test_id):
        cmd = "select * from %s where test_id=%d" % (SAMPLE_TABLE, test_id)
        self.sql_cursor.execute(cmd)
        samples = []
        while True:
            sample = self.fetch_sample()
            if sample == None:
                return samples
            samples.append(sample)

    def clean_samples(self, test_id):
        cmd = "delete from %s where test_id=%d and status != 0" % (SAMPLE_TABLE, test_id)
        self.sql_cursor.execute(cmd)
        self.sql_conn.commit() 

    def fetchid(self):
        row = self.sql_cursor.fetchone()
        assert(row != None)
        assert(len(row) == 1)
        assert(type(row[0]) == int)
        return int(row[0])

    def table_get_id(self, table, name, ver):
        cmd = ("insert into %s(name, ver) select \"%s\", \"%s\" "
            "where not exists (select 1 from %s where name=\"%s\" and ver=\"%s\");"
            % (table, name, ver, table, name, ver))
        self.sql_cursor.execute(cmd)
        cmd = "select id from %s where name=\"%s\" and ver=\"%s\"" % (table, name, ver)
        self.sql_cursor.execute(cmd)
        self.sql_conn.commit()
        return self.fetchid()

    def cpu_model_get_id(self, cpu_model_name, cpu_model_alias=None):
        assert(cpu_model_alias == None)
        cmd = ("insert into cpu_model(name) select \"%s\" "
            "where not exists (select 1 from cpu_model where name=\"%s\")"
            % (cpu_model_name, cpu_model_name))
        self.sql_cursor.execute(cmd)
        cmd = "select id from cpu_model where name=\"%s\"" % cpu_model_name
        self.sql_cursor.execute(cmd)
        self.sql_conn.commit()
        return self.fetchid()

    def app_get_id(self, name, ver):
        return self.table_get_id("app", name, ver)

    def os_get_id(self, name, ver):
        return self.table_get_id("os", name, ver)

    def get_tests(self, commit):
        tests = []
        cmd = "select * from %s where gbtcp_commit='%s'" % (TEST_TABLE, commit)
        self.sql_cursor.execute(cmd)
        while True:
            test = self.fetch_test()
            if test == None:
                return tests
            tests.append(test)
        return tests

    def get_os(self, os_id):
        cmd = "select name, ver from os where id=%d" % os_id
        self.sql_cursor.execute(cmd)
        row = self.sql_cursor.fetchone()
        if row == None:
            return None, None
        assert(len(row) == 2)
        return row[0], row[1]

    def get_app(self, app_id):
        cmd = "select name, ver from app where id=%d" % app_id
        self.sql_cursor.execute(cmd)
        row = self.sql_cursor.fetchone()
        if row == None:
            return None, None
        assert(len(row) == 2)
        return row[0], row[1]
   
    def get_cpu_model(self, cpu_model_id):
        cmd = "select name, alias from cpu_model where id=%d" % cpu_model_id
        self.sql_cursor.execute(cmd)
        row = self.sql_cursor.fetchone()
        if row == None:
            return None, None
        assert(len(row) == 2)
        return row[0], row[1]

    def __init__(self):
        self.project_path = get_project_path()
        self.commit = None
        self.have_xdp = None
        self.have_netmap = None
        self.ts_planned = 0
        self.ts_pass = 0
        self.ts_failed = 0

        cmd = self.project_path + "/bin/gbtcp-aio-helloworld -v"
        _, out, _ = system(cmd)
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

        self.sql_conn = sqlite3.connect(self.project_path + "/test/data.sqlite3")
        self.sql_cursor = self.sql_conn.cursor()

        self.os_id = self.os_get_id(platform.system(), platform.release())
        self.cpu_model_id = self.cpu_model_get_id(get_cpu_name())
