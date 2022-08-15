import platform # FIXME
import mysql.connector


from common import *

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
                "gbtcp_commit varchar(40),"
                "tester_id int,"
                "os_id int,"
                "app_id int,"
                "transport varchar(32),"
                "driver_id int,"
                "concurrency int,"
                "cpu_model_id int,"
                "cpu_mask varchar(128),"
                "primary key(id),"
                "unique key(gbtcp_commit, tester_id, os_id, app_id, transport, "
                        "driver_id, concurrency, cpu_model_id, cpu_mask),"
                "foreign key(os_id) references os(id),"
                "foreign key(app_id) references app(id),"
                "foreign key(cpu_model_id) references cpu_model(id)"
                ")" % Database.TABLE_TEST)

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
            transport, driver_id, concurrency, cpu_mask, duration):

        where = ("gbtcp_commit=\"%s\" and tester_id=%d and os_id=%d and app_id=%d and "
            "transport=\"%s\" and driver_id=%d and concurrency=%d and cpu_model_id=%d and "
            "cpu_mask=\"%s\"" %
            (commit, tester_id, self.os_id, app_id,
            transport.value, driver_id, concurrency, self.cpu_model_id,
            cpu_mask))

        cmd = ("insert into %s "
            "(gbtcp_commit, tester_id, os_id, app_id, "
            "transport, driver_id, concurrency, cpu_model_id, cpu_mask) "
            "select \"%s\", %d, %d, %d, \"%s\", %d, %d, %d, \"%s\" where not exists "
            "(select 1 from %s where %s)" % (
            Database.TABLE_TEST, commit, tester_id, self.os_id, app_id,
            transport.value, driver_id, concurrency, self.cpu_model_id, cpu_mask,
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
        test.transport = Transport(row[5])
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
