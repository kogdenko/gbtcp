#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
from enum import Enum
import mysql.connector

from common import *


class Database:
    class Role(Enum):
        RUNNER = "runner"
        TESTER = "tester"


    class Sample:
        pass


    @staticmethod
    def mysql_enum(enum):
        s = ""
        for e in enum:
            if s:
                s += ", "
            s += "'" + e.value + "'"
        return "enum(" + s + ")"


    def create_core_tables(self):
        columns = unique = ""        
        fields = [
                ["gbtcp_commit", "varchar(40)"],
                ["runner_os", "varchar(64)"],
                ["runner_app", "varchar(64)"],
                ["runner_mode", self.mysql_enum(Mode)],
                ["runner_transport", self.mysql_enum(Transport)],
                ["runner_driver", self.mysql_enum(Driver)],
                ["runner_cpu_model", "varchar(64)"],
                ["runner_cpu_mask", "varchar(128)"],
                ["tester_os", "varchar(64)"],
                ["tester_app", "varchar(64)"],
                ["tester_transport", self.mysql_enum(Transport)],
                ["tester_driver", self.mysql_enum(Driver)],
                ["tester_cpu_model", "varchar(64)"],
                ["tester_cpu_mask", "varchar(128)"],
                ["concurrency", "int"],
                ["connectivity", self.mysql_enum(Connectivity)],
            ]

        for field in fields:
            if columns:
                columns += ", "
                unique += ", "
            columns += field[0] + " " + field[1]
            unique += field[0]

        self.execute("create table if not exists test ("
                "id int auto_increment,"
                "%s,"
                "primary key(id),"
                "unique key(%s)"
                ")" % (columns, unique))

        self.execute("create table if not exists sample ("
                "id int auto_increment,"
                "test_id int,"
                "duration int,"
                "runner_cpu_percent int,"
                "tester_cpu_percent int,"
                "ipps int,"
                "opps int,"
                "cps int,"
                "primary key(id),"
                "foreign key(test_id) references test(id) on delete cascade"
                ")")


    def __init__(self, address):
        #self.sql_conn = sqlite3.connect(address)
        self.sql_conn = mysql.connector.connect(user='root', database='gbtcp')

        self.create_core_tables()


    def execute(self, cmd, *args):
        try:
            sql_cursor = self.sql_conn.cursor(buffered = True)
            sql_cursor.execute(cmd, *args);
        except mysql.connector.errors.ProgrammingError as exc:
            raise RuntimeError("mysql query '%s' failed" % cmd) from exc
        return sql_cursor


    def commit(self):
        self.sql_conn.commit()


    def fetchid(self, sql_cursor):
        row = sql_cursor.fetchone()
        assert(row != None)
        assert(len(row) == 1)
        assert(type(row[0]) == int)
        return int(row[0])


    def __insert_into_test(self, duration, fields):
        where = keys = values = ""

        for key, value in fields.items():
            if where:
                where += " and "
                values += ", "
                keys += ", "
            
            if type(value) == int:
                s = str(value)
            else:
                s = '"' + value + '"'

            where += key + "=" + s
            values += s
            keys += key

        cmd = ("insert into test (%s) select %s where not exists (select 1 from test where %s)"
            % (keys, values, where))
        self.execute(cmd)

        cmd = "select id from test where %s" % where
        sql_cursor = self.execute(cmd)
        self.commit()
        test_id = self.fetchid(sql_cursor)

        sample_count = 0
        samples = self.get_samples(test_id)

        for sample in samples:
            if sample.duration >= duration:
                sample_count += 1

        return test_id, sample_count


    def insert_into_test(self,
            duration,
            gbtcp_commit,
            runner_os,
            runner_app,
            runner_mode,
            runner_transport,
            runner_driver,
            runner_cpu_model,
            runner_cpu_mask,
            tester_os,
            tester_app,
            tester_transport,
            tester_driver,
            tester_cpu_model,
            tester_cpu_mask,
            concurrency,
            connectivity):
        fields = locals()
        del fields['self']
        del fields['duration']
        return self.__insert_into_test(duration, fields)


    def delete_sample(self, sample_id):
        cmd = "delete from sample where id = %d" % sample_id
        self.execute(cmd)
        self.commit()


    def insert_into_sample(self, sample):
        if not sample.test_id:
            # dry-run
            sample.id = None
            return

        samples = self.get_samples(sample.test_id)
        while len(samples) > TEST_SAMPLE_MAX:
            candidate = sample
            for i in range(len(samples)):
                if samples[i].duration < candidate.duration:
                    candidate = samples[i]
            if candidate == sample:
                return 0
            self.delete_sample(candidate.id)
            samples.remove(candidate)

        cmd = ("insert into sample "
            "(test_id, duration, runner_cpu_percent, tester_cpu_percent, ipps, opps, cps) "
            "values (%d, %d, %d, %d, 0, 0, 0)" %
            (sample.test_id,
            sample.duration,
            sample.runner_cpu_percent,
            sample.tester_cpu_percent))
        sql_cursor = self.execute(cmd)
        self.commit()
        sample.id = sql_cursor.lastrowid


    def fetch_sample(self, sql_cursor):
        row = sql_cursor.fetchone()
        if row == None:
            return None
        assert(len(row) == 8)
        sample = Database.Sample()
        sample.id = int(row[0])
        sample.test_id = int(row[1])
        sample.duration = int(row[2])
        sample.runner_cpu_percent = int(row[3])
        sample.tester_cpu_percent = int(row[4])
        sample.ipps = int(row[5])
        sample.opps = int(row[6])
        sample.cps = int(row[7])
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
        cmd = "select * from sample where id=%d" % sample_id
        sql_cursor = self.execute(cmd)
        return self.fetch_sample(sql_cursor)

    def get_samples(self, test_id):
        cmd = "select * from sample where test_id=%d" % test_id
        sql_cursor = self.execute(cmd)
        samples = []
        while True:
            sample = self.fetch_sample(sql_cursor)
            if sample == None:
                return samples
            samples.append(sample)


    # FIXME:
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


    # FIXME:
    def set_cpu_model_alias(self, cpu_model_id, cpu_model_alias):
        cmd = "update cpu_model set alias = '%s' where id = %d" % (cpu_model_alias, cpu_model_id)
        self.execute(cmd)
        self.sql_conn.commit();


    # FIXME:
    def get_app_id(self, name, ver):
        return self.get_table_id("app", name, ver)


    # FIXME:
    def get_os_id(self, name, ver):
        return self.get_table_id("os", name, ver)


    def get_tests(self, commit):
        tests = []
        cmd = "select test from %s where gbtcp_commit='%s'" % commit
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
        cmd = ("create table if not exists %s (sample_id int, role %s" %
            (table, self.mysql_enum(Database.Role)))
        for column in columns:
            cmd += ", %s bigint" % column
        cmd += (", primary key(sample_id, role),"
            "foreign key(sample_id) references sample(id) on delete cascade")
        cmd += ")"
        self.execute(cmd)
        self.commit()


    def alter_netstat_add_column(self, table, column):
        cmd = "alter table %s add column %s bigint" % (table, column)
        self.execute(cmd)
        self.commit()


    def alter_netstat_add_columns(self, table, columns):
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
        self.commit()


    def insert_into_netstat(self, table, sample_id, role, entries):
        assert(entries)
        cmd = "insert into %s (sample_id, role" % table
        for entry in entries:
            cmd += ", %s" % entry.name
        cmd += ") values (%d, \"%s\"" % (sample_id, role.value)
        for entry in entries:
            cmd += ", %d" % entry.value
        cmd += ")"
        self.execute(cmd)
        self.commit()
