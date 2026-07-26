#!/usr/bin/python

# SPDX-License-Identifier: LGPL-2.1-only

# mysql -D gbtcp
# mysql -D gbtcp -e 'select * from test;'

# use mysql;
# update user set plugin='mysql_native_password' where user='root';
# flush privileges;

# show tables;
# mysql -D gbtcp -e 'select * from test;'
# select * from netstat_bsd_tcp\G;
#
# delete from test where pps = 0;
# mysql -D gbtcp -e 'delete from test where id in (2, 3);'
# delete from test where id between 4 and 8;
#
# mysql -D gbtcp -e 'drop database gbtcp'
# mysql -D gbtcp -e 'drop table netstat_bsd_arp,netstat_bsd_ip,netstat_bsd_tcp,netstat_bsd_udp,test;'

from enum import Enum
import mysql.connector

from common import *

class Database:
    unique = [
            ["tags", "varchar(64)"],
            ["test", "varchar(32)"],
            ["git", "varchar(40)"],
            ["driver", "varchar(32)"],
            ["cpus", "int"],
        ]

    def __init__(self, db="gbtcp", address=""):
        self.sql_conn = None
        self.sql_conn = mysql.connector.connect(user='root')
        self.execute("create database if not exists %s" % db)
        self.sql_conn.close()
        self.sql_conn = mysql.connector.connect(user='root', database=db)

    def __del__(self):
        if self.sql_conn != None:
            self.sql_conn.close()
            self.sql_conn = None

    def create_test_table(self):
        columns = unique = "" 

        for field in self.unique:
            if columns:
                columns += ", "
                unique += ", "
            columns += field[0] + " " + field[1]
            unique += field[0]
        columns += ", `load` int"
        columns += ", `pps` int"
        columns += ", `bps` bigint"

        sql_cursor = self.execute("create table if not exists test ("
                "id int auto_increment,"
                "%s,"
                "primary key(id),"
                "unique key(%s)"
                ")" % (columns, unique))
        sql_cursor.close()

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
        rows = sql_cursor.fetchone()
        assert(rows != None)
        assert(len(rows) == 1)
        assert(type(rows[0]) == int)
        return int(rows[0])

    def fetch_pps(self, sql_cursor):
        rows = sql_cursor.fetchone()
        if rows == None:
            return None
        assert(len(rows) == 2)
        assert(type(rows[0]) == int)
        assert(type(rows[1]) == int)
        return int(rows[0]), int(rows[1])

    def insert_into_test(self, tags, test, git, driver, cpus, load, pps, bps):
        self.create_test_table()

        fields = locals()

        where = keys = values = ""

        for uq in self.unique:
            key = uq[0]
            value = fields[key]

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

        keys += ", `load`"
        keys += ", `pps`"
        keys += ", `bps`"

        values += ", %s" % str(load)
        values += ", %s" % str(pps)
        values += ", %s" % str(bps)

        cmd = ("insert into test (%s) select %s where not exists (select 1 from test where %s)"
                % (keys, values, where))
        sql_cursor = self.execute(cmd)
        sql_cursor.close()

        cmd = "select id from test where %s" % (where)
        sql_cursor = self.execute(cmd)
        self.commit()
        test_id = self.fetchid(sql_cursor)
        sql_cursor.close()

        return test_id

    def select_pps_from_test(self, tags, test, git, driver, cpus):
        fields = locals()

        where = ""

        for uq in self.unique:
            key = uq[0]
            value = fields[key]
            if where:
                where += " and "
            if type(value) == int:
                s = str(value)
            else:
                s = '"' + value + '"'

            where += key + "=" + s

        cmd = f"select pps, bps from test where {where}"
        sql_cursor = self.execute(cmd)
        self.commit()
        pps = self.fetch_pps(sql_cursor)
        sql_cursor.close()

        return pps

    def get_columns(self, table):
        cmd = "show columns from %s" % table

        columns = []
        sql_cursor = self.execute(cmd)
        while True:
            rows = sql_cursor.fetchone()
            if rows == None:
                break
            columns.append(rows[0])

        sql_cursor.close()

        return columns

    def is_table_exists(self, table):
        cmd = "show tables like '%s'" % table
        sql_cursor = self.execute(cmd)
        rows = sql_cursor.fetchone()
        sql_cursor.close()

        return rows != None

    def create_netstat_table(self, table, columns):
        cmd = "create table if not exists %s (test_id int, local boolean" % table
        for column in columns:
            cmd += ", %s bigint" % column
        cmd += (", primary key(test_id, local),"
            "foreign key(test_id) references test(id) on delete cascade")
        cmd += ")"
        sql_cursor = self.execute(cmd)
        self.commit()
        sql_cursor.close()

    def alter_netstat_add_column(self, table, column):
        cmd = "alter table %s add column %s bigint" % (table, column)
        sql_cursor = self.execute(cmd)
        self.commit()
        sql_cursor.close()

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
        sql_cursor = self.execute(cmd)
        self.commit()
        sql_cursor.close()

    def insert_into_netstat(self, table, test_id, local, entries):
        assert(entries)

        cmd = "insert ignore into %s (test_id, local" % table
        for entry in entries:
            cmd += ", %s" % entry.name
        cmd += ") values (%d, %d" % (test_id, local)
        for entry in entries:
            cmd += ", %d" % entry.value
        cmd += ")"
        sql_cursor = self.execute(cmd)
        self.commit()
        sql_cursor.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clean", type=str, choices=["zero", "dup"], required=False)
    args = ap.parse_args()

    if args.clean == None:
        return

if __name__ == "__main__":
    sys.exit(main())
