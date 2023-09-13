#!/usr/bin/python

# SPDX-License-Identifier: LGPL-2.1-only

from enum import Enum
import mysql.connector

from common import *


def mysql_enum(enum):
	s = ""
	for e in enum:
		if s:
			s += ", "
		s += "'" + e.value + "'"
	return "enum(" + s + ")"


class Database:
	test_fields = [
			["tag", "varchar(40)"],
			["concurrency", "int"],
			["mode", mysql_enum(Mode)],
			["local_os", "varchar(64)"],
			["local_app", "varchar(64)"],
			["local_transport", mysql_enum(Transport)],
			["local_driver", mysql_enum(Driver)],
			["local_cpu_model", "varchar(64)"],
			["local_cpu_mask", "varchar(128)"],
			["remote_os", "varchar(64)"],
			["remote_app", "varchar(64)"],
			["remote_transport", mysql_enum(Transport)],
			["remote_driver", mysql_enum(Driver)],
			["remote_cpu_model", "varchar(64)"],
			["remote_cpu_mask", "varchar(128)"],
		]


	class Rep:
		def __init__(self):
			self.id = None
			self.test_id = None


	class Test:
		pass


	def create_core_tables(self):
		columns = unique = ""		 

		for field in self.test_fields:
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

		self.execute("create table if not exists rep ("
				"id int auto_increment,"
				"test_id int,"
				"duration int,"
				"cpu_load int,"
				"ipps int,"
				"opps int,"
				"cps int,"
				"primary key(id),"
				"foreign key(test_id) references test(id) on delete cascade"
				")")


	def __init__(self, address):

		self.sql_conn = mysql.connector.connect(user='root')
		self.execute("create database if not exists gbtcp")
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
		rows = sql_cursor.fetchone()
		assert(rows != None)
		assert(len(rows) == 1)
		assert(type(rows[0]) == int)
		return int(rows[0])


	def insert_into_test(self,
			duration,
			tag,
			concurrency,
			mode,
			local_os,
			local_app,
			local_transport,
			local_driver,
			local_cpu_model,
			local_cpu_mask,
			remote_os,
			remote_app,
			remote_transport,
			remote_driver,
			remote_cpu_model,
			remote_cpu_mask):
		fields = locals()
		del fields['self']
		del fields['duration']

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

		n_reps = 0
		reps = self.get_reps(test_id)

		for rep in reps:
			if rep.cpu_load >= CPU_LOAD_THRESHOLD and rep.duration >= duration:
				n_reps += 1

		return test_id, n_reps


	def delete_rep(self, rep_id):
		cmd = "delete from rep where id = %d" % rep_id
		self.execute(cmd)
		self.commit()


	def insert_into_rep(self, rep):
		assert(rep.test_id)

		reps = self.get_reps(rep.test_id)
		while len(reps) > TEST_REPS_MAX:
			candidate = rep
			for i in range(len(reps)):
				if reps[i].duration < candidate.duration:
					candidate = reps[i]
			if candidate == rep:
				return 0
			self.delete_rep(candidate.id)
			reps.remove(candidate)

		cmd = ("insert into rep "
				"(test_id, duration, cpu_load, ipps, opps, cps) "
				"values (%d, %d, %d, %d, %d, 0)" %
				(rep.test_id,
				rep.duration,
				rep.cpu_load,
				rep.ipps,
				rep.opps,
				))
		sql_cursor = self.execute(cmd)
		self.commit()
		rep.id = sql_cursor.lastrowid


	def fetch_rep(self, sql_cursor):
		rows = sql_cursor.fetchone()
		if rows == None:
			return None
		assert(len(rows) == 7)
		rep = Database.Rep()
		rep.id = int(rows[0])
		rep.test_id = int(rows[1])
		rep.duration = int(rows[2])
		rep.cpu_load = int(rows[3])
		rep.ipps = int(rows[4])
		rep.opps = int(rows[5])
		rep.cps = int(rows[6])
		return rep


	def fetch_test(self, sql_cursor):
		rows = sql_cursor.fetchone()
		if rows == None:
			return None
		assert(len(rows) == len(Database.test_fields) + 1)
		test = Database.Test()
		test.id = int(rows[0])

		for i in range(1, len(rows)):
			setattr(test, Database.test_fields[i - 1][0], rows[i])

		return test


	def get_rep(self, rep_id):
		cmd = "select * from rep where id=%d" % rep_id
		sql_cursor = self.execute(cmd)
		return self.fetch_rep(sql_cursor)


	def get_reps(self, test_id):
		cmd = "select * from rep where test_id=%d" % test_id
		sql_cursor = self.execute(cmd)
		reps = []
		while True:
			rep = self.fetch_rep(sql_cursor)
			if rep == None:
				return reps
			reps.append(rep)


	def get_tests(self, tag):
		tests = []

		cmd = "select id"
		for field in Database.test_fields:
			cmd += ", " + field[0]
		cmd += " from test where tag='%s'" % tag

		sql_cursor = self.execute(cmd)
		while True:
			test = self.fetch_test(sql_cursor)
			if test == None:
				return tests
			tests.append(test)

		return tests


	def get_columns(self, table):
		cmd = "show columns from %s" % table

		columns = []
		sql_cursor = self.execute(cmd)
		while True:
			rows = sql_cursor.fetchone()
			if rows == None:
				break
			columns.append(rows[0])
		return columns


	def is_table_exists(self, table):
		cmd = "show tables like '%s'" % table
		sql_cursor = self.execute(cmd)
		rows = sql_cursor.fetchone()
		if rows == None:
			return False
		else:
			return True


	def create_netstat_table(self, table, columns):
		cmd = "create table if not exists %s (rep_id int, local boolean" % table
		for column in columns:
			cmd += ", %s bigint" % column
		cmd += (", primary key(rep_id, local),"
			"foreign key(rep_id) references rep(id) on delete cascade")
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


	def insert_into_netstat(self, table, rep_id, local, entries):
		assert(entries)
		cmd = "insert into %s (rep_id, local" % table
		for entry in entries:
			cmd += ", %s" % entry.name
		cmd += ") values (%d, %d" % (rep_id, local)
		for entry in entries:
			cmd += ", %d" % entry.value
		cmd += ")"
		self.execute(cmd)
		self.commit()
