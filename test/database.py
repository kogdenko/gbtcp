#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
from enum import Enum
import mysql.connector

from common import *


class Database:
	class Rep:
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
				["tag", "varchar(40)"],
				["concurrency", "int"],
				["mode", self.mysql_enum(Mode)],
				["local_os", "varchar(64)"],
				["local_app", "varchar(64)"],
				["local_transport", self.mysql_enum(Transport)],
				["local_driver", self.mysql_enum(Driver)],
				["local_cpu_model", "varchar(64)"],
				["local_cpu_mask", "varchar(128)"],
				["remote_os", "varchar(64)"],
				["remote_app", "varchar(64)"],
				["remote_transport", self.mysql_enum(Transport)],
				["remote_driver", self.mysql_enum(Driver)],
				["remote_cpu_model", "varchar(64)"],
				["remote_cpu_mask", "varchar(128)"],
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
		#self.sql_conn = sqlite3.connect(address)

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
		row = sql_cursor.fetchone()
		assert(row != None)
		assert(len(row) == 1)
		assert(type(row[0]) == int)
		return int(row[0])


	def insert_into_test2(self, duration, fields):
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
			if rep.duration >= duration:
				n_reps += 1

		return test_id, n_reps


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
		return self.insert_into_test2(duration, fields)


	def delete_rep(self, rep_id):
		cmd = "delete from rep where id = %d" % rep_id
		self.execute(cmd)
		self.commit()


	def insert_into_rep(self, rep):
		if not rep.test_id:
			# Dry run
			rep.id = None
			return

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
				"values (%d, %d, %d, 0, 0, 0)" %
				(rep.test_id,
				rep.duration,
				rep.cpu_load,
				))
		sql_cursor = self.execute(cmd)
		self.commit()
		rep.id = sql_cursor.lastrowid


	def fetch_rep(self, sql_cursor):
		row = sql_cursor.fetchone()
		if row == None:
			return None
		assert(len(row) == 7)
		rep = Database.Rep()
		rep.id = int(row[0])
		rep.test_id = int(row[1])
		rep.duration = int(row[2])
		rep.cpu_load = int(row[3])
		rep.ipps = int(row[4])
		rep.opps = int(row[5])
		rep.cps = int(row[6])
		return rep


	def fetch_test(self, sql_cursor):
		row = sql_cursor.fetchone()
		if row == None:
			return None
		assert(len(row) == 10)
		test = Database.Test()
		test.id = int(row[0])
		test.tag = row[1]
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


	def get_tests(self, commit):
		tests = []
		cmd = "select test from %s where tag='%s'" % commit
		sql_cursor = self.execute(cmd)
		while True:
			test = self.fetch_test(sql_cursor)
			if test == None:
				return tests
			tests.append(test)
		return tests


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
		cmd = "create table if not exists %s (rep_id int, local int" %	table
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
		cmd += ") values (%d, \"%s\"" % (rep_id, local)
		for entry in entries:
			cmd += ", %d" % entry.value
		cmd += ")"
		self.execute(cmd)
		self.commit()
