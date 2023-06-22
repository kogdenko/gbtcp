#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0

# TODO:
# 1) Client interface: Gold, Silver, Bronze (2)
# 2) Transport (1)
# 4) Analayzer (3)
import os
import sys
import time
import math
import atexit
import errno
import getopt
import socket
import subprocess
import platform
import importlib
import multiprocessing
import re

import numpy

from common import *
from database import Database
import application
import netstat
from network import Network


NGINX = application.nginx.get_name()
CON_GEN = application.con_gen.get_name()
EPOLL_HELLOWORLD = application.gbtcp_epoll_helloworld.get_name()

COOLING_MIN = 0
COOLING_MAX = 3*60
COOLING_DEFAULT = 20


def get_peer_mode(mode):
	if mode == Mode.SERVER:
		return Mode.CLIENT
	else:
		return Mode.SERVER


def print_report(test_id, rep, app, concurrency, cpu_load):
	s = ""
	if rep != None:
		s += ("%d/%d: " % (test_id, rep.id))

	s += ("%s:%s: c=%d, CPU=%s" %
		(app.transport.value, app.get_name(), concurrency, str(cpu_load)))

	if rep != None:
		 pps = rep.ipps + rep.opps
		 s += ", %.2f mpps" % (pps/1000000)

	s += " ... "

	if rep == None:
		s += "Error"
	elif rep.cpu_load < 98:
		s += "Failed"
	else:
		s += "Passed"

	print_log(s, True)


class CheckTest:
	def __init__(self, client, name):
		self.client = client
		self.name = name


	def get_name(self):
		return self.name


	def run(self):
		proc = self.client.repo.start_process(self.client.repo.path + '/bin/' + self.name,
				None, None)
		if wait_process(proc)[0] == 0:
			self.client.tests_passed += 1
			status = "Passed"
		else:
			self.client.tests_failed += 1
			status = "Failed"
		print_log("%s ... %s" % (self.name, status), True)


class Client:
	@staticmethod
	def add_test(d, test):
		d[test.get_name()] = test


	def __del__(self):
		print("Passed: ", self.tests_passed)
		print("Failed: ", self.tests_failed)


	def __init__(self): 
		self.tests_passed = 0
		self.tests_failed = 0
		self.repo = Repository()

		self.os= platform.system() + "-" + platform.release()
		self.cpu_model = get_cpu_model()

		tests = {}
		for f in os.listdir(self.repo.path + '/bin'):
			if f[:10] == "gbtcp-test":
				if os.path.isfile(self.repo.path + '/test/' + f + '.pkt'):
					#Client.add_test(tests, Tcpkt(f))
					pass
				else:
					Client.add_test(tests, CheckTest(self, f))

		# Assume that last test ended at least 10 seconds ago
		self.start_cooling_time = milliseconds() - 10000

		ap = argparse.ArgumentParser()

		argparse_add_reload_netmap(ap)
		argparse_add_cpu(ap);
		argparse_add_duration(ap, TEST_DURATION_DEFAULT)

		ap.add_argument("-i", metavar="interface", required=True, type=argparse_interface,
				help="")

		ap.add_argument("--dry-run", action='store_true',
				help="")

		ap.add_argument("--connect", metavar="ip", type=argparse_ip_address,
				help="")

		ap.add_argument("--network", metavar="ip/mask", type=argparse_ip_network,
				default="20.30.0.0/16",
				help="")

		ap.add_argument("--sample", metavar="count", type=int,
				choices=range(TEST_REPS_MIN, TEST_REPS_MAX),
				default=TEST_REPS_DEFAULT,
				help="")

		ap.add_argument("--cooling", metavar="seconds", type=int,
				choices=range(COOLING_MIN, COOLING_MAX),
				default=COOLING_DEFAULT,
				help="")

		ap.add_argument("--concurrency", metavar="num", type=int, nargs='+',
				action=UniqueAppendAction,
				default=[CONCURRENCY_DEFAULT],
				help="Number of parallel connections")

		ap.add_argument("--transport", metavar="name", type=Transport,
				help="")

		ap.add_argument("--test", metavar="name", type=str, nargs='+',
				choices = [ k for (k, v) in tests.items() ],
				help="")

		self.args = ap.parse_args()
		self.concurrency = self.args.concurrency
		self.dry_run = self.args.dry_run
		self.duration = self.args.duration
		self.sample = self.args.sample
		self.interface = self.args.i
		self.cpus = self.args.cpu
		self.network = Network()
		self.network.set_interface(self.interface)
		self.network.set_ip_network(self.args.network)


		for cpu in self.cpus:
			set_cpu_scaling_governor(cpu)

		if self.args.reload_netmap:
			reload_netmap(self.args.reload_netmap, self.interface)

		self.tests = []
		if self.args.test:
			for test in self.args.test:
				self.tests.append(tests[test])

		self.transport = self.args.transport
		self.repo.set_interface(self.interface)

		self.database = Database("")

		if self.args.connect:
			self.sock = socket.create_connection(str(self.args.connect), 9999)
		else:
			self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
			self.sock.connect(SUN_PATH)
		self.sock.settimeout(10)

		self.send_hello()

 
	def start_cooling(self):
		self.start_cooling_time = milliseconds()


	def send_hello(self):			   
		hello = make_hello(self.network)
		send_string(self.sock, hello)
		lines = recv_lines(self.sock)[1]
		process_hello(self.network, lines)


	def cooling(self):
		ms = milliseconds() - self.start_cooling_time
		if ms < self.args.cooling * 1000:
			t = int(math.ceil((self.args.cooling * 1000 - ms) / 1000))
			time.sleep(t)


	def send_req(self, mode, remote, concurrency):
		req = "run\n"
		req += str(self.duration) + "\n"
		req += str(concurrency) + "\n"
		req += remote + "\n"
		req += mode.value + "\n"
		req += "\n"
		send_string(self.sock, req)


	def recv_reply(self):
		return recv_lines(self.sock)[1]


	def do_rep(self, mode, local, remote, test_id, concurrency, cpus):
		self.cooling()

		if mode == Mode.SERVER:
			local.start(self.repo, self.network, mode, concurrency, cpus)
			# Wait until client network interface is up
			time.sleep(2)

		self.send_req(get_peer_mode(mode), remote, concurrency)

		if mode == Mode.CLIENT:
			# Wait until server network interface is up
			time.sleep(2)
			local.start(self.repo, self.network, mode, concurrency, cpus)

		time.sleep(2)
		top = Top(cpus, self.duration - 2)
		top.join()

		if mode == Mode.CLIENT:
			local.stop()
			send_string(self.sock, "ok")
			recv_lines(self.sock)
		else:
			send_string(self.sock, "ok")
			recv_lines(self.sock)
			local.stop()

		rep = Database.Rep()
		rep.test_id = test_id
		rep.duration = self.duration
		rep.cpu_load = int(numpy.mean(top.load))

		lines = self.recv_reply()
		rep.ipps = int(lines[0])
		rep.opps = int(lines[1])
		remote_netstat = netstat.create(lines[2])
		remote_netstat.create_from_lines(lines[3:])

		local_netstat = local.netstat

		self.start_cooling()

		if rep != None:
			self.database.insert_into_rep(rep)
			local_netstat.insert_into_database(self.database, rep.id, True)
			remote_netstat.insert_into_database(self.database, rep.id, False) 

		print_report(test_id, rep, local, concurrency, top.load)

		if rep == None and rep.cpu_load < 98:
			self.tests_failed += 1
		else:
			self.tests_passed += 1


	def run_application(self, mode, local, remote, cpus, concurrency):
		if self.dry_run:
			test_id = None
			n_reps = 0
		else:
			if local.transport == Transport.NATIVE:
				tag = ""
			else:
				tag = self.repo.tag

			cpu_mask = make_cpu_mask(cpus)
			test_id, n_reps = self.database.insert_into_test(
					self.duration,
					tag,
					concurrency,
					mode.value,
					self.os,
					local.get_name() + "-" + local.get_version(self.repo),
					local.transport.value,
					self.interface.driver.value,
					self.cpu_model,
					cpu_mask,
					"Osxxx", # ?????
					remote,
					Transport.NETMAP.value,
					Driver.IXGBE.value,
					"ryzenxxxx", # ?????
					"000010000xxxx", # ??????
				)

		for j in range (0, self.sample - n_reps):
			self.interface.set_channels(cpus)
			self.do_rep(mode, local, remote, test_id, concurrency, cpus)


	def run_client_server(self, mode, local, remote, n_cpus, concurrency):
		local = application.create(local, self.transport)
		self.run_application(mode, local, remote, self.cpus[0:n_cpus], concurrency)


this = Client()
#this.run_client_server(Mode.SERVER, EPOLL_HELLOWORLD, CON_GEN, 2, 1000)
this.run_client_server(Mode.CLIENT, CON_GEN, CON_GEN, 2, 1000)
