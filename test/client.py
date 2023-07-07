#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0

# TODO:
# - Client interface: Gold, Silver, Bronze (2)
# - Analayzer (3)
import os
import sys
import time
import math
import errno
import getopt
import socket
import subprocess

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

	log_notice(s)


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
		log_notice("%s ... %s" % (self.name, status))


class Client:
	@staticmethod
	def add_test(d, test):
		d[test.get_name()] = test


	def __del__(self):
		log_notice("Passed: %d" % self.tests_passed)
		log_notice("Failed: %d" % self.tests_failed)


	def set_cpus(self, cpus):
		self.cpus = cpus
		for cpu in self.cpus:
			assert(cpu < multiprocessing.cpu_count())
			set_cpu_scaling_governor(cpu)	


	def __init__(self): 
		self.tests_passed = 0
		self.tests_failed = 0
		self.repo = Repository()

		self.os = get_os()
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

		argparse_add_duration(ap, TEST_DURATION_DEFAULT)

		ap.add_argument("-i", metavar="interface", required=True, type=argparse_interface,
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

		ap.add_argument("--test", metavar="name", type=str, nargs='+',
				choices = [ k for (k, v) in tests.items() ],
				help="")

		self.args = ap.parse_args()
		self.remote_transport = Transport.NETMAP
		self.dry_run = False
		self.cpus = []
		self.duration = self.args.duration
		self.sample = self.args.sample
		self.interface = self.args.i
		self.network = Network()
		self.network.set_interface(self.interface)
		self.network.set_ip_network(self.args.network)


		self.tests = []
		if self.args.test:
			for test in self.args.test:
				self.tests.append(tests[test])

		self.repo.set_interface(self.interface)

		self.database = Database("")

		if self.args.connect:
			self.sock = Socket(socket.create_connection(str(self.args.connect), 9999))
		else:
			self.sock = Socket(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
			self.sock.connect(SUN_PATH)
		self.sock.settimeout(10)

		self.send_hello()

 
	def start_cooling(self):
		self.start_cooling_time = milliseconds()


	def send_hello(self):			   
		hello = make_hello(self.network, self.cpus)
		self.sock.send_string(hello)
		lines = self.sock.recv_lines()[1]
		hello = process_hello(self.network, lines)
		self.remote_os = hello[0]
		self.remote_driver = hello[1]
		self.remote_cpu_model = hello[2]
		self.remote_cpu_mask = hello[3]


	def cooling(self):
		ms = milliseconds() - self.start_cooling_time
		if ms < self.args.cooling * 1000:
			t = int(math.ceil((self.args.cooling * 1000 - ms) / 1000))
			time.sleep(t)


	def send_req(self, mode, remote_transport, remote, concurrency):
		req = "run\n"
		req += str(self.duration) + "\n"
		req += str(concurrency) + "\n"
		req += str(remote_transport.value) + "\n"
		req += remote + "\n"
		req += mode.value + "\n"
		req += "\n"
		self.sock.send_string(req)


	def recv_reply(self):
		return self.sock.recv_lines()[1]


	def do_rep(self, local, test_id, cpus):
		self.cooling()

		if self.mode == Mode.SERVER:
			local.start(self.repo, self.network, self.mode, self.concurrency, cpus)
			# Wait until client network interface is up
			time.sleep(2)

		self.send_req(get_peer_mode(self.mode), self.remote_transport, self.remote,
				self.concurrency)

		if self.mode == Mode.CLIENT:
			# Wait until server network interface is up
			time.sleep(2)
			local.start(self.repo, self.network, self.mode, self.concurrency, cpus)

		time.sleep(2)
		top = Top(cpus, self.duration - 2)
		top.join()

		if self.mode == Mode.CLIENT:
			local.stop()
			self.sock.send_string("ok")
			self.sock.recv_lines()
		else:
			self.sock.send_string("ok")
			self.sock.recv_lines()
			local.stop()

		rep = Database.Rep()
		rep.test_id = test_id
		rep.duration = self.duration
		rep.cpu_load = int(numpy.mean(top.load))

		lines = self.recv_reply()
		assert(len(lines) > 3)
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

		print_report(test_id, rep, local, self.concurrency, top.load)

		if rep == None and rep.cpu_load < 98:
			self.tests_failed += 1
		else:
			self.tests_passed += 1


	def do_run(self):
		cpus = self.cpus[0:self.n_cpus]

		local = application.create(self.local, self.local_transport)

		if self.dry_run:
			test_id = None
			n_passed = 0
		else:
			if local.transport == Transport.NATIVE:
				tag = ""
			else:
				tag = self.repo.tag

			cpu_mask = make_cpu_mask(cpus)
			test_id, n_passed = self.database.insert_into_test(
					self.duration,
					tag,
					self.concurrency,
					self.mode.value,
					self.os,
					local.get_name() + "-" + local.get_version(self.repo),
					local.transport.value,
					self.interface.driver.value,
					self.cpu_model,
					cpu_mask,
					self.remote_os,
					self.remote,
					self.remote_transport.value,
					self.remote_driver,
					self.remote_cpu_model,
					self.remote_cpu_mask,
				)

		for j in range (0, self.sample - n_passed):
			self.interface.set_channels(cpus)
			self.do_rep(local, test_id, cpus)


def main():
	self = Client()
	self.set_cpus([1, 2, 3, 4])
	self.local_transport = Transport.NETMAP
	self.mode = Mode.SERVER
	self.local = EPOLL_HELLOWORLD
	self.remote = CON_GEN
	self.concurrency = 1000
	for i in range(1, len(self.cpus)):
		self.n_cpus = i
		self.do_run()


if __name__ == "__main__":
	sys.exit(main())
