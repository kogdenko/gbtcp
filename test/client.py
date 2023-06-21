#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
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


def print_report(test_id, sample, app, concurrency, cpu_usage):
	s = ""
	if sample != None:
		s += ("%d/%d: " % (test_id, sample.id))

	s += ("%s:%s: c=%d, CPU=%s" %
		(app.transport.value, app.get_name(), concurrency, str(cpu_usage)))

#	 if sample != None:
#		 pps = sample.results[Database.Sample.IPPS] + sample.results[Database.Sample.OPPS]
#		 s += ", %.2f mpps" % (pps/1000000)
#		 if False:
#			 rxmtps = sample.results[Database.Sample.RXMTPS]
#			 s += ", %.2f rxmtps" % (rxmtps/1000000)

	s += " ... "

	if sample == None:
		s += "Error"
	elif sample.runner_cpu_percent < 98:
		s += "Failed"
	else:
		s += "Passed"

	print_log(s, True)



class Simple:
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
					Client.add_test(tests, Simple(self, f))

		# Assume that last test ended at least 10 seconds ago
		self.stop_ms = milliseconds() - 10000

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
				choices=range(TEST_SAMPLE_MIN, TEST_SAMPLE_MAX),
				default=TEST_SAMPLE_DEFAULT,
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

#		 application_choices = [ a.get_name() for a in Application.registered() ]
#		 ap.add_argument("--application", metavar="name", type=str,
#				 choices = application_choices,
#				 help="")

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

#		 self.applications = []
#		 if self.args.application:
#			 app = Application.create(self.args.application, self.repo, self.network,
#					 Mode.SERVER, self.args.transport)
#			 self.applications.append(app)

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
 

	def send_hello(self):			   
		hello = make_hello(self.network)
		send_string(self.sock, hello)
		lines = recv_lines(self.sock)
		if len(lines) < 2:
			raise RuntimeError("Bad hello message")

		args = lines[1].strip().split()
		process_hello(self.network, args)


	def stop(self):
		self.stop_ms = milliseconds()


	def cooling(self):
		ms = milliseconds() - self.stop_ms
		if ms < self.args.cooling * 1000:
			t = int(math.ceil((self.args.cooling * 1000 - ms) / 1000))
			time.sleep(t)


	def send_req(self, concurrency):
		req = ("run\n"
				"--duration %d "
				"--concurrency %d "
				"--application con-gen" % (
				self.duration,
				concurrency))
		send_string(self.sock, req)


	def recv_reply(self):
		return recv_lines(self.sock)

	def run_sample(self, app, test_id, mode, concurrency, cpus):
		app.start(self.repo, self.network, mode, concurrency, cpus)

		# Wait interface goes up
		time.sleep(2)
		self.cooling()
		self.send_req(concurrency)

		top = Top(cpus, self.duration)
		top.join()

		lines = self.recv_reply()
		remote_netstat = netstat.create(lines[0])
		remote_netstat.create_from_lines(lines[1:])

#		 print(lines[1:])
#		 print("--------------------------------------------------")
#		 print(remote_netstat)
#		 print("--------------------------------------------------")


		app.stop()
		local_netstat = app.netstat

		self.stop()

		sample = Database.Sample()
		sample.test_id = test_id
		sample.duration = self.duration
		sample.runner_cpu_percent = int(numpy.mean(top.usage))
		sample.tester_cpu_percent = 0

		if sample != None:
			self.database.insert_into_sample(sample)
			local_netstat.insert_into_database(self.database, sample.id, Database.Role.RUNNER)
			remote_netstat.insert_into_database(self.database, sample.id, Database.Role.TESTER) 

		print_report(test_id, sample, app, concurrency, top.usage)

		if sample == None and sample.runner_cpu_percent < 98:
			self.tests_failed += 1
		else:
			self.tests_passed += 1



	def run_application(self, app, mode, cpus, concurrency):
		if self.dry_run:
			test_id = None
			sample_count = 0
		else:
			if app.transport == Transport.NATIVE:
				commit = ""
			else:
				commit = self.repo.commit

			cpu_mask = make_cpu_mask(cpus)
			test_id, sample_count = self.database.insert_into_test(
					self.duration,
					commit,
					self.os,
					app.get_name() + "-" + app.get_version(self.repo),
					mode.value,
					app.transport.value,
					self.interface.driver.value,
					self.cpu_model,
					cpu_mask,
					"Osxxx",
					"con-genxxx",
					Transport.NETMAP.value,
					Driver.IXGBE.value,
					"ryzenxxxx",
					"000010000xxxx",
					concurrency,
					Connectivity.LOCAL.value)

		for j in range (0, self.sample - sample_count):
			self.interface.set_channels(cpus)
			self.run_sample(app, test_id, mode, concurrency, cpus)


	def run_client_server(self, mode, local, remote, n_cpus, concurrency):
		local = application.create(local, self.transport)
		self.run_application(local, mode, self.cpus[0:n_cpus], concurrency)



this = Client()
this.run_client_server(Mode.SERVER, EPOLL_HELLOWORLD, CON_GEN, 2, 1000)
