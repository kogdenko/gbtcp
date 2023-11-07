#!/usr/bin/python

# SPDX-License-Identifier: LGPL-2.1-only

# TODO:
# - Client interface: Gold, Silver, Bronze (2)
# - CPS
# - Analyze new commit
import os
import sys
import time
import math
import psutil
import errno
import getopt
import socket
import subprocess
import syslog
from enum import Enum

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


class Status(Enum):
	PASSED = "Passed"
	FAILED = "Failed"
	ERROR = "Error"
	SKIPPED = "Skipped"
	CALIBRATION = "Calibration"


def get_peer_mode(mode):
	if mode == Mode.SERVER:
		return Mode.CLIENT
	else:
		return Mode.SERVER


def print_report(status, rep, app, concurrency, cpu_load):
	report = ""

	if rep:
		pps = rep.ipps + rep.opps
		if rep.test_id:
			report += "%d/%d: " % (rep.test_id, rep.id)
	else:
		pps = 0

	report += ("%s/%s/%s: c=%d, CPU=%s, %.2f mpps ... %s " % (
			app.transport.value,
			app.mode.value,
			app.get_name(),
			concurrency,
			str(cpu_load),
			pps/1000000,
			status.value))

	log_notice(report)


class CheckTest:
	def __init__(self, client, name):
		self.client = client
		self.name = name


	def get_name(self):
		return self.name


	def run(self):
		path = self.client.repo.path + '/bin/' + self.name
		proc = self.client.repo.start_process(path, None, None, None, Transport.NATIVE)
		if wait_process(proc)[0] == 0:
			self.client.tests_passed += 1
			status = Status.PASSED
		else:
			self.client.tests_failed += 1
			status = Status.FAILED
		log_notice("%s ... %s" % (self.name, status.value))


class Client:
	def __del__(self):
		log_notice("Passed: %d" % self.tests_passed)
		log_notice("Failed: %d" % self.tests_failed)
		log_notice("Skipped: %d" % self.tests_skipped)


	def set_cpus(self, cpus):
		self.cpus = cpus
		for cpu in self.cpus:
			assert(cpu < multiprocessing.cpu_count())
			set_cpu_scaling_governor(cpu)	


	def __init__(self, interface, server_address): 
		self.calibration_pps = None
		self.tests_passed = 0
		self.tests_failed = 0
		self.tests_skipped = 0
		self.skipped = {}
		self.repo = Repository()

		self.os = get_os()
		self.cpu_model = get_cpu_model()

		for f in os.listdir(self.repo.path + '/bin'):
			if f[:10] == "gbtcp-test":
				if os.path.isfile(self.repo.path + '/test/' + f + '.pkt'):
					pass
				else:
					test = CheckTest(self, f)
					test.run()

		# Assume that last test ended at least 10 seconds ago
		self.start_cooling_time = milliseconds() - 10000


		self.remote_transport = Transport.NETMAP
		self.impl = Impl.GBTCP
		self.dry_run = False
		self.cpus = []
		self.duration = TEST_DURATION_DEFAULT
		self.n_reps = 1
		self.n_tries = 2
		self.cooling = COOLING_DEFAULT
		self.interface = interface
		self.network = Network()
		self.network.set_interface(self.interface)
		self.network.set_ip_network(ipaddress.ip_network("20.30.0.0/16"))

		self.repo.set_interface(self.interface)

		self.database = Database("")
		
		if server_address:
			sock = socket.create_connection(server_address, 9999)
		else:
			sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
			sock.connect(SUN_PATH)

		self.sock = Socket(sock, "server")
		self.sock.settimeout(10)

		self.send_hello()

 
	def start_cooling(self):
		self.start_cooling_time = milliseconds()


	def send_hello(self):			   
		hello = make_hello(self.network, self.cpus)
		self.sock.send_string(hello)
		lines = self.recv_reply()
		hello = process_hello(self.network, lines)
		self.remote_os = hello[0]
		self.remote_driver = hello[1]
		self.remote_cpu_model = hello[2]
		self.remote_cpu_mask = hello[3]


	def do_cooling(self):
		ms = milliseconds() - self.start_cooling_time
		if ms < self.cooling * 1000:
			t = int(math.ceil((self.cooling * 1000 - ms) / 1000))
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
		lines = self.sock.recv_lines()[1]
		if lines == None or not len(lines):
			die(None, "Server seems died. Quitting...")
		return lines


	def is_linerate_limited(self, pps):
		if self.calibration_pps == None or self.calibration_pps == 0:
			return False
		if pps > self.calibration_pps:
			return True
		return self.calibration_pps - pps < self.calibration_pps * 0.1


	def start_local_app(self, local, cpus):
		s = local.start(self.repo, self.network, self.mode, self.impl, self.concurrency, cpus)
		if not s:
			log_warning(("Local app (%s) do not support %s mode" %
					(local.get_name(), local.mode.value)))
		return s


	def do_rep(self, local, test_id, cpus):
		skipped_key = (str(self.remote_transport) + "_" +
				str(local.transport) + "_" +
				local.get_name())
		skipped_n_cpus = self.skipped.get(skipped_key)

		if skipped_n_cpus and len(cpus) > skipped_n_cpus:
			self.tests_skipped += 1
			return Status.SKIPPED, None

		self.do_cooling()

		if self.mode == Mode.SERVER:
			if not self.start_local_app(local, cpus):
				return Status.SKIPPED, None
			# Wait until client network interface is up
			time.sleep(2)

		# TODO: Wait for reply from server, that app started and ready
		self.send_req(get_peer_mode(self.mode), self.remote_transport, self.remote,
				self.concurrency)

		if self.mode == Mode.CLIENT:
			# Wait until server network interface is up
			time.sleep(2)
			if not self.start_local_app(local, cpus):
				return Status.SKIPPED, None

		time.sleep(2)
		top = Top(cpus, self.duration - 2)
		top.join()

		if self.mode == Mode.CLIENT:
			local.stop()
			self.sock.send_string("stop")
			# Wait 'stopped' message
			self.recv_reply()
		else:
			self.sock.send_string("stop")
			# Wait 'stopped' message
			self.recv_reply()
			local.stop()

		lines = self.recv_reply()
		assert(len(lines) > 0)
		if lines[0] == "ok":
			rep = Database.Rep()
			rep.test_id = test_id
			rep.duration = self.duration
			rep.cpu_load = int(numpy.mean(top.load))
			rep.ipps = int(lines[1])
			rep.opps = int(lines[2])
			remote_netstat = netstat.create(lines[3])
			remote_netstat.create_from_lines(lines[4:])

			local_netstat = local.netstat

			if rep.test_id != None:
				self.database.insert_into_rep(rep)
				local_netstat.insert_into_database(self.database, rep.id, True)
				remote_netstat.insert_into_database(self.database, rep.id, False) 

			pps = rep.ipps + rep.opps
			if self.calibration_pps == 0:
				rep.status = Status.CALIBRATION
				self.calibration_pps = pps
			else:
				if rep.cpu_load < CPU_LOAD_THRESHOLD:
					if self.is_linerate_limited(pps):
						rep.status = Status.SKIPPED
						self.tests_skipped += 1
					else:
						rep.status = Status.FAILED
						self.tests_failed += 1
					
					self.skipped[skipped_key] = len(cpus)
				else:
					rep.status = Status.PASSED
					self.tests_passed += 1

			status = rep.status
		else:
			self.tests_failed += 1
			rep = None
			status = Status.ERROR
			pps = None

		print_report(status, rep, local, self.concurrency, top.load)

		self.start_cooling()

		return status, pps


	def do_run(self):
		cpus = self.cpus[0:self.n_cpus]

		local = application.create(self.local, self.local_transport)
		remote = application.create(self.remote, self.remote_transport)
		if remote.is_gbtcp():
			log_warning(("Remote app (%s/%s) should not use gbtcp. "
				"Please change remote app or transport") %
				(remote.transport.value, remote.get_name()))
			return []

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

		self.interface.set_channels(cpus)

		pps = []
		for _ in range (0, self.n_reps - n_passed):
			for _ in range (0, self.n_tries):
				rep_status, rep_pps = self.do_rep(local, test_id, cpus)
				if rep_status != Status.ERROR:
					pps.append(rep_pps)
				if rep_status != Status.FAILED:
					break
		return pps


def calibration(c):
	dry_run = c.dry_run
	c.calibration_pps = 0
	c.dry_run = True

	c.n_reps = 1
	c.n_tries = 1
	c.cooling = 10
	c.duration = 10
	c.remote_transport = Transport.NETMAP
	c.local_transport = Transport.NETMAP
	c.mode = Mode.SERVER
	c.remote = CON_GEN
	c.local = CON_GEN
	c.concurrency = len(c.cpus) * 1000
	c.n_cpus = len(c.cpus)
	c.do_run()

	c.dry_run = dry_run


def bronze(c):

	#calibration(c)

	c.n_reps = 1
	c.n_tries = 3
	c.cooling = 10
	c.duration = 10

	c.remote_transport = Transport.NETMAP
	c.local_transport = Transport.NETMAP
	c.mode = Mode.SERVER
	c.remote = CON_GEN #EPOLL_HELLOWORLD
	c.concurrency = 5000
	for app in [EPOLL_HELLOWORLD, NGINX]:
		c.local = app
		for i in range(0, len(c.cpus)):
			c.n_cpus = i + 1
			c.do_run()


def custom(c):
	c.n_reps = 1
	c.cooling = 10
	c.duration = 10

	c.remote_transport = Transport.NETMAP
	c.local_transport = Transport.NETMAP
	c.mode = Mode.SERVER
	c.remote = CON_GEN #EPOLL_HELLOWORLD
	c.concurrency = 5000
	app = EPOLL_HELLOWORLD
	for mode in [Mode.SERVER, Mode.CLIENT]:
		c.local = app
		for i in range(0, len(c.cpus)):
			c.n_cpus = i + 1
			pps = c.do_run()


def alive(c):
	dry_run = c.dry_run
	c.dry_run = True

	c.n_reps = 1
	c.n_tries = 1
	c.cooling = 10
	c.duration = 10
	c.remote_transport = Transport.NETMAP
	c.local_transport = Transport.NETMAP
	c.concurrency = 100
	c.n_cpus = 1
	c.remote = CON_GEN

	tests = {}
	tests[Mode.CLIENT] = [EPOLL_HELLOWORLD]
	tests[Mode.SERVER] = [EPOLL_HELLOWORLD, NGINX]

	for c.impl in [Impl.GBTCP, Impl.BSD44]:
		for c.mode, apps in tests.items():
			for c.local in apps:
				pps = c.do_run()
				if not len(pps):
					return False
				for x in pps:
					if x < 100000:
						return False

	c.dry_run = dry_run
	return True


def silver():
	pass


def gold():
	pass


def main():
	ap = argparse.ArgumentParser()

	argparse_add_log_level(ap)

	argparse_add_cpu(ap)

	ap.add_argument("-i", metavar="interface", required=True, type=argparse_interface,
			help="")

	ap.add_argument("--connect", metavar="ip", type=argparse_ip_address,
			help="")

	ap.add_argument("--bronze", action="store_true", help="Run bronze tests")
	ap.add_argument("--custom", action="store_true", help="Run custom tests")
	ap.add_argument("--alive", action="store_true", help="Run alive tests")

	ap.add_argument("--dry-run", action="store_true", help="Don't store test results")

	args = ap.parse_args()

	set_log_level(args.stdout, args.syslog)

	for proc in psutil.process_iter():
		if proc.name() in application.Application.registered():
			proc.kill()

	c = Client(args.i, args.connect)

	c.set_cpus(args.cpu)
	c.dry_run = args.dry_run

	if args.custom:
		custom(c)

	if args.bronze:
		bronze(c)

	if args.alive:
		if alive(c):
			return 0
		else:
			return 1

	return c.tests_failed == 0


if __name__ == "__main__":
	try:
		code = main()
	except KeyboardInterrupt as exc:
		code = 2
	sys.exit(code)
