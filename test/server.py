#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import getopt
import socket
import traceback
import numpy

import ifstat
from common import *
from network import Network
import application


def print_report(app, top, rc):
	report = "%s: CPU=%s ... " % (app.get_name(), top)
	if rc == 0:
		report += "Passed"
	else:
		report += "Failed"
	log_notice(report)


class Server:
	def process_req(self, lines):
		duration = int(lines[1])
		concurrency = int(lines[2])
		transport = Transport(lines[3]) 
		application_name = lines[4]
		mode = Mode(lines[5])

		app = application.create(application_name, transport)
		assert(not app.is_gbtcp())
	
		app.start(self.repo, self.network, mode, concurrency, self.cpus)
	
		time.sleep(3)	
		top = Top(self.cpus, duration - 4)

		ifstat_old = None
		ipps = []
		opps = []
				
		while True:
			timedout = self.sock.recv_lines(1)[0]
			if not timedout:
				break
			ms_new = milliseconds()
			ifstat_new = app.read_ifstat()
			if ifstat_old:
				ifstat_rate = (ifstat_new - ifstat_old) / ((ms_new - ms_old) / 1000)
				ipps.append(ifstat_rate.ipackets)
				opps.append(ifstat_rate.opackets)
			ms_old = ms_new
			ifstat_old = ifstat_new

		top.join()

		rc = app.stop()[0]
		self.sock.send_string("ok")

		print_report(app, top.load, rc)
		if rc == 0:
			reply = ""
			reply += str(int(numpy.mean(ipps))) + "\n"
			reply += str(int(numpy.mean(opps))) + "\n" 
			reply += app.netstat.get_name() + "\n"
			reply += repr(app.netstat)
			return reply
		else:
			return None

	
	def process_client(self):
		try:
			while True:
				lines = self.sock.recv_lines()[1]
				if lines == None or len(lines) == 0:
					# Disconnected
					return

				header = lines[0].lower()

				if header == 'hello':
					process_hello(self.network, lines) 
					reply = make_hello(self.network, self.cpus)
				elif header == 'run':
					reply = self.process_req(lines)
				else:
					break

				if reply == None:
					break
				self.sock.send_string(reply)
		except Exception as exc:
			log_err(exc, "Client message caused error")


	def loop(self):
		if self.args.listen == None:
			listen_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
			try:
				os.unlink(SUN_PATH)
			except:
				pass
			listen_sock.bind(SUN_PATH)
		else:
			listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			listen_sock.bind(str(self.args.listen), 9999)
		listen_sock.listen()
		listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

		while True:
			self.sock = Socket(listen_sock.accept()[0])
			self.process_client()


	def __init__(self):
		ap = argparse.ArgumentParser()

		argparse_add_cpu(ap)
		argparse_add_log_level(ap)

		ap.add_argument("--listen", metavar="ip", type=argparse_ip_address,
				help="Listen for incomming test commands")

		ap.add_argument("-i", metavar="interface", required=True, type=argparse_interface,
				help="Interface direct connected to test client")


		self.args = ap.parse_args()

		set_log_level(self.args.stdout, self.args.syslog)

		self.cpus = self.args.cpu
		self.network = Network()
		self.network.set_interface(self.args.i)

		self.repo = Repository()
		self.repo.set_interface(self.args.i)

		for cpu in self.cpus:
			set_cpu_scaling_governor(cpu)

		self.network.interface.set_channels(self.cpus)


def main():

	server = Server()
	#set_log_level(syslog.LOG_DEBUG, None)
	server.loop()


if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt as exc:
		pass
