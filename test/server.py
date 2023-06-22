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


def print_err(exc, s):
	print_log(s + " ('" + str(exc) + "')")
	traceback.print_exception(exc)


def print_report(app, top, rc):
	report = "%s: CPU=%s ... " % (app.get_name(), top)
	if rc == 0:
		report += "Passed"
	else:
		report += "Failed"
	print_log(report)


class Server:
	def process_req(self, lines):
		duration = int(lines[1])
		concurrency = int(lines[2])
		local = lines[3]
		mode = Mode(lines[4])

		app = application.create(local)
		app.start(self.repo, self.network, mode, concurrency, self.cpus)
	
		time.sleep(3)	
		top = Top(self.cpus, duration - 4)

		ifstat_old = None
		ipps = []
		opps = []
				
		while True:
			timedout = recv_lines(self.sock, 1)[0]
			if not timedout:
				break
			ms_new = milliseconds()
			ifstat_new = app.create_ifstat()
			ifstat_new.read(app)
			if ifstat_old:
				ifstat_rate = (ifstat_new - ifstat_old) / ((ms_new - ms_old) / 1000)
				ipps.append(ifstat_rate.ipackets)
				opps.append(ifstat_rate.opackets)
			ms_old = ms_new
			ifstat_old = ifstat_new

		top.join()

		rc = app.stop()[0]
		send_string(self.sock, "ok")

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
				lines = recv_lines(self.sock)[1]

				header = lines[0].lower()

				if header == 'hello':
					process_hello(self.network, lines) 
					reply = make_hello(self.network)
				elif header == 'run':
					reply = self.process_req(lines)
				else:
					break

				if reply == None:
					break
				send_string(self.sock, reply)
		except Exception as e:
			print_err(e, "Client message caused error")


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
			self.sock, _ = listen_sock.accept()
			self.process_client()
			self.sock.close()


	def __init__(self):
		ap = argparse.ArgumentParser()

		argparse_add_reload_netmap(ap)
		argparse_add_cpu(ap)

		ap.add_argument("--listen", metavar="ip", type=argparse_ip_address,
				help="Listen for incomming test commands")

		ap.add_argument("-i", metavar="interface", required=True, type=argparse_interface,
				help="Interface direct connected to test client")

		self.args = ap.parse_args()
		self.cpus = self.args.cpu
		self.network = Network()
		self.network.set_interface(self.args.i)

		self.repo = Repository()

		for cpu in self.cpus:
			set_cpu_scaling_governor(cpu)

		if self.args.reload_netmap:
			reload_netmap(self.args.reload_netmap, self.network.interface)

		self.network.interface.set_channels(self.cpus)


def main():
	server = Server()
	server.loop()


if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt as exc:
		pass
