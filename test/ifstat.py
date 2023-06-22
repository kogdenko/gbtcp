#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import sys
import math
import socket
import argparse
import enum

from common import *


class Ifstat:
	class Counter(enum.Enum):
		IBYTES = 0
		IPACKETS = enum.auto()
		OBYTES = enum.auto()
		OPACKETS = enum.auto()


	@property
	def ibytes(self):
		return self.counters[Ifstat.Counter.IBYTES.value]


	@property
	def ipackets(self):
		return self.counters[Ifstat.Counter.IPACKETS.value]


	@property
	def obytes(self):
		return self.counters[Ifstat.Counter.OBYTES.value]


	@property
	def opackets(self):
		return self.counters[Ifstat.Counter.OPACKETS.value]


	def reset_counters(self):
		self.counters = [0] * len(Ifstat.Counter)


	def __init__(self):
		self.reset_counters()


	def __sub__(self, right):
		res = Ifstat()
		for i in Ifstat.Counter:
			res.counters[i.value] = self.counters[i.value] - right.counters[i.value]
		return res


	def __truediv__(self, dt):
		res = Ifstat()
		for i in Ifstat.Counter:
			res.counters[i.value] = int(self.counters[i.value]/dt)
		return res


	def __str__(self):
		return ("ibytes: %d\n"
			"ipackets: %d\n"
			"obytes: %d\n"
			"opackets: %d\n" %
			(self.ibytes,
			self.ipackets,
			self.obytes,
			self.opackets))


	def __repr__(self):
		return self.__str__()


	def read(self, app):
		try:
			ok = self.vread(app)
		except Exception as e:
			raise RuntimeError("Ifstat: Internal error: '%s'" % str(e))
		if not ok:
			raise RuntimeError("Ifstat: Invalid interface: '%s'" % app.repo.interface.name)


class LinuxIfstat(Ifstat):
	def vread(self, app):
		self.reset_counters()
		with open('/proc/net/dev', 'r') as f:
			lines = f.readlines()
		for line in lines:
			columns = line.split()
			if columns[0].strip() == app.repo.interface.name + ':':
				assert(len(columns) == 17)
				self.counters[Ifstat.Counter.IBYTES.value] = int(columns[1])
				self.counters[Ifstat.Counter.IPACKETS.value] = int(columns[2])
				self.counters[Ifstat.Counter.OBYTES.value] = int(columns[9])
				self.counters[Ifstat.Counter.OPACKETS.value] = int(columns[10])
				return True
		return False


class GbtcpIfstat(Ifstat):
	def __init__(self):
		super().__init__()


	def parse(self, interface, lines):
		for line in lines[1:]:
			columns = line.split()
			assert(len(columns) == 7)
			if interface == None or columns[0].strip() == interface.name:
				self.counters[Ifstat.Counter.IBYTES.value] = int(columns[3])
				self.counters[Ifstat.Counter.IPACKETS.value] = int(columns[1])
				self.counters[Ifstat.Counter.OBYTES.value] = int(columns[6])
				self.counters[Ifstat.Counter.OPACKETS.value] = int(columns[4])
				return True
		return False


	def vread(self, app):
		self.reset_counters()
		cmd = app.repo.path + "/bin/gbtcp-netstat -bI " + app.repo.interface.name
		lines = app.repo.system(cmd)[1].splitlines()
		return self.parse(app.repo.interface, lines)


class CongenIfstat(Ifstat):
	def __init__(self):
		super().__init__()


	def parse(self, interface, lines):
		for line in lines[1:]:
			columns = line.split()
			assert(len(columns) == 4)
			self.counters[Ifstat.Counter.IPACKETS.value] += int(columns[0])
			self.counters[Ifstat.Counter.IBYTES.value] += int(columns[1])
			self.counters[Ifstat.Counter.OPACKETS.value] += int(columns[2])
			self.counters[Ifstat.Counter.OBYTES.value] += int(columns[3])
			return True
		return False


	def vread(self, app):
		self.reset_counters()
		sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		sun_path = "/var/run/con-gen.%d.sock" % app.proc.pid
		sock.connect(sun_path)
		send_string(sock, "i")

		lines = recv_lines(sock)[1]
		return self.parse(None, lines)


def create_ifstat(t):
	if t == "linux":
		return LinuxIfstat()
	elif t == "gbtcp":
		return GbtcpIfstat()
	elif t == "con-gen":
		return CongenIfstat()
	else:
		assert(0)


def main():
	class PseudoInterface:
		def __init__(self, name):
			self.name = name

	class PseudoProc:
		def __init__(self, pid):
			self.pid = pid

	class PseudoApplication:
		def __init__(pid):
			self.proc = PseudoProc(pid)
			self.repo = Repository()

	ap = argparse.ArgumentParser()
	ap.add_argument("--type", type=str, choices=["linux", "gbtcp", "con-gen"], required=True)
	ap.add_argument("--pid", metavar="num", type=int, default=None)
	ap.add_argument("-i", type=str, required=True)

	args = ap.parse_args()

	app = PseudoApplication(args.pid)
	app.repo.interface = PseudoInterface(args.i)

	ifstat = create(args.type)

	ifstat.read(app)

	print(ifstat)


if __name__ == "__main__":
	sys.exit(main())
