#!/usr/bin/python

# SPDX-License-Identifier: LGPL-2.1-only

import os
import re
import sys
import time
import select
import psutil
import platform
import socket
import argparse
import subprocess
import datetime
import traceback
import multiprocessing
from syslog import *
import ipaddress
import threading
import numpy
from enum import Enum

 
SUN_PATH = "/var/run/gbtcp-test.sock"

TEST_REPS_MIN = 1
TEST_REPS_MAX = 20
TEST_REPS_DEFAULT = 5
CPU_LOAD_THRESHOLD = 98

class Mode(Enum):
	CLIENT = "client"
	SERVER = "server"


class Transport(Enum):
	DEFAULT = "default"
	NATIVE = "native"
	NETMAP = "netmap"
	XDP = "xdp"


class Driver(Enum):
	VETH = "veth"
	IXGBE = "ixgbe"


class EnvVar(Enum):
	LD_LIBRARY_PATH = "LD_LIBRARY_PATH"
	LD_PRELOAD = "LD_PRELOAD"
	GBTCP_CONF = "GBTCP_CONF"


TEST_DURATION_MIN = 10
TEST_DURATION_MAX = 10*60
TEST_DURATION_DEFAULT = 60

TEST_DELAY_MIN = 0
TEST_DELAY_MAX = TEST_DURATION_MIN - 1
TEST_DELAY_DEFAULT = 2

CONCURRENCY_DEFAULT=1000
CONCURRENCY_MAX=20000

g_log_level_stdout = LOG_NOTICE
g_log_level_syslog = LOG_INFO

def set_log_level(log_level_stdout, log_level_syslog):
	global g_log_level_syslog
	global g_log_level_stdout

	if log_level_stdout:
		g_log_level_stdout = log_level_stdout
	if log_level_syslog:
		g_log_level_syslog = log_level_syslog


def print_log(level, s):
	global g_log_level_stdout
	global g_log_level_syslog

#	if True:
#		traceback.print_stack()

	if level <= g_log_level_stdout:
		print(str(datetime.datetime.now()) + ": " + s)
	if level <= g_log_level_syslog:
		syslog(s)


def log_err(exc, s):
	if exc != None:
		exception_str = '\n'.join(traceback.format_exception(exc))
		s += " ('" + str(exc) + "')\n" + exception_str
	print_log(LOG_ERR, s)


def die(s):
	log_err(None, s)
	sys.exit(1)


def log_debug(s):
	print_log(LOG_DEBUG, s)


def log_info(s):
	print_log(LOG_INFO, s)


def log_notice(s):
	print_log(LOG_NOTICE, s)


def dbg(*args):
	traceback.print_stack(limit=2)
	print(args)


def get_os():
	return platform.system() + "-" + platform.release()


class ArgumentParser(argparse.ArgumentParser):
	def error(self, message):
		raise RuntimeError(message)


class UniqueAppendAction(argparse.Action):
	def __call__(self, parser, namespace, values, option_string=None):
		unique_values = list(set(values))
		unique_values.sort()
		setattr(namespace, self.dest, unique_values)


class mac_address:
	@staticmethod
	def create(s):
		error = ValueError("invalid literal for mac_address(): '%s'" % s)

		six = s.split(':')
		if len(six) != 6:
			raise error;

		for i, x in enumerate(six):
			if len(x) != 2:
				raise error;
			try:
				six[i] = int(x, 16)
			except ValueError:
				raise error;

		return mac_address(*six)


	@staticmethod
	def argparse(s):
		try:
			return mac_address.create(s)
		except ValueError as exc:
			raise argparse.ArgumentTypeError("invalid MAC value '%s'" % s)


	def __init__(self, a, b, c, d, e, f):
		self.__data = (a, b, c, d, e, f)


	def __str__ (self):
		return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
			self.__data[0], self.__data[1], self.__data[2],
			self.__data[3], self.__data[4], self.__data[5])

   
	def __repr__(self):
		return __str__(self)


class Socket:
	def __init__(self, sock, name):
		self.sock = sock
		self.name = name
		self.recv_buffer = []


	def connect(self, address):
		self.sock.connect(address)


	def settimeout(self, timeout):
		self.sock.settimeout(timeout)


	def recv_timed(self, bufsize, timeout=None):
		if timeout == None:
			data = self.sock.recv(bufsize)
			return False, data

		blocking = self.sock.getblocking()
		self.sock.setblocking(0)

		ready = select.select([self.sock], [], [], timeout)
		if ready[0]:
			timedout = False
			data = self.sock.recv(bufsize)
		else:
			timedout = True
			data = None

		self.sock.setblocking(blocking)
		return timedout, data


	def split_lines(self, message):
		lines = message.splitlines()
		if '' in lines:
			lines.remove('')

		return False, lines


	def pop_recv_buffer(self):
		message = self.recv_buffer[0]
		self.recv_buffer = self.recv_buffer[1:]
		return message


	def recv_lines(self, timeout=None):
		if len(self.recv_buffer) > 0:
			message = self.pop_recv_buffer()
			if len(self.recv_buffer) > 0:
				return self.split_lines(message)
		else:
			message = ""

		while True:
			timedout, data = self.recv_timed(1024, timeout)
			if timedout:
				log_debug("recvfrom %s Timeouted" % self.name)
				return True, None

			s = data.decode('utf-8')

			message += s

			self.recv_buffer = message.split("\n\n")
			assert(len(self.recv_buffer) > 0)
			if len(self.recv_buffer) > 1 or s == "":
				message = self.pop_recv_buffer()
				log_debug("recvfrom %s\n%s" % (self.name, message))
				return self.split_lines(message)


	def send_string(self, s):
		while s[-1] == '\n':
			s = s[:-1]
		data = (s + "\n\n").encode('utf-8')
		rc = self.sock.send(data)
		assert(rc == len(data))
		log_debug("sendto %s:\n%s" % (self.name, s))


def argparse_ip_address(s):
	try:
		return ipaddress.ip_address(s)
	except Exception as exc:
		raise argparse.ArgumentTypeError(str(exc))


def argparse_ip_network(s):
	try:
		return ipaddress.ip_network(s, strict=False)
	except Exception as exc:
		raise argparse.ArgumentTypeError(str(exc))


def argparse_dir(s):
	error = argparse.ArgumentTypeError("invalid directory '%s'" % s)

	try:
		path = os.path.abspath(s)
		if os.path.isdir(path):
			return path
		else:
			raise error;
	except:
		raise error;


def argparse_interface(s):
	error = argparse.ArgumentTypeError("invalid interface '%s'" % s)

	try:
		driver = get_interface_driver(s)
		interface = Interface.create(s, driver)
	except RuntimeError as exc:
		traceback.print_exception(exc)
		raise error
	return interface


def argparse_add_cpu(ap):
	ap.add_argument("--cpu", metavar="cpu-id", type=int, nargs='+',
			action=UniqueAppendAction,
			required=True,
			choices=range(0, multiprocessing.cpu_count() - 1),
			help="")


def argparse_log_stdout(s):
	set_log_level(int(s), None)


def argparse_add_log_level(ap):
	log_levels = [LOG_DEBUG, LOG_INFO, LOG_NOTICE, LOG_WARNING, LOG_ERR]
	ap.add_argument("--stdout", metavar="log-level", type=int, default=LOG_NOTICE,
			choices=log_levels,
			help="Set stdout log level")
	ap.add_argument("--syslog", metavar="log-level", type=int, default=LOG_NOTICE,
			choices=log_levels,
			help="Set syslog log level")


def argparse_add_duration(ap, default=None):
	if default:
		required = False
	else:
		required = True
	ap.add_argument("--duration", metavar="seconds", type=int,
			choices=range(TEST_DURATION_MIN, TEST_DURATION_MAX),
			required=required, default=default,
			help="Test duration in seconds")


def make_hello(network, cpus):
	hello = "hello\n"
	hello += str(network.interface.mac) + "\n"
	hello += str(network.ip_network) + "\n"
	hello += get_os() + "\n"
	hello += network.interface.driver.value + "\n"
	hello += get_cpu_model() + "\n"
	hello += make_cpu_mask(cpus) + "\n"
	return hello
 

def process_hello(network, lines):
	network.set_gw_mac(mac_address.create(lines[1]))
	network.set_ip_network(ipaddress.ip_network(lines[2]))
	os = lines[3]
	driver = lines[4]
	cpu_model = lines[5]
	cpu_mask  = lines[6]
	return os, driver, cpu_model, cpu_mask


def upper_pow2_32(x):
	x = int(x)
	x -= 1
	x |= x >>  1
	x |= x >>  2
	x |= x >>  4
	x |= x >>  8
	x |= x >> 16
	x += 1
	return x;


def bytes_to_str(b):
	return b.decode('utf-8').strip()


def make_cpu_mask(cpus):
	cpu_mask = ""
	for i in range(0, multiprocessing.cpu_count()):
		if i in cpus:
			cpu_mask += "1"
		else:
			cpu_mask += "0"
	return cpu_mask


def env_str(env):
	if not env:
		return ""
	s = ""
	for v in EnvVar:
		if env.get(v.value):
			if len(s):
				s += " "
			s += "%s=%s" % (v.value, env.get(v.value))

	return s;


def system(cmd, log_level=LOG_INFO, fault_tollerance=False, env=None):
	s = env_str(env)
	if len(s):
		cmd_with_env = "%s %s" % (s, cmd)
	else:
		cmd_with_env = cmd

	proc = subprocess.Popen(cmd.split(), env=env,
			stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	try:
		out, err = proc.communicate(timeout = 5)
	except Exception as exc:
		proc.kill();
		log_err(exc, "Command '%s' failed" % cmd_with_env)
		raise exc

	out = bytes_to_str(out)
	err = bytes_to_str(err)
	rc = proc.returncode

	log = "$ %s" % cmd_with_env
	if rc != 0:
		log += " $? = %d" % rc
	if len(out):
		log += "\n%s" % out
	if len(err):
		log += "\n%s" % err
	if rc == 0:
		print_log(log_level, log)
	else:
		if fault_tollerance:
			failed_log_level = log_level
		else:
			failed_log_level = LOG_ERR
		print_log(failed_log_level, log)

	if rc != 0 and not fault_tollerance:
		raise RuntimeError("Command '%s' failed with code '%d'" % (cmd, rc))
		
	return rc, out, err


def rmmod(module):
	rc, _, err = system("rmmod %s" % module, LOG_INFO, True)
	if rc == 0:
		return True
	lines = err.splitlines()
	if len(lines) == 1:
		msg = lines[0].strip()
		p = "rmmod: ERROR: Module %s is not currently loaded" % module
		m = re.search(p, msg)
		if m != None:
			return False
		p = "rmmod: ERROR: Module %s is in use by: " % module
		m = re.search(p, msg)
		if m != None and rmmod(msg[len(p):]):
			rmmod(module)
			return True
	raise RuntimeError("Cannot remove module '%s" % module)


def insmod(netmap_path, module_name):
	if module_name == "ixgbe":
		module_dir = "ixgbe"
	else:
		module_dir = ""
	path = netmap_path + "/" + module_dir + "/" + module_name + ".ko"
	system("insmod %s" % path)


def reload_netmap(netmap_path, interface):
	rmmod(interface.driver.value)
	rmmod("netmap")
	insmod(netmap_path, "netmap")
	insmod(netmap_path, interface.driver.value)
	# Wait interfaces after inserting module
	time.sleep(1)
	interface.up()


def round_std(std):
	assert(type(std) == int)
	assert(std >= 0)
	s = str(std)
	l = len(s)
	if l < 2:
		return std, 0
	if s[0] == '1' or s[0] == '2':
		z = 2
	else:
		z = 1
	r = s[0:z] + '0' * (l - z)
	return (int(r), l - z)


def round_val(val, std):
	assert(type(val) == int)
	assert(val >= 0)
	std_rounded, n = round_std(std)
	val_rounded = round(val, -n)
	return val_rounded, std_rounded


def set_irq_affinity(interface, cpus):
	with open("/proc/interrupts", 'r') as f:
		lines = f.readlines()

	irqs = []

	p = re.compile("^%s-TxRx-[0-9]*$" % interface)
	for i in range(1, len(lines)):		 
		columns = lines[i].split()
		for column in columns:
			m = re.match(p, column.strip())
			if m != None:
				irq = columns[0].strip(" :")
				if not irq.isdigit():
					raise RuntimeError("invalid irq: /proc/interrupts:%d" % i + 1)
				irqs.append(int(irq))

	if len(cpus) != len(irqs):
		raise RuntimeError("invalid number of irqs: %d" % len(irqs))

	for i in range(0, len(irqs)):
		with open("/proc/irq/%d/smp_affinity" % irqs[i], 'w') as f:
			f.write("%x" % (1 << cpus[i]))


def set_cpu_scaling_governor(cpu):
	path = "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor" % cpu
	with open(path, 'w') as f:
		f.write("performance")


def get_interface_driver(name):
	cmd = "ethtool -i %s" % name
	rc, out, _ = system(cmd)
	for line in out.splitlines():
		if line.startswith("driver: "):
			return line[8:].strip()
	raise RuntimeError("invalid ethtool driver: '%s'" % name )


def milliseconds():
	return int(time.monotonic_ns() / 1000000)


def get_cpu_model():
	if platform.system() == "Windows":
		return platform.processor()
	elif platform.system() == "Darwin":
		cmd ="sysctl -n machdep.cpu.brand_string"
		return system(command)[1].strip()
	elif platform.system() == "Linux":
		f = open("/proc/cpuinfo");
		lines = f.readlines()
		f.close()
		for line in lines:
			if "model name" in line:
				return re.sub( ".*model name.*:", "", line, 1).strip()
	raise RuntimeError("Cannot determine CPU model")


def find_outliers(reps, std):
	if std == None:
		std = [numpy.std(reps)] * len(reps)
	mean = numpy.mean(reps)
	# 3 sigma method
	outliers = []
	for i in range(0, len(reps)):
		if abs(mean - reps[i]) > 3 * std[i]:
			outliers.append(i)
	return outliers


def start_process(cmd, env=None):
	proc = subprocess.Popen(cmd.split(), env=env,
			stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	log = "$"
	s = env_str(env)
	if len(s):
		log += " %s" % s
	log += " %s & [pid=%d]" % (cmd, proc.pid)
	log_info(log)
	return proc


def wait_process(proc):
	lines = []
	t0 = milliseconds()
	try:
		proc.wait(timeout=5)
	except Exception as exc:
		t1 = milliseconds()
		dt = t1 - t0
		assert(dt * 1000 > 4.5)
		log_err(exc, "$ [pid=%d] Timeouted" % proc.pid)
		proc.terminate()
		proc.wait(timeout=5)

	for pipe in [proc.stdout, proc.stderr]:
		while True:
			line = pipe.readline()
			if not line:
				break
			lines.append(line.decode('utf-8').strip())

	log = "$ [pid=%d] Done + %d\n%s" % (proc.pid, proc.returncode, '\n'.join(lines))
	if proc.returncode == 0:
		log_debug(log)
	else:
		log_info(log)

	return proc.returncode, lines


class Interface:
	@staticmethod
	def create(name, driver_value):
		driver = Driver(driver_value)
		for instance in Interface.__subclasses__():
			if instance.driver == driver:
				interface = instance(name)
				return interface
		assert(0)


	def __init__(self, name):
		self.name = name
		with open("/sys/class/net/%s/address" % name) as f:
			self.mac = f.read().strip()
		self.up()


	def up(self):
		system("ip l s dev %s up" % self.name)


class ixgbe(Interface):
	driver = Driver.IXGBE

	def get_channels(self):
		cmd = "ethtool -l %s" % self.name
		out = system(cmd)[1]
		current_hardware_settings = False
		Combined = "Combined:"
		for line in out.splitlines():
			if line.startswith("Current hardware settings:"):
				current_hardware_settings = True
			if line.startswith(Combined) and current_hardware_settings:
				return int(line[len(Combined):])
		raise RuntimeError("'%s': No current hardware setting for 'Combined' ring" % cmd)


	def __init__(self, name):
		Interface.__init__(self, name)
		system("ethtool -K %s rx off tx off" % name)
		system("ethtool -K %s gso off" % name)
		system("ethtool -K %s ntuple on" % name)
		system("ethtool -N %s rx-flow-hash tcp4 sdfn" % name)
		system("ethtool -N %s rx-flow-hash udp4 sdfn" % name)
		system("ethtool -G %s rx 2048 tx 2048" % name)


	def set_channels(self, cpus):
		system("ethtool -L %s combined %d" % (self.name, len(cpus)))
		set_irq_affinity(self.name, cpus)


class veth(Interface):
	driver = Driver.VETH


	def __init__(self, name):
		Interface.__init__(self, name)
		system("ethtool -K %s rx off tx off" % name)
		system("ethtool -K %s gso off" % name)
		system("ethtool -N %s rx-flow-hash tcp4 sdfn" % name)
		system("ethtool -N %s rx-flow-hash udp4 sdfn" % name)


	def set_channels(self, cpus):
		if len(cpus) != 1:
			raise RuntimeError("veth interface doesn't support multiqueue mode")


class Top:
	def __init__(self, cpus, duration):
		self.cpus = cpus
		self.duration = duration
		self.thread = threading.Thread(name="top", target=self.measure)
		self.thread.start()


	def measure(self):
		percent = psutil.cpu_percent(self.duration, True)
		self.load = []
		for cpu in self.cpus:
			self.load.append(percent[cpu])


	def join(self):
		self.thread.join()


class Repository:
	def system(self, cmd, log_level=LOG_INFO, fault_tollerance=False):
		env = os.environ.copy()
		env["LD_LIBRARY_PATH"] = self.path + "/bin"
		return system(cmd, log_level, fault_tollerance, env)


	def __init__(self):
		self.path = os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + "/../")
		self.config_path = self.path + "/test/gbtcp.conf"
		self.interface = None

		self.tag = None

		cmd = self.path + "/bin/gbtcp-aio-helloworld -v"
		_, out, _ = self.system(cmd)
		for line in out.splitlines():
			if line.startswith("gbtcp: "):
				self.tag = line[7:]

		if self.tag == None:
			raise RuntimeError("Invalid command output: '%s'" % cmd)


	def set_interface(self, interface):
		self.interface = interface


	def write_config(self, network, mode, transport):
		assert(self.interface)
		config = ""
		config += "dev.transport=%s\n" % transport.value
		config += "route.if.add=%s\n" % self.interface.name
		if mode == Mode.CLIENT:
			config += "arp.add=%s,%s\n" % (network.server, network.gw_mac)
		else:
			config += "arp.add=%s,%s\n" % (network.first_client, network.gw_mac)

		with open(self.config_path, 'w') as f:
			f.write(config)


	def start_process(self, cmd, network, mode, transport=Transport.NATIVE):
		e = os.environ.copy()
		e[EnvVar.LD_LIBRARY_PATH.value] = self.path + "/bin"
		if transport != Transport.NATIVE:
			self.write_config(network, mode, transport)
			e[EnvVar.LD_PRELOAD.value] = os.path.normpath(self.path + "/bin/libgbtcp.so")
			e[EnvVar.GBTCP_CONF.value] = self.config_path
		return start_process(cmd, e)
