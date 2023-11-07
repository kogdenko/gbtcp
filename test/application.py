#!/usr/bin/python

# SPDX-License-Identifier: LGPL-2.1-only

import platform
import re
import signal
from syslog import *

from common import *
import netstat
import ifstat


def parse_version(s):
	m = re.search(r'[0-9]+\.[0-9]+\.[0-9]+', s.strip())
	assert(m != None)
	return m.group(0)


def create(name, transport):
	for cls in Application.registered():
		if name == cls.get_name():
			return cls(transport)
	return None


class Application:
	class Registered:
		pass


	@property
	def pid(self):
		return self.proc.pid


	def __init__(self, transport):
		self.transport = transport
		self.version = None
		self.mode = None
		self.repo = None
		self.proc = None


	def is_running(self):
		return self.proc.poll() == None


	def is_gbtcp(self):
		return self.transport != Transport.NATIVE


	def __del__(self):
		if self.repo != None and self.proc != None:
			self.stop()


	def get_version(self, repo):
		if self.version == None:
			self.version = self.system_get_version(repo)
		return self.version


	def create_netstat(self):
		if self.transport == Transport.NATIVE:
			return netstat.LinuxNetstat()
		else:
			return netstat.GbtcpNetstat()


	def read_netstat(self):
		if not self.proc:
			return None

		netstat = self.create_netstat()
		netstat.read(self) 
		return netstat


	def create_ifstat(self):
		if self.transport == Transport.NATIVE:
			return ifstat.LinuxIfstat()
		else:
			return ifstat.GbtcpIfstat()


	def read_ifstat(self):
		if not self.proc:
			return None

		ifstat = self.create_ifstat()
		if ifstat.read(self):
			return ifstat
		else:
			return None


	def configure_network(self, onoff, network, mode, concurrency, cpus):
		network.set_onoff_configure_routing(onoff)
		network.configure(mode, concurrency, len(cpus))


	def after_start(self, repo):
		self.repo = repo
		self.initial_netstat = self.create_netstat()
		if type(self.initial_netstat) == netstat.LinuxNetstat:
			self.initial_netstat = self.read_netstat()


	def before_stop(self):
		netstat = self.read_netstat()
		if netstat:
			self.netstat = netstat - self.initial_netstat
		self.repo = None


	def wait_process(self):
		if not self.proc:
			return -1, None
		res = wait_process(self.proc)
		self.proc = None
		return res


	def send_signal(self, signum):
		if self.proc:
			self.proc.send_signal(signum)


	@staticmethod
	def registered():
		return Application.Registered.__subclasses__()


class nginx(Application, Application.Registered):
	@staticmethod
	def get_name():
		return "nginx"


	@staticmethod
	def system_get_version(repo):
		s = system("nginx -v")[2]
		return parse_version(s)


	def stop(self):
		self.before_stop()
		system("nginx -s quit", LOG_INFO, True)
		return self.wait_process()


	def start(self, repo, network, mode, impl, concurrency, cpus):
		self.mode = mode

		if mode != Mode.SERVER:
			return False

		worker_cpu_affinity = ""

		n = len(cpus)
		assert(n > 0)

		self.configure_network(True, network, mode, concurrency, cpus)

		cpu_count = multiprocessing.cpu_count()
		templ = [ '0' for i in range(0, cpu_count) ]
		for i in cpus:
			templ[cpu_count - 1 - i] = '1'
			worker_cpu_affinity += " " + "".join(templ)
			templ[cpu_count - 1 - i] = '0'

		worker_connections = upper_pow2_32(concurrency)
		if worker_connections < 1024:
			worker_connections = 1024

		nginx_conf = (
			"user root;\n"
			"daemon off;\n"
			"master_process on;\n"
			"\n"
			"worker_processes %d;\n"
			"worker_cpu_affinity %s;\n"
			"worker_rlimit_nofile %d;\n"
			"events {\n"
			"	 use epoll;\n"
			"	 multi_accept on;\n"
			"	 worker_connections %d;\n"
			"}\n"
			"\n"
			"http {\n"
			"	 access_log off;\n"
			"	 tcp_nopush on;\n"
			"	 tcp_nodelay on;\n"
			"	 keepalive_timeout 65;\n"
			"	 types_hash_max_size 2048;\n"
			"	 reset_timedout_connection on;\n"
			"	 send_timeout 2;\n"
			"	 client_body_timeout 10;\n"
			"	 include /etc/nginx/conf.d/*.conf;\n"
			"	 server {\n"
			"		 listen %s:80 reuseport;\n"
			"		 server_name  _;\n"
			"		 location / {\n"
			"			 return 200 'Hello world!!!';\n"
			"		 }\n"
			"	 }\n"
			"}\n"
			% (n, worker_cpu_affinity, worker_connections, worker_connections, network.server))

		nginx_conf_path = repo.path + "/test/nginx.conf"

		with open(nginx_conf_path, 'w') as f:
			f.write(nginx_conf)

		cmd = "nginx -c %s" % nginx_conf_path
		self.proc = repo.start_process(cmd, network, mode, impl, self.transport)
		self.after_start(repo)
		return True


class gbtcp_base_helloworld(Application):
	def get_path(self, repo):
		return repo.path + "/bin/" + self.get_name()


	def system_get_version(self, repo):
		cmd = "%s -v" % self.get_path(repo)
		s = repo.system(cmd)[1]
		for line in s.splitlines():
			if line.startswith("version: "):
				return parse_version(line)
		assert(0)


	def stop(self):
		self.before_stop()
		self.send_signal(signal.SIGUSR1)
		return self.wait_process()


	def start(self, repo, network, mode, impl, concurrency, cpus):
		self.mode = mode
		self.repo = repo
		self.configure_network(True, network, mode, concurrency, cpus)

		cmd = self.get_path(repo)
		cmd += " -a "
		for i in range(len(cpus)):
			if i != 0:
				cmd += ","
			cmd += str(cpus[i])
		if mode == Mode.SERVER:
			cmd += " -l -C"
		else:
			cmd += " -c %d" % concurrency
			cmd += " " + str(network.server)

		self.proc = repo.start_process(cmd, network, mode, impl, self.transport)
		self.after_start(repo)
		return True


class gbtcp_epoll_helloworld(gbtcp_base_helloworld, Application.Registered):
	@staticmethod
	def get_name():
		return "gbtcp-epoll-helloworld"


class gbtcp_aio_helloworld(gbtcp_base_helloworld, Application.Registered):
	@staticmethod
	def get_name():
		return "gbtcp-aio-helloworld"


class con_gen(Application, Application.Registered):
	@staticmethod
	def get_name():
		return "con-gen"


	# TODO: Get real version
	@staticmethod
	def system_get_version(repo):
		return "1.0.2"


	def is_gbtcp(self):
		return False;


	def create_netstat(self):
		return netstat.CongenNetstat()


	def create_ifstat(self):
		return ifstat.CongenIfstat()


	def start(self, repo, network, mode, impl, concurrency, cpus):
		self.mode = mode
		self.configure_network(False, network, mode, concurrency, cpus)

		cmd = self.get_name()
		cmd += (" --print-report 0 -v -S %s -D %s -N -p 80" %
				(network.interface.mac, str(network.gw_mac)))

		if self.transport == Transport.NETMAP:
			cmd += " --netmap"
		elif self.transport == Transport.XDP:
			cmd += " --xdp"
		elif self.transport == Transport.NATIVE:
			cmd += " --pcap"
		else:
			assert(0)

		if mode == Mode.CLIENT:
			cmd += " -d %s" % network.server

			n_cpus = len(cpus)
			for i in range(n_cpus):
				concurrency_per_cpu = concurrency / n_cpus
				if i == 0:
					concurrency_per_cpu += concurrency % n_cpus
				else:
					cmd += " --"
				cmd += " -i %s-%d" % (network.interface.name, i)
				cmd += " -c %d" % concurrency_per_cpu
				cmd += " -a %d" % cpus[i]
				cmd += " -s %s-%s" % (network.clients[i][0], network.clients[i][1])
		else:
			cmd += (" -L -s %s -d %s-%s -c %d" % (
					network.server,
					network.first_client, network.last_client,
					concurrency * 2,
				))

			n_cpus = len(cpus)
			for i in range(n_cpus):
				if i != 0:
					cmd += " --"
				cmd += " -i %s-%d" % (network.interface.name, i)
				cmd += " -a %d" % cpus[i]


		self.proc = start_process(cmd)
		self.after_start(repo)
		return True


	def stop(self):
		self.before_stop()
		self.send_signal(signal.SIGINT)
		return self.wait_process()
