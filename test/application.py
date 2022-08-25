#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import platform
import re

from common import *
from netstat import Netstat
from netstat import LinuxNetstat
from netstat import GbtcpNetstat


def parse_application_version(s):
    m = re.search(r'[0-9]+\.[0-9]+\.[0-9]+', s.strip())
    assert(m != None)
    return m.group(0)


class Application:
    class Registered:
        pass


    def __init__(self, gbtcp, network, transport, mode):
        self.gbtcp = gbtcp
        self.network = network
        self.transport = transport
        self.mode = mode
        self.version = None


    def get_version(self):
        if self.version == None:
            self.version = self.system_get_version()
        return self.version


    def __str__(self):
        return self.get_name() + "-" + self.get_version()


    def create_netstat(self):
        if self.transport == Transport.NATIVE:
            if platform.system() == 'Linux':
                return LinuxNetstat()
            else:
                assert(0)
        else:
            return GbtcpNetstat(self.gbtcp)


    @staticmethod
    def registered():
        return Application.Registered.__subclasses__()


    @staticmethod
    def create(name, gbtcp, network, transport, mode):
        for cls in Application.registered():
            if name == cls.get_name():
                return cls(gbtcp, network, transport, mode)
        return None


class nginx(Application, Application.Registered):
    @staticmethod
    def get_name():
        return "nginx"


    @staticmethod
    def system_get_version():
        s = system("nginx -v")[2]
        return parse_application_version(s)


    def stop(self):
        self.netstat = self.create_netstat()
        self.netstat.read()
        self.netstat = self.netstat - self.__netstat
        system("nginx -s quit", True)
        wait_process(self.__proc)


    def start(self, concurrency, cpus):
        worker_cpu_affinity = ""

        n = len(cpus)
        assert(n > 0)

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
            "    use epoll;\n"
            "    multi_accept on;\n"
            "    worker_connections %d;\n"
            "}\n"
            "\n"
            "http {\n"
            "    access_log off;\n"
            "    tcp_nopush on;\n"
            "    tcp_nodelay on;\n"
            "    keepalive_timeout 65;\n"
            "    types_hash_max_size 2048;\n"
            "    reset_timedout_connection on;\n"
            "    send_timeout 2;\n"
            "    client_body_timeout 10;\n"
            "    include /etc/nginx/conf.d/*.conf;\n"
            "    server {\n"
            "        listen %s:80 reuseport;\n"
            "        server_name  _;\n"
            "        location / {\n"
            "            return 200 'Hello world!!!';\n"
            "        }\n"
            "    }\n"
            "}\n"
            % (n, worker_cpu_affinity, worker_connections, worker_connections,
                self.network.server))

        nginx_conf_path = self.gbtcp.path + "/test/nginx.conf"

        with open(nginx_conf_path, 'w') as f:
            f.write(nginx_conf)

        self.__proc = self.gbtcp.start_process("nginx -c %s" % nginx_conf_path, self.transport)
        self.__netstat = self.create_netstat()
        self.__netstat.read()


class gbtcp_base_helloworld(Application):
    def get_path(self):
        return self.gbtcp.path + "/bin/" + self.get_name()


    def system_get_version(self):
        cmd = "%s -v" % self.get_path()
        s = self.gbtcp.system(cmd)[1]
        for line in s.splitlines():
            if line.startswith("version: "):
                return parse_application_version(line)
        assert(0)


    def stop(self):
        self.netstat = self.create_netstat()
        self.netstat.read()
        self.netstat = self.netstat - self.__netstat
        self.gbtcp.system("%s -S" % self.get_path(), True)
        wait_process(self.__proc)


    def start(self, concurrency, cpus):
        assert(self.mode == Mode.SERVER)
        cmd = "%s -l -a " % self.get_path()
        for i in range(len(cpus)):
            if i != 0:
                cmd += ","
            cmd += str(cpus[i])
        self.__proc = self.gbtcp.start_process(cmd, self.transport)
        self.__netstat = self.create_netstat()
        self.__netstat.read()


class gbtcp_epoll_helloworld(gbtcp_base_helloworld, Application.Registered):
    @staticmethod
    def get_name():
        return "gbtcp-epoll-helloworld"


class gbtcp_aio_helloworld(gbtcp_base_helloworld, Application.Registered):
    @staticmethod
    def get_name():
        return "gbtcp-aio-helloworld"


#class con_gen(Application):
#    @staticmethod
#    def get_name():
#        return "con-gen"
#
#
#    # TODO: Get real version
#    @staticmethod
#    def system_get_version():
#        return "1.0.2"
#
#
#    def start(self, concurrency, cpus):
#        assert(self.mode == Mode.CLIENT)
#        dst_ip = get_runner_ip(req.subnet)
#        cmd = self.get_name()
#        cmd += (" --print-report 0 -v -S %s -D %s --reports %d -N -p 80 -d %s" %
#            (self.interface.mac, str(req.dst_mac), req.duration, dst_ip))
#
#        n = len(self.tester.cpus)
#        for i in range(n):
#            concurrency_per_cpu = req.concurrency / n
#            if i == 0:
#                concurrency_per_cpu += req.concurrency % n
#            else:
#                cmd += " --"
#            cmd += " -i %s-%d" % (self.tester.interface.name, i)
#            cmd += " -c %d" % concurrency_per_cpu
#            cmd += " -a %d" % self.tester.cpus[i]
#            cmd += " -s %d.%d.%d.1-%d.%d.%d.255" % (
#                    req.subnet[0], req.subnet[1], i + 1,
#                    req.subnet[0], req.subnet[1], i + 1)
#        return start_process(cmd)
