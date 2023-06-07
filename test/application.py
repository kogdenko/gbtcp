#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import platform
import re
import signal

from common import *
import netstat
import ifstat


def parse_version(s):
    m = re.search(r'[0-9]+\.[0-9]+\.[0-9]+', s.strip())
    assert(m != None)
    return m.group(0)


class Application:
    class Registered:
        pass


    @property
    def pid(self):
        return self.proc.pid


    def __init__(self, repo, network, mode, transport=None):
        self.repo = repo
        self.network = network
        self.transport = transport
        self.mode = mode
        self.version = None


    def __del__(self):
        self.stop()


    def get_version(self):
        if self.version == None:
            self.version = self.system_get_version()
        return self.version


    def __str__(self):
        return self.get_name() + "-" + self.get_version()


    def create_netstat(self):
        if self.transport == Transport.NATIVE:
            if platform.system() == 'Linux':
                return netstat.LinuxNetstat()
            else:
                assert(0)
        else:
            return netstat.GbtcpNetstat(self.repo)


    def create_ifstat(self):
        if self.transport == Transport.NATIVE:
            if platform.system() == 'Linux':
                return ifstat.LinuxIfstat(self.network.interface)
            else:
                assert(0)
        else:
            return ifstat.GbtcpIfstat(self.network.interface)


    def configure_network(self, onoff_configure_routing, concurrency, cpus):
        self.network.set_onoff_configure_routing(onoff_configure_routing)
        self.network.configure(self.mode, concurrency, len(cpus))


    def before_stop(self):
        current = self.create_netstat()
        current.read()
        self.netstat = current - self.netstat


    @staticmethod
    def registered():
        return Application.Registered.__subclasses__()


    @staticmethod
    def create(name, repo, network, mode, transport=None):
        for cls in Application.registered():
            if name == cls.get_name():
                return cls(repo, network, mode, transport)
        return None


class nginx(Application, Application.Registered):
    @staticmethod
    def get_name():
        return "nginx"


    @staticmethod
    def system_get_version():
        s = system("nginx -v")[2]
        return parse_version(s)


    def stop(self):
        self.before_stop()
        system("nginx -s quit", True)
        return wait_process(self.proc)


    def start(self, concurrency, cpus):
        worker_cpu_affinity = ""

        n = len(cpus)
        assert(n > 0)

        self.configure_network(True, concurrency, cpus)

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

        nginx_conf_path = self.repo.path + "/test/nginx.conf"

        with open(nginx_conf_path, 'w') as f:
            f.write(nginx_conf)

        cmd = "nginx -c %s" % nginx_conf_path
        self.proc = self.repo.start_process(cmd, self.network, self.mode, self.transport)


class gbtcp_base_helloworld(Application):
    def get_path(self):
        return self.repo.path + "/bin/" + self.get_name()


    def system_get_version(self):
        cmd = "%s -v" % self.get_path()
        s = self.repo.system(cmd)[1]
        for line in s.splitlines():
            if line.startswith("version: "):
                return parse_version(line)
        assert(0)


    def stop(self):
        self.before_stop()
        self.repo.system("%s -S" % self.get_path(), True)
        return wait_process(self.proc)


    def start(self, concurrency, cpus):
        assert(self.mode == Mode.SERVER)

        self.configure_network(True, concurrency, cpus)

        cmd = "%s -l -a " % self.get_path()
        for i in range(len(cpus)):
            if i != 0:
                cmd += ","
            cmd += str(cpus[i])
        self.proc = self.repo.start_process(cmd, self.network, self.mode, self.transport)


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
    def system_get_version():
        return "1.0.2"


    def create_ifstat(self):
        return ifstat.CongenIfstat(self.network.interface, self.proc.pid)


    def start(self, concurrency, cpus):

        self.configure_network(False, concurrency, cpus)

        cmd = self.get_name()
        cmd += (" --print-report 0 -v -S %s -D %s -N -p 80" %
            (self.network.interface.mac, str(self.network.gw_mac)))

        if self.mode == Mode.CLIENT:
            cmd += " -d %s" % self.network.server

            n_cpus = len(cpus)
            for i in range(n_cpus):
                concurrency_per_cpu = concurrency / n_cpus
                if i == 0:
                    concurrency_per_cpu += concurrency % n_cpus
                else:
                    cmd += " --"
                cmd += " -i %s-%d" % (self.network.interface.name, i)
                cmd += " -c %d" % concurrency_per_cpu
                cmd += " -a %d" % cpus[i]
                cmd += " -s %s-%s" % (
                        self.network.clients[i][0],
                        self.network.clients[i][1])
        else:
            assert(0)

        self.proc = start_process(cmd)


    def stop(self):
        self.before_stop()
        self.proc.send_signal(signal.SIGINT)
        return wait_process(self.proc)
