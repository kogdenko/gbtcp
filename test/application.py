#!/usr/bin/python
# SPDX-License-Identifier: LGPL-2.1-only

import multiprocessing
import platform
import re
import signal
import singleton
import time

from util import (
    start_process,
    wait_process,
    system,
    upper_pow2_32,
)
from common import (Transport, Mode)
from framework import Framework
import netstat
import ifstat

from network import LinuxNetwork, GbtcpNetwork, NoNetwork

class Application:
    class Registered:
        pass

    @staticmethod
    def create(name, network, transport):
        for cls in Application.registered():
            if name == cls.get_name():
                return cls(network, transport)
        return None

    @property
    def pid(self):
        return self.proc.pid

    def set_impl(self, impl):
        if self.transport != Transport.NATIVE:
            self.impl = impl

    def __init__(self, network, transport):
        self.transport = transport
        self.network = network
        self.version = None
        self.mode = None
        self.impl = None
        self.proc = None

    def is_running(self):
        return self.proc.poll() == None

    def is_gbtcp(self):
        return self.transport != Transport.NATIVE

    def __del__(self):
        if self.proc != None:
            self.stop()

    def get_version(self):
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

    def create_network(self):
        if self.transport == Transport.NATIVE:
            return LinuxNetwork(self.network)
        else:
            return GbtcpNetwork(self.network)

    def read_ifstat(self):
        if not self.proc:
            return None

        ifstat = self.create_ifstat()
        ifstat.read(self)
        return ifstat

    def configure_network(self, net, mode, concurrency, cpus):
        net.configure(mode, concurrency, len(cpus))

    def _start(self, cmd, framework=None, net=None, mode=None, impl=None):
        if framework == None:
            self.gbtcpd = None
            self.proc = start_process(cmd)
        else:
            preload = self.transport != Transport.NATIVE
            if preload:
                self.gbtcpd = framework.start_gbtcpd(net, mode, impl, self.transport)
                # FIXME:
                #time.sleep(1)
            self.proc = framework.start_application(cmd, preload)

        self.initial_netstat = self.create_netstat()
        if type(self.initial_netstat) == netstat.LinuxNetstat:
            self.initial_netstat = self.read_netstat()

    def stop(self):
        netstat = self.read_netstat()
        if netstat:
            self.netstat = netstat - self.initial_netstat
        if self.proc:
            self._stop()
            wait_process(self.proc)
            self.proc = None
        if self.gbtcpd:
            Framework.stop_gbtcpd(self.gbtcpd)
            self.gbtcpd = None

    def _stop(self):
        self.send_signal(signal.SIGTERM)

    def send_signal(self, signum):
        if self.proc:
            self.proc.send_signal(signum)

    @staticmethod
    def registered():
        return Application.Registered.__subclasses__()

class Repl(Application):
    def start(self, framework, mode, impl):
        net = self.create_network()
        self.configure_network(net, mode, 1, [1])
        cmd = singleton.rootdir + "/test/repl.py"
        self._start(cmd, framework, net, mode, impl)
        return True

class nginx(Application, Application.Registered):
    @staticmethod
    def get_name():
        return "nginx"

    def _stop(self):
        system("nginx -s quit", True)

    def start(self, framework, mode, impl, concurrency, cpus):
        self.mode = mode
        self.set_impl(impl)

        if mode != Mode.SERVER:
            return False

        worker_cpu_affinity = ""

        n = len(cpus)
        assert(n > 0)

        net = self.create_network()
        self.configure_network(net, mode, concurrency, cpus)

        cpu_count = multiprocessing.cpu_count()
        templ = [ '0' for i in range(0, cpu_count) ]
        for i in cpus:
            templ[cpu_count - 1 - i] = '1'
            worker_cpu_affinity += " " + "".join(templ)
            templ[cpu_count - 1 - i] = '0'

        worker_connections = upper_pow2_32(concurrency)
        if worker_connections < 1024:
            worker_connections = 1024

        nginx_conf = "" \
            "user root;\n" \
            "daemon off;\n" \
            "master_process on;\n" \
            "\n" \
            f"worker_processes {n};\n" \
            f"worker_cpu_affinity {worker_cpu_affinity};\n" \
            f"worker_rlimit_nofile {worker_connections};\n" \
            "events {\n"

        if platform.system() == 'Linux':
            nginx_conf += "    use epoll;\n"
        else:
            nginx_conf += "    use kqueue;\n"

        nginx_conf += f"" \
            "    multi_accept on;\n" \
            f"    worker_connections {worker_connections};\n" \
            "}\n" \
            "\n" \
            "http {\n" \
            "    access_log off;\n" \
            "    tcp_nopush on;\n" \
            "    tcp_nodelay on;\n" \
            "    keepalive_timeout 65;\n" \
            "    types_hash_max_size 2048;\n" \
            "    reset_timedout_connection on;\n" \
            "    send_timeout 2;\n" \
            "    client_body_timeout 10;\n" \
            "    include /etc/nginx/conf.d/*.conf;\n" \
            "    server {\n" \
            f"        listen {net.server}:80 reuseport;\n" \
            "        server_name  _;\n" \
            "        location / {\n" \
            "            return 200 'Hello world!!!';\n" \
            "        }\n" \
            "    }\n" \
            "}\n"

        nginx_conf_path = singleton.rootdir + "/test/nginx.conf"

        with open(nginx_conf_path, 'w') as f:
            f.write(nginx_conf)

        cmd = "nginx -c %s" % nginx_conf_path
        self._start(cmd, framework, net, mode, impl)
        return True

class gbtcp_base_helloworld(Application):
    # Run workers as threads (-t) instead of processes.
    use_threads = False

    def get_bin_name(self):
        return self.get_name()

    def _stop(self):
        self.send_signal(signal.SIGUSR1)

    def start(self, framework, mode, impl, concurrency, cpus):
        self.mode = mode
        self.set_impl(impl)

        net = self.create_network()
        self.configure_network(net, mode, concurrency, cpus)

        cmd = singleton.builddir + self.get_bin_name()
        cmd += " -a "
        for i in range(len(cpus)):
            if i != 0:
                cmd += ","
            cmd += str(cpus[i])
        if mode == Mode.SERVER:
            cmd += " -l -C"
        else:
            cmd += " -c %d" % concurrency
            cmd += " " + str(net.server)
        if self.use_threads:
            cmd += " -t"

        self._start(cmd, framework, net, mode, impl)
        return True

class gbtcp_epoll_helloworld(gbtcp_base_helloworld, Application.Registered):
    @staticmethod
    def get_name():
        return "gbtcp-epoll-helloworld"

class gbtcp_epoll_helloworld_thread(gbtcp_epoll_helloworld, Application.Registered):
    use_threads = True

    @staticmethod
    def get_name():
        return "gbtcp-epoll-helloworld-thread"

    def get_bin_name(self):
        return gbtcp_epoll_helloworld.get_name()

class gbtcp_aio_helloworld(gbtcp_base_helloworld, Application.Registered):
    @staticmethod
    def get_name():
        return "gbtcp-aio-helloworld"

class con_gen(Application, Application.Registered):
    @staticmethod
    def get_name():
        return "con-gen"

    def is_gbtcp(self):
        return False;

    def create_netstat(self):
        return netstat.CongenNetstat()

    def create_ifstat(self):
        return ifstat.CongenIfstat()

    def start(self, framework, mode, impl, concurrency, cpus):
        self.mode = mode
        net = NoNetwork(self.network)
        self.configure_network(net, mode, concurrency, cpus)

        cmd = self.get_name()
        cmd += (" --print-report 0 -v -S %s -D %s -N -p 80" %
                (net.interface.mac, str(net.gw_mac)))

        if self.transport == Transport.NETMAP:
            cmd += " --netmap"
        elif self.transport == Transport.XDP:
            cmd += " --xdp"
        elif self.transport == Transport.NATIVE:
            cmd += " --pcap"
        else:
            assert(0)

        if mode == Mode.CLIENT:
            cmd += " -d %s" % net.server

            n_cpus = len(cpus)
            for i in range(n_cpus):
                concurrency_per_cpu = concurrency / n_cpus
                if i == 0:
                    concurrency_per_cpu += concurrency % n_cpus
                else:
                    cmd += " --"
                cmd += f" -i {net.interface.name}"
                cmd += f" -q {i}"
                cmd += " -c %d" % concurrency_per_cpu
                cmd += " -a %d" % cpus[i]
                cmd += " -s %s-%s" % (net.clients[i][0], net.clients[i][1])
        else:
            cmd += (" -L -s %s -d %s-%s -c %d" % (
                    net.server,
                    net.first_client, net.last_client,
                    concurrency * 2,
                ))

            n_cpus = len(cpus)
            for i in range(n_cpus):
                if i != 0:
                    cmd += " --"
                cmd += f" -i {net.interface.name}"
                cmd += f" -q {i}"
                cmd += f" -a {cpus[i]}"

        self._start(cmd)
        return True
