#!/usr/bin/python
# SPDX-License-Identifier: LGPL-2.1-only

# TODO:
# - CPS, RTPS, BPS
# - Analyze new commit
import os
import sys
import time
import math
import psutil
import errno
import socket
import subprocess
import syslog
from enum import Enum

import singleton

import numpy

from util import (
    log_error,
    monotonic_ms,
    kmgt
)
from common import (Transport,
    Impl,
    Interface,
    Mode,
    Top,
    set_cpus_scaling_governor
)
from framework import Framework

from database import Database
from application import Application
import application
from netstat import Netstat
from network import Network
from e2e_server import E2eServer

import gbtcp.config

class TestCase(Framework):
    nginx = application.nginx.get_name()
    con_gen = application.con_gen.get_name()
    epoll_helloworld = application.gbtcp_epoll_helloworld.get_name()
    epoll_helloworld_thread = application.gbtcp_epoll_helloworld_thread.get_name()
    aio_helloworld = application.gbtcp_aio_helloworld.get_name()

    def __init__(self, *args, **kwargs):
        super().__init__(*args,  **kwargs)

    @classmethod
    def setUpClass(self):
        if singleton.use_database:
            try:
                self.database = Database()
            except Exception as ex:
                log_error(ex, "Couldn't connect to database")
                self.database = None
        else:
            self.database = None

    @classmethod
    def tearDownClass(self):
        del self.database
        self.database = None

    def setUp(self):
        tags = []
        if "e2e" not in singleton.tags:
            self.skipTest("Tag `e2e` not specified")

        if "xdp" in singleton.tags:
            if gbtcp.config.GT_HAVE_XDP == 0:
                self.skipTest("Compiled without `XDP`")
            self.tested_transport = Transport.XDP
        else:
            if gbtcp.config.GT_HAVE_NETMAP == 0:
                self.skipTest("Compiled without `netmap`")
            self.tested_transport = Transport.NETMAP

        if "bsd44" in singleton.tags:
            tags.append("bsd44")
            if gbtcp.config.GT_HAVE_BSD44 == 0:
                self.skipTest("Compiled without `4.4BSD`")
            self.impl = Impl.BSD44
        else:
            self.impl = Impl.GBTCP

        if "fast" in singleton.tags:
            tags.append("fast")
            self.fast = True
        else:
            self.fast = False

        self.cpu_scaling = "cpu-scaling" in singleton.tags

        self.tags = ','.join(tags)

        interface = Interface.create(singleton.tested_interface)

        # Assume that last test ended at least 10 seconds ago
        self.start_cooling_time = monotonic_ms() - 10000

        self.cpus = []
        self.interface = interface
        self.network = Network()
        self.network.set_interface(self.interface)

        ip_network = "10.10.0.0/16"

        self.network.set_ip_network(ip_network)

        if singleton.tester_address:
            self.server = E2eServer.create_remote(singleton.tester_address)
        else:
            interface = Interface.create(singleton.tester_interface)
            self.server = E2eServer.create_local(interface, singleton.tester_cpus)

        self.server.set_parameters(ip_network, self.interface.mac)

        mac = self.server.get_mac()
        self.network.set_gw_mac(mac)

        set_cpus_scaling_governor(singleton.tested_cpus)

    def start_cooling(self):
        self.start_cooling_time = monotonic_ms()

    def do_cooling(self):
        ms = monotonic_ms() - self.start_cooling_time
        if ms < self.cooling * 1000:
            t = int(math.ceil((self.cooling * 1000 - ms) / 1000))
            time.sleep(t)

    def _start_tested(self, app, cpus):
        s = app.start(self, self.mode, self.impl, self.concurrency, cpus)
        assert(s)

    def _run(self):
        cpus = singleton.tested_cpus[0:self.n_cpus]

        tested = Application.create(self.tested, self.network, self.tested_transport)

        if tested.transport == Transport.NATIVE:
            tag = ""
            use_databse = True
        else:
            tag = self.tag
            use_database = not self.changed

        self.interface.set_channels(cpus)

        self.do_cooling()

        if self.mode == Mode.SERVER:
            self._start_tested(tested, cpus)
            # Wait until tested network interface is up
            time.sleep(2)

        if self.mode == Mode.SERVER:
            tester_mode = Mode.CLIENT
        else:
            tester_mode = Mode.SERVER

        self.server.start(self.n_cpus, self.concurrency, self.tester_transport, self.tester, tester_mode)

        if self.mode == Mode.CLIENT:
            # Wait until tester network interface is up
            time.sleep(2)
            self._start_tested(tested, cpus)

        top = Top(cpus, self.duration - 2)
        self.server.process(self.duration - 2)
        top.join()
        self.start_cooling()

        if self.mode == Mode.CLIENT:
            tested.stop()

        pps, bps, cps, tester_netstat = self.server.stop()

        if self.mode != Mode.CLIENT:
            tested.stop()

        self.assertTrue(pps != None)

        load = int(numpy.mean(top.load))

        tested_netstat = tested.netstat

        test_name = self._testMethodName.split("_")
        test = '_'.join(test_name[1:])
        if tested.transport == Transport.NATIVE:
            driver = self.interface.driver.value
        else: 
            driver = tested.transport.value + "-" + self.interface.driver.value
        cpus = len(cpus)

        if self.database != None and use_database:
            test_id = self.database.insert_into_test(self.tags, test, tag, driver, cpus, load, pps, bps)

            tested_netstat.insert_into_database(self.database, test_id, True)
            tester_netstat.insert_into_database(self.database, test_id, False) 

        s = f"{cpus}cpu: {kmgt(pps)}pps"

        if singleton.baseline and self.database:
            res = self.database.select_pps_from_test(self.tags, test, singleton.baseline, driver, cpus)
            if res != None:
                b_pps = res[0]
                s += "("
                if pps > b_pps:
                    s += "+"
                else:
                    s += "-"
                s += "%.2f%%" % (abs(pps - b_pps)/min(pps, b_pps)*100)
#                s += f" {pps}~{b_pps}"
                s += ")"
        s += f" {kmgt(bps)}bps {kmgt(cps)}cps; "

        sys.stdout.write(s)
        sys.stdout.flush()

        return pps

    def _test(self, mode, app):
        self.tester = self.con_gen

        if self.interface.is_paired or self.tested_transport != Transport.NATIVE:
            self.tester_transport = self.tested_transport
        else:
            self.tester_transport = Transport.NETMAP

        self.mode = mode
        self.tested = app

        if self.fast:
            self.cooling = 10
            self.duration = 10
        else:
            self.cooling = 30
            self.duration = 30

        if self.cpu_scaling:
            n_cpus = range(1, len(singleton.tested_cpus) + 1)
        else:
            n_cpus = [len(singleton.tested_cpus)]

        prev_pps = 0

        for self.n_cpus in n_cpus:
            self.concurrency = 3000 * self.n_cpus

            pps = self._run()
            self.assertGreater(pps, 100000)

            if abs(pps - prev_pps) / pps < 0.05:
                break
            prev_pps = pps

    def test_congen(self):
        if "infra" not in singleton.tags:
            self.skipTest("Tag `infra` not specified")

        self._test(Mode.CLIENT, self.con_gen)
        return        

    def test_nginx(self):
        self._test(Mode.SERVER, self.nginx)

    def test_server_epoll(self):
        self._test(Mode.SERVER, self.epoll_helloworld)

    def test_server_epoll_threads(self):
        self._test(Mode.SERVER, self.epoll_helloworld_thread)

    def test_client_epoll(self):
        self._test(Mode.CLIENT, self.epoll_helloworld)

    def test_server_aio(self):
        self._test(Mode.SERVER, self.aio_helloworld)

    # TODO: repair test
    #def test_client_aio(self):
    #    self._test_fast(Mode.CLIENT, self.aio_helloworld)
