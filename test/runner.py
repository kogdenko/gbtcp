#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import os
import sys
import time
import math
import atexit
import errno
import getopt
import socket
import subprocess
import platform
import importlib
import multiprocessing
import re

import numpy

from common import *
from database import Database
from application import Application

#FIXME:
from netstat import BsdNetstat


COOLING_MIN = 0
COOLING_MAX = 3*60
COOLING_DEFAULT = 20

g_subnet = (10, 20, 0, 0)

g_project = Project()
g_db = Database("")

class Simple:
    def __init__(self, name):
        self.name = name


    def get_name(self):
        return self.name


    def run(self):
        g_runner.ts_planned += 1
        proc = g_project.start_process(g_project.path + '/bin/' + self.name)
        if wait_process(proc)[0] == 0:
            g_runner.ts_pass += 1
            status = "Pass"
        else:
            g_runner.ts_failed += 1
            status = "Failed"
        print_log("%s ... %s" % (self.name, status), True)



class Runner:
    @staticmethod
    def add_test(d, test):
        d[test.get_name()] = test


    def print_test_statistics(self):
        print("Planned: ", self.ts_planned)
        print("Pass: ", self.ts_pass)
        print("Failed: ", self.ts_failed)


    def __init__(self): 
        self.ts_planned = 0
        self.ts_pass = 0
        self.ts_failed = 0

        self.os= platform.system() + "-" + platform.release()
        self.cpu_model = get_cpu_model()

        tests = {}
        for f in os.listdir(g_project.path + '/bin'):
            if f[:10] == "gbtcp-test":
                if os.path.isfile(g_project.path + '/test/' + f + '.pkt'):
                    #Runner.add_test(tests, Tcpkt(f))
                    pass
                else:
                    Runner.add_test(tests, Simple(f))

        # Assume that last test ended at least 10 seconds ago
        self.stop_ms = milliseconds() - 10000

        ap = argparse.ArgumentParser()

        argparse_add_reload_netmap(ap)
        argparse_add_cpu(ap);
        argparse_add_duration(ap, TEST_DURATION_DEFAULT)

        ap.add_argument("-i", metavar="interface", required=True, type=argparse_interface,
                help="")

        ap.add_argument("--dry-run", action='store_true',
                help="")

        ap.add_argument("--connect", metavar="ip", type=argparse_ip,
                help="")

        ap.add_argument("--sample", metavar="count", type=int,
                choices=range(TEST_SAMPLE_MIN, TEST_SAMPLE_MAX),
                default=TEST_SAMPLE_DEFAULT,
                help="")

        ap.add_argument("--cooling", metavar="seconds", type=int,
                choices=range(COOLING_MIN, COOLING_MAX),
                default=COOLING_DEFAULT,
                help="")

        ap.add_argument("--concurrency", metavar="num", type=int, nargs='+',
                action=UniqueAppendAction,
                default=[CONCURRENCY_DEFAULT],
                help="Number of parallel connections")

        ap.add_argument("--transport", metavar="name", type=Transport,
                help="")

        ap.add_argument("--test", metavar="name", type=str, nargs='+',
                choices = [ k for (k, v) in tests.items() ],
                help="")

        application_choices = [ a.get_name() for a in Application.registered() ]
        ap.add_argument("--application", metavar="name", type=str,
                choices = application_choices,
                help="")

        self.__args = ap.parse_args()
        self.concurrency = self.__args.concurrency
        self.dry_run = self.__args.dry_run
        self.duration = self.__args.duration
        self.sample = self.__args.sample
        self.interface = self.__args.i
        self.cpus = self.__args.cpu

        self.applications = []
        if self.__args.application:
            app = Application.create(self.__args.application, g_project,
                    self.__args.transport, Mode.SERVER)
            self.applications.append(app)

        for cpu in self.cpus:
            set_cpu_scaling_governor(cpu)

        if self.__args.reload_netmap:
            reload_netmap(self.__args.reload_netmap, self.interface)

        self.tests = []
        if self.__args.test:
            for test in self.__args.test:
                self.tests.append(tests[test])

        if self.__args.connect:
            self.__sock = socket.create_connection((make_ip(self.__args.connect), 9999))
        else:
            self.__sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.__sock.connect(SUN_PATH)
        self.__sock.settimeout(10)


    def stop(self):
        self.stop_mss = milliseconds()


    def cooling(self):
        ms = milliseconds() - self.stop_ms
        if ms < self.__args.cooling * 1000:
            t = int(math.ceil((self.__args.cooling * 1000 - ms) / 1000))
            time.sleep(t)


    def send_req(self, concurrency):
        req = ("--dst-mac %s "
                "--subnet %d.%d.0.0 "
                "--duration %d "
                "--concurrency %d "
                "--application con-gen\n\n" % (
                str(self.interface.mac),
                g_subnet[0], g_subnet[1],
                self.duration,
                concurrency))
        self.__sock.send(req.encode('utf-8'))


    def recv_msg(self):
        return recv_lines(self.__sock)

g_runner = Runner()


def print_report(test_id, sample, app, concurrency, cpu_usage):
    s = ""
    if sample != None:
        s += ("%d/%d: " % (test_id, sample.id))

    s += ("%s:%s: c=%d, CPU=%s" %
        (app.transport.value, app.get_name(), concurrency, str(cpu_usage)))

#    if sample != None:
#        pps = sample.results[Database.Sample.IPPS] + sample.results[Database.Sample.OPPS]
#        s += ", %.2f mpps" % (pps/1000000)
#        if False:
#            rxmtps = sample.results[Database.Sample.RXMTPS]
#            s += ", %.2f rxmtps" % (rxmtps/1000000)

    s += " ... "

    if sample == None:
        s += "Error"
    elif sample.runner_cpu_percent < 98:
        s += "Failed"
    else:
        s += "Passed"

    print_log(s, True)


def run_sample(app, test_id, concurrency, cpus):
    app.start(concurrency, cpus)

    # Wait netmap interface goes up
    time.sleep(2)
    g_runner.cooling()
    g_runner.send_req(concurrency)

    top = cpu_percent(g_runner.duration, cpus)

    reply = g_runner.recv_msg()
    if not reply:
        raise RuntimeError("Lost connection to tester")

    app.stop()
    g_runner.stop()

    sample = Database.Sample()
    sample.test_id = test_id
    sample.duration = g_runner.duration
    sample.runner_cpu_percent = int(numpy.mean(top))
    sample.tester_cpu_percent = 0

    if sample != None:
        g_db.insert_into_sample(sample)
        app.netstat.write(g_db, sample.id, Database.Role.RUNNER)
        netstat = BsdNetstat()
        netstat.parse(reply)
        app.netstat.write(g_db, sample.id, Database.Role.TESTER)
       

    print_report(test_id, sample, app, concurrency, top)

    if sample == None and sample.runner_cpu_percent < 98:
        g_runner.ts_failed += 1
    else:
        g_runner.ts_pass += 1


def run_application(app, cpus, concurrency):
    if g_runner.dry_run:
        test_id = None
        sample_count = 0
    else:
        if app.transport == Transport.NATIVE:
            commit = ""
        else:
            commit = g_project.commit

        cpu_mask = make_cpu_mask(cpus)
        test_id, sample_count = g_db.insert_into_test(
                g_runner.duration, 
                commit,
                g_runner.os,
                str(app),
                app.mode.value,
                app.transport.value,
                g_runner.interface.driver.value,
                g_runner.cpu_model,
                cpu_mask,
                "Osxxx",
                "con-genxxx",
                Transport.NETMAP.value,
                Driver.IXGBE.value,
                "ryzenxxxx",
                "000010000xxxx",
                concurrency,
                Connectivity.LOCAL.value)

    g_runner.ts_planned += g_runner.sample

    for j in range (0, g_runner.sample - sample_count):
        g_runner.interface.set_channels(cpus)
        run_sample(app, test_id, concurrency, cpus)



################ MAIN ####################


system("ip a flush dev %s" % g_runner.interface.name)
system("ip a a dev %s %s/32" % (g_runner.interface.name, get_runner_ip(g_subnet)))
system("ip r flush dev %s" % g_runner.interface.name)
system("ip r d %d.%d.1.1/32" % (g_subnet[0], g_subnet[1]), True)
system("ip r a dev %s %d.%d.1.1/32 initcwnd 1" %
    (g_runner.interface.name, g_subnet[0], g_subnet[1]))
system("ip r d %d.%d.0.0/15" % (g_subnet[0], g_subnet[1]), True)
system(("ip r a dev %s %d.%d.0.0/15 via %d.%d.1.1 initcwnd 1" %
    (g_runner.interface.name, g_subnet[0], g_subnet[1], g_subnet[0], g_subnet[1])))




g_project.set_interface(g_runner.interface)

for test in g_runner.tests:
    test.run()

for app in g_runner.applications:
    cpus = g_runner.cpus
    for concurrency in g_runner.concurrency:
        run_application(app, cpus, concurrency)
