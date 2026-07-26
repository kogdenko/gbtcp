#!/usr/bin/python
import os
import singleton

from parameterized import parameterized
from parameterized import parameterized_class

from common import *
from framework import Framework

class TestBin(Framework):
    @classmethod
    def setUpClass(self):
        pass
#        self.set_interface(Interface.create(singleton.tester_interface))

    @parameterized.expand([
        ["gbtcp-test-epoll-close-fd"],
        ["gbtcp-test-epoll-create"],
#        ["gbtcp-test-epoll-RDHUP"], # TODO: replace tcpkt with scapy
        ["gbtcp-test-fork"],
#        ["gbtcp-test-FP"], # TODO: replace tcpkt with scapy
        ["gbtcp-test-ioctl-FIONSPACE"],
#        ["gbtcp-test-slow-start"], # TODO: replace tcpkt with scapy
#        ["libgbtcp-test-dev"], # TODO: kill controller after test
#        ["libgbtcp-test-xdp"], # TODO: kill controller adter test
    ])
    def test_run(self, name):
        if name[0:3] == "lib":
            transports = [Transport.NATIVE]
        else:
            transports = [Transport.NETMAP, Transport.XDP]

        for transport in transports:
            cmd = singleton.builddir + name
            cmd += f" -i {singleton.tested_interface}"
            cmd += f" -p {singleton.tester_interface}"

            preload = transport != Transport.NATIVE
            if preload:
                gbtcpd = self.start_gbtcpd(None, None, None, transport)
            proc = self.start_application(cmd, preload)
            self.assertEqual(wait_process(proc), 0)
            if preload:
                self.stop_gbtcpd(gbtcpd)
