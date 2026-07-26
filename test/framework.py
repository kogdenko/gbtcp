# SPDX-License-Identifier: LGPL-2.1-only

import os
import time
import socket
import signal
import unittest
import git
import singleton
import gbtcp.config

from gbtcp.proto.gbtcp.kernel.cli_pb2 import CliCommandDump
from gbtcp.api import APIClient

from util import EnvVar, start_process, wait_process
from common import Mode, Transport


class Framework(unittest.TestCase):
    def get_tag(self, r):
        sha = r.head.commit.hexsha
        for tag in r.tags:
            if sha == tag.commit:
                return tag.name
        return sha[0:8]

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        self._config_path = singleton.rootdir + "/test/gbtcp.conf"

        r = git.Repo(search_parent_directories=True)
        self.tag = self.get_tag(r)
        changed = [item.a_path for item in r.index.diff(None)]
        self.changed = len(changed) > 0

    def _write_config(self, network, mode, impl, transport):
        config = ""
        if transport != None:
            config += "dev set transport %s\n" % transport.value

        if network != None:
            config += f"ip link add dev {network.interface.name}"
            if transport != None:
                config += f" io {transport.value}"
            config += "\n"
            config += network.config

        if impl != None:
            config += "socket set impl %s\n" % impl.value
        if mode != None and network != None:
            if mode == Mode.CLIENT:
                config += "arp add host %s hwaddr %s\n" % (network.server, network.gw_mac)
            else:
                config += "arp add host %s hwaddr %s\n" % (network.first_client, network.gw_mac)

        config += "module load name socket\n"

        with open(self._config_path, 'w') as f:
            f.write(config)

    def start_application(self, cmd, preload):
        e = os.environ.copy()
        e[EnvVar.LD_LIBRARY_PATH.value] = singleton.builddir
        if preload:
            e[EnvVar.LD_PRELOAD.value] = singleton.builddir + "/libgbtcp-preload.so"
        return start_process(cmd, e)

    def connect_to_gbtcpd(self):
        err = None
        for tries in range(0, 20):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.connect(gbtcp.config.GT_API_SOCK_PATH)
                sock.settimeout(2)
                return sock
            except Exception as e:
                time.sleep(0.1)
                err = e
        raise err

    def start_gbtcpd(self, network=None, mode=None, impl=None, transport=None):
        e = os.environ.copy()
        e[EnvVar.LD_LIBRARY_PATH.value] = singleton.builddir

        assert(transport != Transport.NATIVE)
        self._write_config(network, mode, impl, transport)
        e[EnvVar.GBTCP_CONF.value] = self._config_path 

        proc = start_process(singleton.builddir + "gbtcp-controller", e)

        # Wait for the server to start listening on the socket
        sock = self.connect_to_gbtcpd()
        sock.close()

        return proc

    @staticmethod
    def stop_gbtcpd(proc):
        proc.send_signal(signal.SIGTERM)
        wait_process(proc)

    def cli(self, s):
        api = APIClient()
        res = []

        rq = CliCommandDump()
        rq.input = s
        rp = api.exec(rq)
        for i in range(0, len(rp)):
            res.append(rp[i].output.rstrip())
        return res
