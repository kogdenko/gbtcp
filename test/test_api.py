#!/usr/bin/python

import socket
import struct
import time

from gbtcp.api import APIClient
from gbtcp.proto.gbtcp.kernel.api_pb2 import ApiEcho, ApiEchoDump
from gbtcp.proto.gbtcp.kernel.cli_pb2 import CliCommandDump

from util import wait_process
from framework import Framework

class TestApi(Framework):
    def setUp(self):
        self.gbtcpd = self.start_gbtcpd()

    def tearDown(self):
        self.stop_gbtcpd(self.gbtcpd)

    def test_01_echo(self):
        api = APIClient()
        rq = ApiEcho()
        rq.data = "hello"
        rp = api.exec(rq)
        self.assertEqual(rp.data, rq.data) 

    def test_02_dump(self):
        api = APIClient()

        rq = ApiEchoDump()

        # Reply is bigger than connection buffer
        rq.data = '*' * 1024
        rq.n_details = 1024
        rp = api.exec(rq)
        self.assertEqual(len(rp), rq.n_details)

        # Empty details
        rq.data = ''
        rq.n_details = 10
        rp = api.exec(rq)
        self.assertEqual(len(rp), rq.n_details)

    def test_03_truncated_msg(self):
        sock = self.connect_to_gbtcpd()
        sock.settimeout(0.2)

        echo = ApiEcho()
        echo.data = "hello"
        data = echo.SerializeToString()

        rq = struct.pack('>IHH', len(data), APIClient.MSG_REQUEST, 0)
        sock.sendall(rq)
        with self.assertRaises(TimeoutError):
            sock.recv(4096)

        sock.sendall("ApiEcho".encode() + b'\x00')
        with self.assertRaises(TimeoutError):
            sock.recv(4096)

        sock.sendall(data)
        buf = sock.recv(4096)
        self.assertGreaterEqual(len(buf), 8)
        _, _, code = struct.unpack('>IHH', buf[0:8])
        self.assertEqual(code, 0)

    def test_04_cli(self):
        api = APIClient()
        data = "AAAA"

        rq = CliCommandDump()
        rq.input = f"test echo data {data} n 2"
        rp = api.exec(rq)
        self.assertEqual(len(rp), 2)
        for i in range(0, 2):
            self.assertEqual(rp[i].output.strip(), data)

    def test_05_cli(self):
        data = "BBBB"
        n = 3
        res = self.cli(f"test echo data {data} n {n}")
        self.assertEqual(len(res), n)
        for i in range(0, n):
            self.assertEqual(res[i].strip(), data)
