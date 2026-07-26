import singleton

from gbtcp.api import APIClient
from gbtcp.proto.gbtcp.kernel.ip_pb2 import IpLinkAdd, IpLinkDump

from framework import Framework

class TestIp(Framework):
    def setUp(self):
        self.gbtcpd = self.start_gbtcpd()

    def tearDown(self):
        self.stop_gbtcpd(self.gbtcpd)

    def test_ip_link(self):
        api = APIClient();

        rq = IpLinkAdd()
        rq.dev = singleton.tested_interface
        api.exec(rq)

        rq = IpLinkDump()
        rp = api.exec(rq)
        self.assertEqual(len(rp), 1)
