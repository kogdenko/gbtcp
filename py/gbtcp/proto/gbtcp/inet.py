#!/usr/bin/python

import socket
import struct

from gbtcp.proto.gbtcp.kernel import inet_pb2
from ipaddress import ip_address

# ip4_address
@staticmethod
def pb2_ip4_address_init(self, ip=ip_address("0.0.0.0")):
    self.ip4_u32 = ip.packed

@staticmethod
def pb2_ip4_address_from_string(cls, s):
    ip = ip_address(s)
    return cls(ip)

def pb2_ip4_address_to_string(self):
    packed = struct.pack('I', self.ip4_u32)
    return socket.inet_ntoa(packed)

inet_pb2.ip4_address.__init__ = pb2_ip4_address_init
inet_pb2.ip4_address.from_string = pb2_ip4_address_from_string
inet_pb2.ip4_address.to_string = pb2_ip4_address_to_string

# eth_address
def pb2_eth_address_to_string(self):
    print(self.eth_bytes)
    if len(self.eth_bytes) == 6:
        return ':'.join(f'{b:02x}' for b in self.eth_bytes)
    else:
        return str(self.eth_bytes)

inet_pb2.eth_address.to_string = pb2_eth_address_to_string
