# SPDX-License-Identifier: LGPL-2.1-only

import sys
import xml.etree.ElementTree as ET

from getmac import get_mac_address

from util import (system,
    Enum
)

class _Driver(Enum):
    EPAIR = "epair"

def _is_thread_group(node):
    if node.tag != 'group':
        return False
    for c in node:
        if c.tag == 'flags':
            for flag in c:
                if flag.attrib['name'] == 'THREAD':
                    return True
    return False

def _collect_cpus(node, cpus):
    if _is_thread_group(node):
        for c in node:
            if c.tag == 'cpu':
                tmp = [int(part.strip()) for part in c.text.split(',')]
                cpus.append(tmp[0])
    else:
        for c in node:
            _collect_cpus(c, cpus)

def get_cpus():
    xml = system("sysctl -n kern.sched.topology_spec")[1]
    root = ET.fromstring(xml)
    cpus = []
    _collect_cpus(root, cpus)
    return cpus

class EpairInterface:
    def __init__(self):
        self.is_paired = True
        self.driver = _Driver.EPAIR

    def set_channels(self, cpus):
        if len(cpus) != 1:
            raise RuntimeError("Epair interface do not support RSS")

class Interface:
    is_paired = False

    @staticmethod
    def create(name):
        if name.startswith('epair'):
            interface = EpairInterface()
        else:
            raise RuntimeError(f"The '{name}' interface is not supported")

        interface.name = name
        interface.mac = get_mac_address(interface=name)
        return interface
