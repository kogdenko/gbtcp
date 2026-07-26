# SPDX-License-Identifier: LGPL-2.1-only

import multiprocessing

from util import (
    Enum,
    system
)

class _Driver(Enum):
    VETH = "veth"
    IXGBE = "ixgbe"
    ICE = "ice"
    MLX5 = "mlx5"

def _get_interface_driver(name):
    cmd = f"ethtool -i {name}"
    rc, out, _ = system(cmd)
    for line in out.splitlines():
        if line.startswith("driver: "):
            return line[8:].strip()
    raise RuntimeError(f"Invalid ethtool driver: '{name}'")

def _set_irq_affinity(interface, cpus):
    return
    with open("/proc/interrupts", 'r') as f:
        lines = f.readlines()

    irqs = []

    p = re.compile(".*%s-TxRx-[0-9]*$" % interface)
    for i in range(1, len(lines)):       
        columns = lines[i].split()
        for column in columns:
            m = re.match(p, column.strip())
            if m != None:
                irq = columns[0].strip(" :")
                if not irq.isdigit():
                    raise RuntimeError(f"Invalid irq: /proc/interrupts:{i + 1}")
                irqs.append(int(irq))

    if len(cpus) != len(irqs):
        raise RuntimeError(f"Invalid number of irqs: {len(irqs)}")

    for i in range(0, len(irqs)):
        with open("/proc/irq/%d/smp_affinity" % irqs[i], 'w') as f:
            f.write("%x" % (1 << cpus[i]))



def get_cpus():
    proc = None
    cpus = {}

    with open("/proc/cpuinfo") as f:
        lines = f.readlines()
        for line in lines:
            tmp = [ i.strip() for i in line.split(':')]
            if len(tmp) != 2:
                continue;
            if tmp[0] == "processor":
                assert(not proc)
                proc = int(tmp[1])
            if tmp[0] == "core id":
                assert(proc != None)
                core_id = tmp[1]
                if not cpus.get(core_id):
                    cpus[core_id] = proc
                proc = None
    return list(cpus.values())

def set_cpu_scaling_governor(cpu):
    assert(cpu < multiprocessing.cpu_count())
    path = "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor" % cpu
    with open(path, 'w') as f:
        f.write("performance")

class Interface:
    is_paired = False
    @staticmethod
    def create(name):
        driver_name = _get_interface_driver(name)
        driver = None
        for d in _Driver:
            if driver_name.startswith(d.value):
                driver = d
                break

        if driver == None:
            raise RuntimeError(f"Unknown driver: `{driver_name}`")

        for instance in Interface.__subclasses__():
            if driver in instance.supported_drivers:
                interface = instance(name, driver)
                return interface
        raise RuntimeError(f"Driver {driver} is not supported")

    def __init__(self, name, driver):
        self.driver = driver
        self.name = name
        with open("/sys/class/net/%s/address" % name) as f:
            self.mac = f.read().strip()
        self.up()

    def up(self):
        system("ip l s dev %s up" % self.name)

class ixgbe(Interface):
    supported_drivers = [ _Driver.IXGBE, _Driver.ICE, _Driver.MLX5 ]

    def __init__(self, name, driver):
        Interface.__init__(self, name, driver)
        system("ethtool -K %s rx off tx off" % name)
        system("ethtool -K %s gso off" % name)
        system("ethtool -K %s ntuple on" % name)
        system("ethtool -N %s rx-flow-hash tcp4 sdfn" % name)
        system("ethtool -N %s rx-flow-hash udp4 sdfn" % name)
        system("ethtool -G %s rx 2048 tx 2048" % name)

    def set_channels(self, cpus):
        system("ethtool -L %s combined %d" % (self.name, len(cpus)))
        _set_irq_affinity(self.name, cpus)

class veth(Interface):
    is_paired = True
    supported_drivers = [ _Driver.VETH ]

    def __init__(self, name, driver):
        Interface.__init__(self, name, driver)
        system("ethtool -K %s rx off tx off" % name)
        system("ethtool -K %s gso off" % name)
#       system("ethtool -N %s rx-flow-hash tcp4 sdfn" % name)
#       system("ethtool -N %s rx-flow-hash udp4 sdfn" % name)

    def set_channels(self, cpus):
        n_cpus = len(cpus)
        system("ethtool -L %s rx %d tx %d" % (self.name, n_cpus, n_cpus))
