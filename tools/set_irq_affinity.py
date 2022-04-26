#!/usr/bin/python
import sys
import getopt
import re

first_core = 0
interface = None
verbose = 0
dry_run = False

def usage():
	print("set_irq_affinity.py {-i INTERFACE} [--dry-run] [-c core] [-hv]")

try:
    opts, args = getopt.getopt(sys.argv[1:], "hvi:c:",["dry-run"])
except getopt.GetoptError as err:
    print(err)
    sys.exit(1)

for o, a in opts:
    if o in ("-i"):
        interface = a
    elif o in ("-h"):
        usage()
        sys.exit(0)
    elif o in ("-v"):
        verbose += 1
    elif o in ("--dru-run"):
        dry_run = True
    elif o in ("-c"):
        first_core = int(a)

if interface == None:
	usage()
	sys.exit(1)

f = open("/proc/interrupts", 'r')
lines = f.readlines()
f.close()
irqs = []
p = re.compile("^%s-TxRx-[0-9]*$" % interface)
for i in range (1, len(lines)):       
    columns = lines[i].split()
    for col in columns:
        m = re.match(p, col.strip())
        if m != None:
            irq = columns[0].strip(" :")
            if not irq.isdigit():
                print("/proc/interrupts:%d: Invalid irq" % i + 1)
                sys.exit(1)
            irqs.append(int(irq))
if verbose > 1:
    print("irqs=", irqs)
for i in range(0, len(irqs)):
    f = open("/proc/irq/%d/smp_affinity" % irqs[i], 'w+')
    affinity = 1 << (first_core + i)
    if verbose > 0:
        lines = f.readlines()
        assert(len(lines) > 0)
        old_affinity = lines[0].strip()
        print("irq %d, affinity 0x%s->0x%08x" % (irqs[i], old_affinity, affinity))
    if not dry_run:
        f.write("%x" % affinity)
    f.close()
sys.exit(0)
