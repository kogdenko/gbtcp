#!/bin/python
import sys

def usage():
	print('Usage set_irq_affinity.py {irq} {cpu} {number of irqs}')

if len(sys.argv) != 4:
	print("Invalid number of arguments")
	usage()
	sys.exit(1)
irq = int(sys.argv[1])
cpu = int(sys.argv[2])
N = int(sys.argv[3])
if N < 1:
	print("Invalid number of irqs")
	usage()
	sys.exit(2)
for i in range(0, N):
	mask = 1 << (cpu + i)
	affinity = "%x"%mask
	filename = "/proc/irq/%d/smp_affinity"%irq
	try:
		f = open(filename, "w")
		f.write(affinity)
		f.close()
	except IOError:
		print("'echo %s > %s' failed"%(affinity, filename))
	else:
		irq += 1
