#!/usr/bin/python

# SPDX-License-Identifier: LGPL-2.1-only

import sys
import getopt
import copy
import math
import numpy
import scipy
import matplotlib.pyplot as plot

from common import *
from database import Database


g_save = None
g_test_ids = []
g_y = "pps"
g_plot_xticks = []
g_plot_ymax = 0
g_graphs = []
g_show_fields = {}
g_db = Database("")

g_test_fields = []
for field in Database.test_fields:
	name = field[0]
	if name != "local_cpu_mask":
		g_test_fields.append(name)

class Graph:
	def __init__(self):
		self.fields = {}
		self.tests = {}


	def compare(self, test):
		global g_test_fields

		for field in g_test_fields:
			value = self.fields.get(field)
			test_value = getattr(test, field)
			if value != None:
				if value != test_value:
					return False
			else:
				self.fields[field] = test_value
		return True


def is_constant_field(name):
	global g_graphs

	value = None
	for graph in g_graphs:
		v = graph.fields.get(name)
		if value == None:
			value = v
		elif value != v:
			return False
	return True


def usage():
	print("analayzer.py [options]")
	print("\thelp: Print this help")
	print("\ttest-id {id,id..}: Specify test id")
	print("\tsample-id {id,id...}: Specify sample id")
	print("\tshow {commit}: Print all tests regarding to specified commit")
	print("\tshow {native}: Print all native tests")
	print("\tshow-plot: Show plot spicified by test-id or sample-id")
	print("\tsave-plot: Save plot spicified by test-id or sample-id")
	sys.exit(0)

def make_plot(x, y, error, legend, line_approximation):
	global g_plot_xticks
	global g_plot_ymax

	std = int(numpy.std(y))
	if error == None:
		error = [std] * len(y)
	if x == None:
		x = range(0, len(y))
	for i in range(0, len(y)):
		y[i] = y[i] / 1000000 
		error[i] = error[i] / 1000000

	g_plot_xticks += x
	p = plot.errorbar(x, y, error, label=legend)
	g_plot_ymax = max(g_plot_ymax, max(y))

	if line_approximation:
		x_array = numpy.array(x)
		y_array = numpy.array(y)
		# y = k*x + b
		# degree = 1
		kb = numpy.polyfit(x_array, y_array, 1)
		k = kb[0]
		b = kb[1]
		x0 = 0
		x1 = len(y) - 1
		y0 = k * x0 + b
		y1 = k * x1 + b
		mean = int(numpy.mean(y))
		mean, std = round_val(mean, std)
		outliers = find_outliers(y, error)
		print("mean=", mean, ", std=", std, ", outliers=", outliers)
		plot.plot([x0, x1], [y0, y1])


def parse_graph(argv):
	global g_graphs
	global g_test_fields

	graph = Graph()
	graph.id = len(g_graphs)
	if len(g_graphs) > 0:
		graph = copy.deepcopy(g_graphs[-1])

	ap = argparse.ArgumentParser()

	for field in g_test_fields:
		if len(g_graphs) == 0 and field == "tag":
			required = True
		else:
			required = False
		ap.add_argument("--%s" % field, metavar="str", type=str, required=required)

	for i in range(len(argv)):
		if argv[i] == "--":
			argv = argv[:i]
			break
	args = ap.parse_args(argv)

	for field in g_test_fields:
		value = getattr(args, field)
		if value != None:
			g_show_fields[field] = True
			graph.fields[field] = value

	g_graphs.append(graph)
		

def init_graph(graph):
	tests = g_db.get_tests(graph.fields["tag"])
	for test in tests:
		if not graph.compare(test):
			continue
		n_cpus = 0
		for cpu in test.local_cpu_mask:
			if cpu == '1':
				n_cpus += 1
		graph.tests[n_cpus] = test

	if len(graph.tests) == 0:
		die("No tests for graph %d" % graph.id)


def get_plot_title():
	global g_graphs
	global g_test_fields

	title = ""
	for field in g_test_fields:
		if is_constant_field(field) and g_show_fields.get(field):
			if len(title) > 0:
				title += "/"
			title += g_graphs[0].fields.get(field)
	return title


def get_graph_legend(graph):
	global g_grpahs
	global g_test_fields

	legend = ""
	for field in g_test_fields:
		if not is_constant_field(field):
			if len(legend) > 0:
				legend += "/"
			legend += graph.fields[field]
	return legend


### MAIN
try:
	opts, args = getopt.getopt(sys.argv[1:], "hy:", [
		"help",
		"save=",
		"test-id=",
		"hide=",
		])
except getopt.GetoptError as err:
	print(err)
	usage()
	sys.exit(1)
for o, a in opts:
	if o in ("-h", "--help"):
		usage()
		sys.exit(0)
	elif o in ("--save"):
		g_save = a
	elif o in ("--test-id"):
		for i in a.split(','):
			g_test_ids.append(int(i))
	elif o in ("--hide"):
#		for hide in a.split(','):
#			if hide in Database.Test.attrs:
#				if hide not in g_hide:
#					g_hide.append(hide)
		pass
	elif o in ("-y"):
		g_y = a


for i in range(1, len(sys.argv)):
	if sys.argv[i] == "--":
		parse_graph(sys.argv[i + 1:])

for graph in g_graphs:
	init_graph(graph)


def get_rep_payload(rep, name):
	if name == "pps":
		return rep.ipps + rep.opps
	else:
		assert(0)


if True:
	if len(g_test_ids) > 0:
		for test_id in g_test_ids:
			reps = g_db.get_reps(test_id)
			y = []
			e = []
			for rep in reps:
				data = get_rep_payload(rep, "pps")
				y.append(int(numpy.mean(data)))
				e.append(int(numpy.std(data)))
			make_plot(None, y, e, str(test_id), True)
	elif len(g_graphs) > 0:
		plot.title(get_plot_title())
		plot.xlabel("CPUs")
		for graph in g_graphs:
			x = []
			y = []
			e = []
			for n_cpus, test in graph.tests.items():
				reps = g_db.get_reps(test.id)
				data = []
				for rep in reps:
					data.append(get_rep_payload(rep, "pps"))
				x.append(n_cpus)
				y.append(int(numpy.mean(data)))
				e.append(int(numpy.std(data)))
			legend = get_graph_legend(graph)
			make_plot(x, y, e, legend, False)
	else:
		pass

	plot.xlim(min(g_plot_xticks), max(g_plot_xticks))
	plot.ylim(0, g_plot_ymax)

	plot.grid(linestyle = "dotted")
#	 plot.legend(loc='upper center')
	plot.xticks(g_plot_xticks)
	step = round(int(g_plot_ymax/10), -1)
	if step == 0:
		step = 1
	plot.yticks(range(0, math.ceil(g_plot_ymax) + step, step))
	plot.legend()
	plot.ylabel("m" + g_y)
	if g_save != None:
		plot.savefig(g_save)
	else:
		plot.show()
