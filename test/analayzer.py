#!/usr/bin/python

import sys
import getopt
import math
import numpy
import scipy
import matplotlib.pyplot as plot
from common import *

class Graph:
    attrs = [ "version", "os", "app", "cpu_model", "driver", "concurrency" ]

    def is_same(a, graphs):
        value = None
        for graph in graphs:
            v = getattr(graph, a)
            if value == None:
                value = v
            elif value != v:
                return False
        return True

    def __init__(self):
        self.version = None
        self.tests = {}
        self.os = None
        self.os_id = None
        self.app = None
        self.app_id = None
        self.cpu_model = None
        self.cpu_model_id = None
        self.driver = None
        self.concurrency = None

    def compare(self, test):
        for a in [ "os", "app", "cpu_model" ]:
            graph_a_id = getattr(self, a + "_id")
            graph_a = getattr(self, a)
            test_a_id = getattr(test, a + "_id")
            test_a = getattr(test, a)
            if graph_a_id == None:
                if graph_a == None or test_a.find(graph_a) >= 0:
                    if graph_a == None:
                        setattr(self, a, test_a)
                    setattr(self, a + "_id", test_a_id)
                else:
                    return False
            elif graph_a_id != test_a_id:
                return False
        for a in [ "driver", "concurrency" ]:
            graph_a = getattr(self, a)
            test_a = getattr(test, a)
            if graph_a == None:
                setattr(self, a, test_a)
            elif graph_a != test_a:
                return False
        return True

g_show_plot = False
g_save_plot = None
g_sample_ids = []
g_test_ids = []
g_skip_reports = 2
g_record = PPS
g_show = None
g_clean_test = False
g_plot_xticks = []
g_plot_ymax = 0
g_graphs = []
env = Environment()

def usage():
    print("analayzer.py [options]")
    print("\thelp: Print this help")
    print("\ttest-id {id,id..}: Specify test id")
    print("\tsample-id {id,id...}: Specify sample id")
    print("\tskip-reports {num}: Skip first num reports (default: %d)" % g_skip_reports)
    print("\tshow {version}: Print all tests regarding to specified version")
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
        outliers, angle = find_outliers(y, error)
        print("mean=%d, std=%d (%.2f%%), angle=%.2f%%, outliers=" %
            (mean, std, round(std/mean*100, 2), round(angle, 2)), outliers)
        plot.plot([x0, x1], [y0, y1])

def get_sample(env, sample_id):
    sample = env.get_sample(sample_id) 
    if sample == None:
        die("No sample with id=%d" % sample_id)
    return sample

def get_sample_record1(sample):
    return get_sample_record(sample, g_record)[g_skip_reports:]

def resolve_test(test):
    res = True
    name, ver = env.get_app(test.app_id)
    if name == None:
        print("Test %d has invalid application id %d" % (test.id, test.app_id))
        res = False
    else:
        test.app = name + "-" + ver

    name, ver = env.get_os(test.os_id)
    if name == None:
        print("Test %d has invalid OS id" % (test.id, test.os_id))
        res = False
    else:
        test.os = name + "-" + ver

    name, alias = env.get_cpu_model(test.cpu_model_id)
    if name == None:
        print("Test %d has invalid cpu_model id %d" % (test.id, test.cpu_model_id))
        res = False
    else:
        if alias == None or len(alias) == 0:
            test.cpu_model = name
        else:
            test.cpu_model = alias

    test.driver = get_driver_name(test.driver_id)

    return res

def parse_graph(argv):
    graph = Graph()
    graph.id = len(g_graphs)
    if len(g_graphs) > 0:
        template = g_graphs[-1]
        for a in Graph.attrs:
            setattr(graph, a, getattr(template, a))
    g_graphs.append(graph)
    try:
        opts, args = getopt.getopt(argv, "", [
            "version=",
            "os=",
            "app=",
            "cpu-model=",
            "driver=",
            "concurrency=",
            ])
    except getopt.GetoptError as err:
        print(err)
        die("Invalid graph options")
    for o, a in opts:
        if o in ("--version"):
            graph.version = a
        elif o in ("--os"):
            graph.os = a
        elif o in ("--app"):
            graph.app = a
        elif o in ("--cpu-model"):
            graph.cpu_model = a
        elif o in ("--driver"):
            graph.driver = a
            get_driver_id(a)
        elif o in ("--concurrency"):
            graph.concurrency = a
    if graph.version == None:
        die("Graph %d version should be specified (see '--version')" % graph.id)

def init_graph(graph):
    tests = env.get_tests(git_rev_parse(graph.version))
    for test in tests:
        if not resolve_test(test):
            continue
        if not graph.compare(test):
            continue
        t = graph.tests.get(test.cpu_count)
        if t != None:
            die(("Ambiguous graph %d specification (see tests %d and %d)" %
                (graph.id, t.id, test.id)))
        else:
            graph.tests[test.cpu_count] = test
    if len(graph.tests) == 0:
        die("No tests for graph %d" % graph.id)
    return graph

def get_graphs_title(graphs):
    title = ""
    for a in Graph.attrs:
        if Graph.is_same(a, graphs):
            if len(title) > 0:
                title += "/"
            title += str(getattr(graphs[0], a))
    return title

def get_graph_legend(graph, graphs):
    legend = ""
    for a in Graph.attrs:
        if not Graph.is_same(a, graphs):
            if len(legend) > 0:
                legend += "/"
            legend += getattr(graph, a)
    return legend

### MAIN
try:
    opts, args = getopt.getopt(sys.argv[1:], "h", [
        "help",
        "show=",
        "show-plot",
        "save-plot=",
        "clean-test",
        "test-id=",
        "sample-id=",
        "skip-reports=",
        "cps",
        "ipps",
        "ibps",
        "opps",
        "obps",
        "concurrency",
        "pps",
        "bps",
        ])
except getopt.GetoptError as err:
    print(err)
    usage()
    sys.exit(1)
for o, a in opts:
    if o in ("-h", "--help"):
        usage()
        sys.exit(0)
    elif o in ("--show"):
        g_show = a
    elif o in ("--show-plot"):
        g_show_plot = True
    elif o in ("--save-plot"):
        g_save_plot = a
    elif o in ("--test-id"):
        g_test_ids = str_to_int_list(a)
    elif o in ("--sample-id"):
        g_sample_ids = str_to_int_list(a)
    elif o in ("--skip-reports"):
        g_skip_reports = int(a)
    elif o in ("--clean-test"):
        g_clean_test = True
    elif o in ("--cps"):
        g_record = CPS
    elif o in ("--ipps"):
        g_record = IPPS
    elif o in ("--ibps"):
        g_record = IBPS
    elif o in ("--opps"):
        g_record = OPPS
    elif o in ("--obps"):
        g_record = OBPS
    elif o in ("--concurrency"):
        g_record = CONCURRENCY
    elif o in ("--pps"):
        g_record = PPS
    elif o in ("--bps"):
        g_record = BPS

for i in range(1, len(sys.argv)):
    if sys.argv[i] == "--":
        parse_graph(sys.argv[i + 1:])

for graph in g_graphs:
    init_graph(graph)

if g_clean_test:
    if len(g_test_ids) == 0:
        print("--clean-test: Please, specify --test-id")
    for test_id in g_test_ids:
        env.clean_samples(test_id)

if g_show != None:
    tests = env.get_tests(git_rev_parse(g_show))
    print("Id | Operating system | Application | CPU model | Driver | Concurrency | CPUs | Samples")
    for test in tests:
        test.samples = env.get_samples(test.id)
        resolve_test(test)
        s = ""
        for sample in test.samples:
            if len(s) != 0:
                s += ","
            s += str(sample.id) + ":" + str(len(sample.records[CPS]))
            if sample.status != SAMPLE_STATUS_OK:
                s += "*"
        print("%d | %s | %s | %s | %s | %d | %d | %s" %
            (test.id, test.os, test.app, test.cpu,
            test.driver, test.concurrency, test.cpu_count, s))

def get_test_good_samples(test_id):
    samples = env.get_samples(test_id)
    if len(samples) == 0:
        die("No samples in test with id=%d" % test_id)
    good_samples = []
    for sample in samples:
        if sample.status == SAMPLE_STATUS_OK:
            good_samples.append(sample)
    if len(good_samples) == 0:
        die("No good samples in test with id=%d" % test_id)
#    print("%d good samples in test %d" % (len(good_samples), test_id))
    return good_samples

if g_show_plot or g_save_plot != None:
    if len(g_sample_ids) > 0:
        for sample_id in g_sample_ids:
            sample = get_sample(env, sample_id)
            print("sample_id=%d, test_id=%d, status=%d" %
                (sample.id, sample.test_id, sample.status))
            y = get_sample_record1(sample)
            make_plot(None, y, None, str(sample_id), True)
    elif len(g_test_ids) > 0:
        for test_id in g_test_ids:
            good_samples = get_test_good_samples(test_id)
            y = []
            e = []
            for sample in good_samples:
                record = get_sample_record1(sample)
                y.append(int(numpy.mean(record)))
                e.append(int(numpy.std(record)))
            make_plot(None, y, e, str(test_id), True)
    elif len(g_graphs) > 0:
        plot.title(get_graphs_title(g_graphs))
        plot.xlabel("CPUs")
        for graph in g_graphs:
            x = []
            y = []
            e = []
            for cpu_count, test in graph.tests.items():
                good_samples = get_test_good_samples(test.id)
                record = []
                for sample in good_samples:
                    record.append(get_sample_record1(sample))
                x.append(cpu_count)
                y.append(int(numpy.mean(record)))
                e.append(int(numpy.std(record)))
            legend = get_graph_legend(graph, g_graphs)
            make_plot(x, y, e, legend, False)
    else:
        die("No plot data specified")

    plot.xlim(min(g_plot_xticks), max(g_plot_xticks))
    plot.ylim(0, g_plot_ymax)

    plot.grid(linestyle = "dotted")
#    plot.legend(loc='upper center')
    plot.xticks(g_plot_xticks)
    step = round(int(g_plot_ymax/10), -1)
    if step == 0:
        step = 1
    plot.yticks(range(0, math.ceil(g_plot_ymax) + step, step))
    plot.legend()
    plot.ylabel("m" + sample_record_name(g_record))
    if g_save_plot != None:
        plot.savefig(g_save)
    if g_show_plot:
        plot.show()
