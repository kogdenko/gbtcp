#!/usr/bin/python

import sys
import getopt
import math
import numpy
import scipy
import matplotlib.pyplot as plot
from common import *

class Graph:
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
        self.tests = {}
        for attr in Test.attrs:
            setattr(self, attr, None)
            setattr(self, attr + "_id", None)

    def compare(self, test):
        for a in Test.attrs:
            if a == "commit":
                continue
            graph_a_id = getattr(self, a + "_id")
            graph_a = getattr(self, a)
            test_a = getattr(test, a)
            if hasattr(test, a + "_id"):
                test_a_id = getattr(test, a + "_id")
                if graph_a_id == None:
                    if graph_a == None or test_a.find(graph_a) >= 0:
                        if graph_a == None:
                            setattr(self, a, test_a)
                        setattr(self, a + "_id", test_a_id)
                    else:
                        return False
                elif graph_a_id != test_a_id:
                    return False
            else:
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
g_show_cpu_model = False
g_set_cpu_model_alias = None
g_cpu_model_id = None
g_clean_test = False
g_plot_xticks = []
g_plot_ymax = 0
g_graphs = []
g_hide = []
g_db = Environment()

def get_test_good_samples(test_id):
    samples = g_db.get_samples(test_id)
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

def usage():
    print("analayzer.py [options]")
    print("\thelp: Print this help")
    print("\ttest-id {id,id..}: Specify test id")
    print("\tsample-id {id,id...}: Specify sample id")
    print("\tskip-reports {num}: Skip first num reports (default: %d)" % g_skip_reports)
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
        outliers, angle = find_outliers(y, error)
        print("mean=%d, std=%d (%.2f%%), angle=%.2f%%, outliers=" %
            (mean, std, round(std/mean*100, 2), round(angle, 2)), outliers)
        plot.plot([x0, x1], [y0, y1])

def get_sample(sample_id):
    sample = g_db.get_sample(sample_id) 
    if sample == None:
        die("No sample with id=%d" % sample_id)
    return sample

def get_sample_record1(sample):
    return get_sample_record(sample, g_record)[g_skip_reports:]

def parse_graph(argv):
    graph = Graph()
    graph.id = len(g_graphs)
    if len(g_graphs) > 0:
        template = g_graphs[-1]
        for attr in Test.attrs:
            setattr(graph, attr, getattr(template, attr))
    g_graphs.append(graph)
    try:
        longopts = []
        for attr in Test.attrs:
            longopts.append("%s=" % attr)

        opts, args = getopt.getopt(argv, "", longopts)
    except getopt.GetoptError as err:
        print(err)
        die("Invalid graph options")
    for o, a in opts:
        assert(hasattr(graph, o[2:]))
        setattr(graph, o[2:], a)
    if graph.commit == None:
        die("Graph %d commit should be specified" % graph.id)

def init_graph(graph):
    tests = g_db.get_tests(git_rev_parse(graph.commit))
    for test in tests:
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
    for attr in Test.attrs:
        if Graph.is_same(attr, graphs) and attr not in g_hide:
            if len(title) > 0:
                title += "/"
            title += str(getattr(graphs[0], attr))
    return title

def get_graph_legend(graph, graphs):
    legend = ""
    for attr in Test.attrs:
        if not Graph.is_same(attr, graphs):
            if len(legend) > 0:
                legend += "/"
            legend += getattr(graph, attr)
    return legend

### MAIN
try:
    opts, args = getopt.getopt(sys.argv[1:], "h", [
        "help",
        "show-cpu-model",
        "set-cpu-model-alias=",
        "cpu-model-id=",
        "show=",
        "show-plot",
        "save-plot=",
        "clean-test",
        "test-id=",
        "sample-id=",
        "skip-reports=",
        "hide=",
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
    elif o in ("--show-cpu-model"):
        g_show_cpu_model = True
    elif o in ("--set-cpu-model-alias"):
        g_set_cpu_model_alias = a
    elif o in ("--cpu-model-id"):
        g_cpu_model_id = int(a)
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
    elif o in ("--hide"):
        for hide in a.split(','):
            if hide in Test.attrs:
                if hide not in g_hide:
                    g_hide.append(hide)
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

if g_show_cpu_model:
    cpu_models = g_db.get_cpu_model(g_cpu_model_id)
    print("id | name | alias")
    for cpu_model in cpu_models:
        print("%d | %s | %s" % (cpu_model.id, cpu_model.name, cpu_model.alias))

if g_set_cpu_model_alias:
    if g_cpu_model_id == None:
        die("To '--set-cpu-model-alias', please, specify --cpu-model-id")
    g_db.set_cpu_model_alias(g_cpu_model_id, g_set_cpu_model_alias)

if g_clean_test:
    if len(g_test_ids) == 0:
        print("--clean-test: Please, specify --test-id")
    for test_id in g_test_ids:
        g_db.clean_samples(test_id)

if g_show != None:
    tests = g_db.get_tests(git_rev_parse(g_show))
    s = ""
    for attr in Test.attrs:
        if attr != "commit":
            if len(s) > 0:
                s += " | "
            s += attr
    print("id | %s | samples" % s)
    for test in tests:
        test.samples = g_db.get_samples(test.id)
        s = "%d" % test.id
        for attr in Test.attrs:
            if attr != "commit":
                s += " | " + str(getattr(test, attr))
        s += " | "
        for i in range(len(test.samples)):
            if i > 0:
                s += ","
            sample = test.samples[i]
            s += str(sample.id) + ":" + str(len(sample.records[CPS]))
            if sample.status != SAMPLE_STATUS_OK:
                s += "*"
        print(s)

if g_show_plot or g_save_plot != None:
    if len(g_sample_ids) > 0:
        for sample_id in g_sample_ids:
            sample = get_sample(sample_id)
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
    plot.ylabel("m" + get_record_name(g_record))
    if g_save_plot != None:
        plot.savefig(g_save)
    if g_show_plot:
        plot.show()
