#!/usr/bin/python

import sys
import getopt
import numpy
import scipy
import matplotlib.pyplot as plot
from common import *

g_show_plot = False
g_save_plot = None
g_sample_ids = []
g_test_ids = []
g_skip_reports = 0
g_record = CPS
g_show = None
g_clean_test = False

def usage():
    print("analayzer.py [options]")
    print("\thelp: Print this help")
    print("\tverbose: Be verbose")
    print("\ttest-id {id,id..}: Specify test id")
    print("\tsample-id {id,id...}: Specify sample id")
    print("\tskip-reports {num}: Skip first num reports")
    print("\tshow {git-commit}: Print all tests regarding to specified commit")
    print("\tshow {native}: Print all native tests")
    print("\tshow-plot: Show plot spicified by test-id or sample-id")
    print("\tsave-plot: Save plot spicified by test-id or sample-id")
    sys.exit(0)

try:
    opts, args = getopt.getopt(sys.argv[1:], "hv", [
        "help",
        "verbose",
        "show=",
        "show-plot",
        "save-plot=",
        "clean-test",
        "compare",
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
    elif o in ("-v", "--verbose"):
        set_verbose(1)
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

def make_plot(x, y, error, legend, verbose):
    std = None
    if error == None:
        std = int(numpy.std(y))
        error = [std] * len(y)
    if x == None:  
        x = range(0, len(y))
    plot.errorbar(x, y, error, label=legend)
    if not verbose:
        return;
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
    if std == None:
         std = int(numpy.std(y))
    mean, std = round_val(mean, std)
    outliers = find_outliers(y, error)
    angle = abs(y1 - y0)/((y1 + y0) / 2);
    print("mean=%d, std=%d (%.2f%%), angle=%.2f%%, outliers=" %
        (mean, std, round(std/mean*100, 2), round(angle*100, 2)), outliers)
    plot.plot([x0, x1], [y0, y1])

def get_sample(app, sample_id):
    sample = app.get_sample(sample_id) 
    if sample == None:
        die("No sample with id=%d" % sample_id)
    return sample

def get_sample_record1(sample):
    return get_sample_record(sample, g_record)[g_skip_reports:]

app = App()

if g_clean_test:
    if len(g_test_ids) == 0:
        print("--clean-test: Please, specify --test-id")
    for test_id in g_test_ids:
        app.clean_samples(test_id)

if g_show != None:
    tests = app.get_tests(g_show)
    os_map = {}
    app_map = {}
    cpu_model_map = {}
    print("Id | Operating system | Application | CPU model | Concurrency | CPUs | Samples")
    for test in tests:
        test.samples = app.get_samples(test.id)
        test.os_name = os_map.get(test.os_id)
        if test.os_name == None:
            os_name, os_ver = app.get_os(test.os_id)
            if os_name == None:
                print("%d: Invalid os_id=%d" % (test.id, test.os_id))
                continue
            test.os_name = os_name + "-" + os_ver
            os_map[test.os_id] = test.os_name
        test.app_name = app_map.get(test.app_id)
        if test.app_name == None:
            app_name, app_ver = app.get_app(test.app_id)
            if app_name == None:
                print("%d: Invalid app_id=%d" % (test.id, test.app_id))
                continue
            test.app_name = app_name + "-" + app_ver
            app_map[test.app_id] = test.app_name
        test.cpu_model_name = cpu_model_map.get(test.cpu_model_id)
        if test.cpu_model_name == None:
            cpu_model_name, cpu_model_alias = app.get_cpu_model(test.cpu_model_id)
            if cpu_model_name == None:
                print("%d: Invalid cpu_model_id=%d" % (test.id, test.cpu_model_id))
                continue
            if cpu_model_alias == None or len(cpu_model_alias) == 0:
                test.cpu_model_name = cpu_model_name
            else:
                test.cpu_model_name = cpu_model_alias
            cpu_model_map[test.cpu_model_id] = test.cpu_model_name
        s = ""
        for sample in test.samples:
            if len(s) != 0:
                s += ","
            s += str(sample.id) + ":" + str(len(sample.records[CPS]))
            if sample.status == 0:
                s += "*"
        print("%d | %s | %s | %s | %d | %d | %s" %
            (test.id, test.os_name, test.app_name, test.cpu_model_name,
            test.concurrency, test.cpu_count, s))

if ((g_show_plot or g_save_plot != None) and
    (len(g_sample_ids) != 0 or len(g_test_ids) != 0)):

    if len(g_sample_ids) > 0:
        for sample_id in g_sample_ids:
            sample = get_sample(app, sample_id) 
            print("sample_id=%d, test_id=%d, status=%d" %
                (sample.id, sample.test_id, sample.status))
            y = get_sample_record1(sample)
            make_plot(None, y, None, str(sample_id), len(g_sample_ids) == 1)
    else:
        for test_id in g_test_ids:
            samples = app.get_samples(test_id)
            if len(samples) == 0:
                die("No samples in test with id=%d" % test_id)
            good_samples = []
            for sample in samples:
                if sample.status > 0:
                    good_samples.append(sample)
            if len(good_samples) == 0:
                die("No good samples in test with id=%d" % test_id)
            print("%d good samples in test %d" % (len(good_samples), test_id))
            test_y = []
            error_y = []
            for sample in good_samples:
                y = get_sample_record1(sample)
                test_y.append(int(numpy.mean(y)))
                error_y.append(int(numpy.std(y)))
            make_plot(None, test_y, error_y, str(test_id), len(g_test_ids) == 1)

#    plot.legend(loc='upper center')
    plot.legend()
    if g_save_plot != None:
        plot.savefig(g_save)
    if g_show_plot:
        plot.show()
