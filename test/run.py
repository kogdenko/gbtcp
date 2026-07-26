#!/usr/bin/env python3

# 
# FreeBSD:
# ifconfig epair create
#
# Linux
# ip la dev vetha type veth peer vethb

import argparse
import configparser
import importlib
import os
import singleton
import sys
import unittest

path = os.path.dirname(os.path.abspath(__file__))

singleton.rootdir = os.path.abspath(f"{path}/..")
path_py = singleton.rootdir + "/py"
sys.path.insert(0, path_py)

path_py_gbtcp_proto = f"{path_py}/gbtcp/proto/"
sys.path.insert(0, path_py_gbtcp_proto)

from common import (
    get_cpus,
    argparse_add_cpus,
    argparse_get_cpus,
    parse_sockaddr_in
)

CONFIG_DIR_PATH = "~/.gbtcp/config/"
CONFIG_FILE_PATH = CONFIG_DIR_PATH + "test.ini"

def print_suite(suite):
    if hasattr(suite, '__iter__'):
        for x in suite:
            print_suite(x)
    else:
        print(suite.id())

def test_filter(name, pattern):
    after = name
    for p in pattern:
        _, m, after = after.partition(p)
        if not m:
            return False
    return True

def collect_tests(res, loader, suite, pattern):
    if hasattr(suite, '__iter__'):
        for x in suite:
            collect_tests(res, loader, x, pattern)
    else:
        if test_filter(suite.id(), pattern):
            test = loader.loadTestsFromName(suite.id())
            res.addTests(test)

# Check for import errors before test execution
def import_tests(directory):
    for f in os.listdir(directory):
        path = f"{directory}/{f}"
        if not os.path.isfile(path):
            continue
        if not f.startswith("test_") or not f.endswith(".py"):
            continue
        module_name = f[:-3]
        importlib.import_module(module_name)

def _parse_args(cpus, config, profile):
    if profile in config:
        cfg = config[profile]
    else:
        cfg = {}

    ap = argparse.ArgumentParser()
    ap.add_argument('-l', '--list', action='store_true', help="Display all tests")
    ap.add_argument("--builddir", type=str, default="./build-debug",
        help="Specify build directory")
    ap.add_argument("--tested-interface", type=str, default=cfg.get('tested-interface'),
        help="Specify tested interface")
    ap.add_argument("--tester-interface", type=str, default=cfg.get('tester-interface'),
        help="Specify tester interface")
    ap.add_argument('-f', "--failfast", type=int, default=0, help="Exit after first failure")
    ap.add_argument('--verbose', type=int, default=0, help="Be verbose")
    argparse_add_cpus(ap, cpus, cfg)
    ap.add_argument('-p', '--pattern', type=str, help="Filter tests by pattern")
    ap.add_argument("--baseline", type=str, metavar="commit", default=cfg.get('baseline'),
        help="Benchmarks baseline")
    ap.add_argument("--tags", type=str, help="Filter tests by tags")
    ap.add_argument("--connect", type=parse_sockaddr_in, metavar="ip:port",
        default=cfg.get('connect'),
        help="Connect to e2e server")
    ap.add_argument("--profile", type=str,
        help=f"Specify test profile (see. {CONFIG_FILE_PATH}")
    args = ap.parse_args()

    if args.profile:
        cfg = {}
        if args.baseline:
            cfg['baseline'] = args.baseline
        if args.connect:
            cfg['connect'] = f"{args.connect[0]}:{args.connect[1]}"
        if args.tested_interface:
            cfg['tested-interface'] = args.tested_interface
        if args.tester_interface:
            cfg['tester-interface'] = args.tester_interface

        config[profile] = cfg

    return args

def parse_args(cpus):
    config = configparser.ConfigParser()
    config_file_path = os.path.expanduser(CONFIG_FILE_PATH)

    config.read(config_file_path)

    args = _parse_args(cpus, config, 'default')
    if args.profile != None and args.profile != 'default':
        args = _parse_args(cpus, config, args.profile)

    if args.profile:
        with open(config_file_path, 'w') as f:
            config.write(f)

    return args

def main():
    os.makedirs(os.path.expanduser(CONFIG_DIR_PATH), exist_ok=True)

    log_file_path = "/tmp/gbtcp-testlog.txt"
    if os.path.isfile(log_file_path):
        os.remove(log_file_path)
    singleton.log_file = open(log_file_path, "w", encoding="utf-8") 
    singleton.verbose = 0

    cpus = get_cpus()

    args = parse_args(cpus)

    import_tests(path)

    loader = unittest.defaultTestLoader

    cpus = argparse_get_cpus(args, cpus)

    if args.list:
        print_suite(loader.discover(path))
        return 0

    if args.tested_interface == None:
        print("Argument `TESTED_INTERFACE` are required")
        sys.exit(1)

    if args.connect:
        singleton.tester_address = args.connect
        singleton.tested_cpus = cpus
    else:
        if args.tester_interface == None:
            print("Argument `TESTER_INTERFACE` are required")
            sys.exit(1)

        singleton.tester_address = None
        if len(cpus) == 1:
            singleton.tested_cpus = cpus
            singleton.tester_cpus = cpus
        else:
            m = int(len(cpus)/2)
            singleton.tested_cpus = cpus[:m]
            singleton.tester_cpus = cpus[m:2*m]

    singleton.builddir = os.path.realpath(args.builddir) + "/"
    singleton.use_database = "release" in args.builddir
    singleton.baseline = args.baseline
    singleton.verbose = args.verbose
    singleton.tested_interface = args.tested_interface
    singleton.tester_interface = args.tester_interface

    runner = unittest.TextTestRunner(verbosity=2, failfast=args.failfast)

    pattern = []
    if args.pattern:
        pattern = [i.strip() for i in args.pattern.split("*") if i]

    if args.tags:
        singleton.tags = [tag.strip() for tag in args.tags.split(",") if tag]
    else:
        singleton.tags = []

    if len(pattern) == 0:
        runner.run(loader.discover(path))
    else:
        suite = unittest.TestSuite()
        collect_tests(suite, loader, loader.discover(path), pattern)
        runner.run(suite)

if __name__ == "__main__":
    sys.exit(main())
