#!/usr/bin/env python3

import datetime
import os
import singleton
import subprocess
import sys
import threading
import time
import traceback

from enum import Enum

class Enum(Enum):
    def __str__(self):
        return self.value

class EnvVar(Enum):
    LD_LIBRARY_PATH = "LD_LIBRARY_PATH"
    LD_PRELOAD = "LD_PRELOAD"
    GBTCP_CONF = "GBTCP_CONF"

def _bytes_to_str(b):
    return b.decode('utf-8').strip()

def dbg(*args):
    traceback.print_stack(limit=2)
    print(args)

def _print_log(s):
    log = str(datetime.datetime.now()) + ": " + s
    singleton.log_file.write(log + "\n")
    singleton.log_file.flush()

    if singleton.verbose > 0:
        print(log)
        sys.stdout.flush()

def log_error(exc, s):
    if exc != None:
        exception_str = '\n'.join(traceback.format_exception(exc))
        s += " ('" + str(exc) + "')\n" + exception_str
    _print_log(s)

def log_info(s):
    _print_log(s)

def upper_pow2_32(x):
    x = int(x)
    x -= 1
    x |= x >>  1
    x |= x >>  2
    x |= x >>  4
    x |= x >>  8
    x |= x >> 16
    x += 1
    return x;

def monotonic_ms():
    return int(time.monotonic_ns() / 1000000)

def _env_to_string(env):
    if not env:
        return ""
    s = ""
    for v in EnvVar:
        if env.get(v.value):
            if len(s):
                s += " "
            s += "%s=%s" % (v.value, env.get(v.value))

    return s;

def _stdout_reader(proc):
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        log_info("$ [pid=%d] %s" % (proc.pid, line.strip()))

def start_process(cmd, env=None):
    proc = subprocess.Popen(cmd.split(), env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            text=True,
    )
    log = "$"

    s = _env_to_string(env)
    if len(s):
        log += f" {s}"
    log += f" {cmd} & [pid={proc.pid}]"
    log_info(log)

    proc._stdout_thread = threading.Thread(target=_stdout_reader, args=(proc,), daemon=True)
    proc._stdout_thread.start()

    return proc

def wait_process(proc):
    t0 = monotonic_ms()
    try:
        proc.wait(timeout=5)
    except Exception as exc:
        t1 = monotonic_ms()
        dt = t1 - t0
        assert(dt * 1000 > 4.5)
        log_error(exc, "$ [pid=%d] Timeouted" % proc.pid)
        proc.terminate()
        proc.wait(timeout=5)

    proc._stdout_thread.join()

    log_info("$ [pid=%d] Done + %d" % (proc.pid, proc.returncode))

    proc.stdout.close()

    return proc.returncode

def system(cmd, fault_tollerance=False):
    env = os.environ.copy()
    if hasattr(singleton, "builddir"):
        env["LD_LIBRARY_PATH"] = singleton.builddir

    proc = subprocess.Popen(cmd.split(), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = proc.communicate(timeout = 5)
    except Exception as exc:
        proc.kill();
        log_error(exc, f"Command '{cmd}' failed")
        raise exc

    out = _bytes_to_str(out)
    err = _bytes_to_str(err)
    rc = proc.returncode

    log = f"$ {cmd}"
    if rc != 0:
        log += " $? = %d" % rc
    if len(out):
        log += "\n%s" % out
    if len(err):
        log += "\n%s" % err
    if rc == 0:
        log_info(log)
    else:
        log_error(None, log)

    if rc != 0 and not fault_tollerance:
        raise RuntimeError(f"Command '{cmd}' failed with code '{rc}'")
        
    return rc, out, err

def kmgt(num):
    suf = [ '', 'k', 'm', 'g', 't' ]
    mag = 0
    v = float(num)

    while v >= 1000:
        mag += 1
        v /= 1000

    if mag == 0:
        return str(num)
    elif abs(v) > 10:
        return f"{v:.0f}{suf[mag]}"
    else:
        return f"{v:.1f}{suf[mag]}"
