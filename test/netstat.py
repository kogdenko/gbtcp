from common import *

# { 'Ip': [['Forwarding', 'DefaultTTL', ... ], [2, 64, ... ]],
#   'Icmp': [['InMsgs', 'InErrors', ...], [59610, 25, ... ]]
#   ...
# }

def parse_file(a, fn):
    f = open(fn, 'r')
    lines = f.readlines()
    f.close()
    ln = 0
    for line in lines:
        ln += 1
        kv = line.split(':')
        if len(kv) != 2:
            die("%s:%d: Unepected ':'" % (fn, ln))
        k = kv[0] # 'Ip'
        v = kv[1] # 'Forwarding DefaultTTL' or '2 64'
        vl = v.split()
        if a.get(k) == None:
            a[k] = [[],[]]
            for vle in vl:
                a[k][0].append(vle)
        else:
            for i in range(len(vl)):
                vle = vl[i]
                vle_is_int, vlei = is_int(vle)
                if not vle_is_int:
                    die("%s:%d:%d: Not an integer" % (fn, ln, i))
                a[k][1].append(vlei)
            k_num = len(a[k][0])
            v_num = len(a[k][1])
            if (k_num != v_num):
                die("%s:%d: Number of keys (%d) not equal to number of values (%d)" % 
                    (fn, ln, k_num, v_num))
    return a

def read():
    a = {}
    a = parse_file(a, '/proc/net/snmp')
    a = parse_file(a, '/proc/net/netstat')
    return a

def diff(a, b):
    d = {}
    for ak, av in a.items():
        bv = b.get(ak)
        if bv == None:
            print_log("netstat: key '%s' not exists" % ak)
            continue
        if len(bv[0]) != len(av[0]):
            print_log("netstat: key '%s' has unexpected number of values (%d, %d)" %
                (ak, len(bv[0]), len(av[0])))
            continue
        for i in range(len(av[0])):
            dv = bv[1][i] - av[1][i]
            if dv != 0:
                if d.get(ak) == None:
                    d[ak] = [[], []]
                d[ak][0].append(av[0][i])
                d[ak][1].append(dv)
    return d

def to_string(a):
    s = ""
    for k, v in a.items():
        s += "%s:\n" % k
        for i in range(len(v[0])):
            s += "    %s: %d\n" % (v[0][i], v[1][i])
    return s

def get(a, k, kk):
    for i in len(a[k][0]):
        if a[k][0][i] == kk:
            return a[k][1][i]
    return None
