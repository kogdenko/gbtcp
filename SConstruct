# SPDX-License-Identifier: GPL-2.0
import platform
import shutil
import subprocess

HAVE_NETMAP = False
HAVE_XDP = False
HAVE_VALE = False

def install_program(env, prog):
    env.Install('/usr/bin', prog)
    env.Alias('install', '/usr/bin')

def die(s):
    print(s)
    Exit(1)

def bytes_to_str(b):
    return b.decode('utf-8').strip()

def system(cmd, failure_tollerance=False):
    proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = proc.communicate()
    except:
        proc.kill();
        die("Command '%s' failed, exception: '%s'" % (cmd, sys.exc_info()[0]))

    out = bytes_to_str(out)
    err = bytes_to_str(err)
    rc = proc.returncode

#    print("$ %s # $? = %d\n%s\n%s" % (cmd, rc, out, err))

    if rc != 0 and not failure_tollerance:
        die("Command '%s' failed, return code: %d" % (cmd, rc))

    return rc, out, err

def get_gbtcp_version():
    if True:
        cmd = "git describe --tags --always"
        rc, out, _ = system(cmd)
        if rc != 0:
            die("Cannot extract gbtcp version")
        return out.strip()
    else:
        cmd = "git log -1 --format=%H"
        commit = system(cmd)[1].strip()
        if len(commit) != 40:
            die("Cannot extract gbtcp version")
        return commit

def add_target(target, source, env):
    env.Append(CPPPATH = ['.'])
    #target.append(str(target[0]))
    return target, source

def configure(target, source, env):
    version = get_gbtcp_version()

    f = open(str(target[0]), 'w')
    s = ""
    s += "#ifndef GBTCP_CONFIG_H\n"
    s += "#define GBTCP_CONFIG_H\n"
    s += "\n"
    s += ("#define GT_VERSION \"%s\"\n" % version)
    if HAVE_XDP:
        s += "#define GT_HAVE_XDP\n"
    if HAVE_NETMAP:
        s += "#define GT_HAVE_NETMAP\n"
    if HAVE_VALE:
        s += "#define GT_HAVE_VALE\n"

    s += "\n"
    s += "#endif // GBTCP_CONFIG_H\n"
    f.write(s)
    f.close()
    return None

def flags_to_string(flags):
    return ' ' + ' '.join(flags)

def libgbtcp_library(orig, srcs):
    cflags = [
        '-fvisibility=hidden',
    ]
    env = orig.Clone()
    env.Append(CFLAGS = flags_to_string(cflags))
    return env.SharedLibrary('bin/libgbtcp.so', srcs)

def aio_helloworld_program(orig):
    ldflags = ['-Lbin', '-lgbtcptools']
    env = orig.Clone()
    env.Append(LINKFLAGS = flags_to_string(ldflags))
    prog = env.Program('bin/gbtcp-aio-helloworld',
        'tools/gbtcp-aio-helloworld/main.c')
    Requires(prog, libgbtcptools)
    Requires(prog, libgbtcp)

def epoll_helloworld_program(orig):
    ldflags = ['-Lbin', '-lgbtcptools']
    env = orig.Clone()
    env.Append(LINKFLAGS = flags_to_string(ldflags))
    prog = env.Program('bin/gbtcp-epoll-helloworld',
        'tools/gbtcp-epoll-helloworld/main.c')
    Requires(prog, libgbtcptools)

cflags = [
    '-g',
    '-Wall',
    ' -Werror',
    '-I.',
    '-std=gnu99',
    '-pipe',
    '-finline-functions',
    '-pthread',
    '-fPIC',
    '-D_LIBC_REENTRANT',
    '-Wstrict-prototypes',
    '-Wunused-variable',
]

ldflags = [
    '-rdynamic',
    '-pthread',
    '-lm',
]

AddOption('--debug-build', action = 'store_true',
    help = 'Debug build', default = False)

AddOption('--without-netmap', action = 'store_true',
    help = "Don't use netmap transport", default = False)

AddOption('--without-vale', action = 'store_true',
    help = "Don't use netmap vale switch", default = False)

AddOption('--without-xdp', action = 'store_true',
    help = "Don't use XDP transport", default = False)

shutil.copyfile('./tools/pre-commit', '.git/hooks/pre-commit')

PLATFORM = platform.system()

env = Environment(CC = 'gcc')

bld = Builder(action = configure, emitter = add_target)
env.Append(BUILDERS = { 'Configure': bld })
env.Configure('gbtcp/config.h', None)
env.AlwaysBuild('gbtcp/config.h')

conf = Configure(env)

srcs = [
    'gbtcp/epoll.c',
    'gbtcp/fd_event.c',
    'gbtcp/file.c',
    'gbtcp/htable.c',
    'gbtcp/inet.c',
    'gbtcp/ip_addr.c',
    'gbtcp/list.c',
    'gbtcp/mbuf.c',
    'gbtcp/mod.c',
    'gbtcp/pid.c',
    'gbtcp/poll.c',
    'gbtcp/route.c',
    'gbtcp/signal.c',
    'gbtcp/sockbuf.c',
    'gbtcp/strbuf.c',
    'gbtcp/sysctl.c',
    'gbtcp/timer.c',
    'gbtcp/controller.c',
    'gbtcp/preload.c',
    'gbtcp/api.c',
    'gbtcp/log.c',
    'gbtcp/arp.c',
    'gbtcp/lptree.c',
    'gbtcp/shm.c',
    'gbtcp/sys.c',
    'gbtcp/tcp.c',
    'gbtcp/service.c',
    'gbtcp/subr.c',
    'gbtcp/dev.c',
]

if PLATFORM == "Linux":
    srcs.append('gbtcp/Linux/netlink.c')
    ldflags.append("-ldl")
    ldflags.append('-lrt')
    if not GetOption('without_xdp'):
        print("XDP disabled due cleanup bug, see libgbtcp-test-xdp.c")
        if (False and conf.CheckHeader('linux/bpf.h') and conf.CheckLib('bpf')):
            srcs.append('gbtcp/Linux/xdp.c')
            HAVE_XDP = True
            ldflags.append('-lbpf')
elif PLATFORM == 'FreeBSD':
    srcs.append('gbtcp/FreeBSD/route.c')
    ldflags.append('-lexecinfo')
    ldflags.append('-lutil')
else:
    print("Unsupported platform: %s" % PLATFORM)
    Exit(1)

cflags.append('-Wno-format-truncation')

if GetOption('debug_build'):
    cflags.append('-O0')
else:
    cflags.append('-O2')
    cflags.append('-DNDEBUG')

if not GetOption('without_netmap'):
    if conf.CheckHeader('net/netmap_user.h'):
        srcs.append('gbtcp/netmap.c')
        HAVE_NETMAP = True
        if not GetOption('without_vale'):
            HAVE_VALE = True

conf.Finish()

if platform.architecture()[0] == "64bit":
    lib_path = '/usr/lib64'
else:
    lib_path = '/usr/lib'

env.Append(CFLAGS = flags_to_string(cflags))
env.Append(LINKFLAGS = flags_to_string(ldflags))

libgbtcp = libgbtcp_library(env, srcs)

env.Install(lib_path, libgbtcp)
env.Alias('install', lib_path)

libgbtcptools = env.SharedLibrary('bin/libgbtcptools.so', [
    'tools/common/subr.c',
    'tools/common/pid.c',
    'tools/common/worker.c',
    ])

# Programs
ldflags.append('-Lbin')
ldflags.append('-lgbtcp')

env_gbtcp = Environment(CC = 'gcc',
    CCFLAGS = flags_to_string(cflags),
    LINKFLAGS = flags_to_string(ldflags),
)

sysctl = env_gbtcp.Program('bin/gbtcp-sysctl', 'sysctl/sysctl.c')
Requires(sysctl, libgbtcp)
install_program(env_gbtcp, sysctl);

netstat = env_gbtcp.Program('bin/gbtcp-netstat', 'netstat/netstat.c')
Requires(netstat, libgbtcp)
install_program(env_gbtcp, netstat)

controller = env_gbtcp.Program('bin/gbtcp-controller', 'controller/controller.c')
Requires(controller, libgbtcp)

aio_helloworld_program(env_gbtcp)
epoll_helloworld_program(env)

# Tests
for f in Glob('test/gbtcp-test-*.c'):
    env.Program("bin/" + f.name[0:-2], ["test/" + f.name, env.Object('test/subr.c')])

for f in Glob('test/libgbtcp-test-*.c'):
    env_gbtcp.Program("bin/" + f.name[0:-2], ["test/" + f.name, env.Object('test/subr.c')])
