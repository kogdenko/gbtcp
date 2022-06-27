import platform
import subprocess

HAVE_NETMAP = False
HAVE_XDP = False

def install_program(env, prog):
    env.Install('/usr/bin', prog)
    env.Alias('install', '/usr/bin')

def die(s):
    print(s)
    sys.exit(1)

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

def get_git_commit():
    cmd = "git log -1 --format=%H"
    commit = system(cmd)[1].strip()
    if len(commit) != 40:
        die("'%s': Unexpected output" % cmd)
    return commit

def configure():
    commit = get_git_commit()

    f = open("gbtcp/config.h", 'w')
    s = ""
    s += "#ifndef GBTCP_CONFIG_H\n"
    s += "#define GBTCP_CONFIG_H\n"
    s += "\n"
    s += ("#define GTL_COMMIT %s\n" % commit)
    s += "\n"
    s += "#endif // GBTCP_CONFIG_H\n"
    f.write(s)
    f.close()
    


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
    '-L.'
]

AddOption('--debug-build', action = 'store_true',
    help = 'Debug build', default = False)

AddOption('--without-netmap', action = 'store_true',
    help = "Don't use netmap transport", default = False)

AddOption('--without-vale', action = 'store_true',
    help = "Don't use netmap vale switch", default = False)

AddOption('--without-xdp', action = 'store_true',
    help = "Don't use XDP transport", default = False)

SConscript([
    'test/SConstruct',
    'tools/epoll_helloworld/SConstruct',
])

PLATFORM = platform.system()

env = Environment(CC = 'gcc')
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
        if (conf.CheckHeader('linux/bpf.h') and conf.CheckLib('bpf')):
            srcs.append('gbtcp/Linux/xdp.c')
            cflags.append('-DHAVE_XDP')
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
    suffix = "-d"
else:
    cflags.append('-O2')
    cflags.append('-DNDEBUG')
    suffix=""

if not GetOption('without_netmap'):
    if conf.CheckHeader('net/netmap_user.h'):
        srcs.append('gbtcp/netmap.c')
        cflags.append('-DHAVE_NETMAP')
        if not GetOption('without_vale'):
            cflags.append('-DHAVE_VALE')

if platform.architecture()[0] == "64bit":
    lib_path = '/usr/lib64'
else:
    lib_path = '/usr/lib'

env.Append(CFLAGS = ' '.join(cflags))
env.Append(LINKFLAGS = ' '.join(ldflags))

configure()

libgbtcp = env.SharedLibrary('bin/libgbtcp%s.so' % suffix, srcs)
env.Install(lib_path, libgbtcp)
env.Alias('install', lib_path)

# Programs
ldflags.append('-Lbin')
ldflags.append('-lgbtcp%s' % suffix)

env = Environment(CC = 'gcc',
    CCFLAGS = ' '.join(cflags),
    LINKFLAGS = ' '.join(ldflags),
)

sysctl = env.Program('bin/gbtcp-sysctl%s' % suffix, 'sysctl/sysctl.c')
Requires(sysctl, libgbtcp)
install_program(env, sysctl);

netstat = env.Program('bin/gbtcp-netstat%s' % suffix, 'netstat/netstat.c')
Requires(netstat, libgbtcp)
install_program(env, netstat)

controller = env.Program('bin/gbtcp-controller%s' % suffix, 'controller/controller.c')
Requires(controller, libgbtcp)

aio_helloworld = env.Program('bin/gbtcp-aio-helloworld%s' % suffix,
    'tools/gbtcp_aio_helloworld/main.c')
Requires(aio_helloworld, libgbtcp)
install_program(env, aio_helloworld)
