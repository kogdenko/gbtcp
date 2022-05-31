import platform

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

srcs = []
for f in Glob("gbtcp/*.c"):
    srcs.append("gbtcp/%s" % f.name)
for f in Glob("gbtcp/%s/*.c" % PLATFORM):
    srcs.append("gbtcp/%s/%s" % (PLATFORM, f.name))

if PLATFORM == "Linux":
    ldflags.append("-ldl")
    ldflags.append('-lrt')
elif PLATFORM == 'FreeBSD':
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

env = Environment(CC = 'gcc')

conf = Configure(env)

if not GetOption('without_netmap'):
    if conf.CheckHeader('net/netmap_user.h'):
        cflags.append('-DHAVE_NETMAP')
        if not GetOption('without_vale'):
            cflags.append('-DHAVE_VALE')

if platform.system() == "Linux" and not GetOption('without_xdp'):
    if (conf.CheckHeader('linux/bpf.h') and conf.CheckLib('bpf')):
        cflags.append('-DHAVE_XDP')
        ldflags.append('-lbpf')
#        srcs.append('xdp.c')

if platform.architecture()[0] == "64bit":
    lib_path = '/usr/lib64'
else:
    lib_path = '/usr/lib'

env.Append(CFLAGS = ' '.join(cflags))
env.Append(LINKFLAGS = ' '.join(ldflags))

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
env.Install('/usr/bin', sysctl)
env.Alias('install', '/usr/bin')

netstat = env.Program('bin/gbtcp-netstat%s' % suffix, 'netstat/netstat.c')
Requires(netstat, libgbtcp)
env.Install('/usr/bin/', netstat)
env.Alias('install', '/usr/bin')

controller = env.Program('bin/gbtcp-controller%s' % suffix, 'controller/controller.c')
Requires(controller, libgbtcp)

aio_helloworld = env.Program('bin/gbtcp-aio-helloworld%s' % suffix,
    'tools/gbtcp_aio_helloworld/bench_gbtcp.c')
Requires(aio_helloworld, libgbtcp)
