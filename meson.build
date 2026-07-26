# HOWTO:
# meson setup build -Dwithout-xdp=true

project('gbtcp', ['c'],
	version: '0.3.0',
	license: 'LGPL-2.1-only',
	default_options: [
		'buildtype=release',
		'c_std=gnu99',
		'werror=true',
		'warning_level=2', # =3
	]
)

platform = host_machine.system()

libprotobuf = dependency('libprotobuf-c', version: '>=1.0.0')
protoc = find_program('protoc')

config_data = configuration_data()

config_data.set('GT_VERSION', meson.project_version())
config_data.set('GT_API_SOCK_PATH', '/var/run/gbtcp.sock')

global_arguments = []
global_arguments += '-pipe'
global_arguments += '-finline-functions'
global_arguments += '-fPIC'
global_arguments += '-D_LIBC_REENTRANT'
global_arguments += '-D_GNU_SOURCE'
# All __thread variables (current, gt_current_process, gt_errno, ...) are defined
# in libraries loaded at program startup (libgbtcp-kernel/socket are DT_NEEDED of
# the LD_PRELOAD lib; the controller/tools link them directly). The only
# fresh-dlopened module, l2fwd, defines no TLS. So their TLS lives in the static
# TLS block and we can use the initial-exec model: a single %fs-relative load
# instead of a __tls_get_addr() call. `current` is dereferenced on every hot-path
# op, so general-dynamic TLS (the shared-library default) is a measurable pps hit.
global_arguments += '-ftls-model=initial-exec'
global_arguments += '-Wstrict-prototypes'
global_arguments += '-Wunused-variable'
global_arguments += '-Wno-unused-parameter'
global_arguments += '-Wno-sign-compare'

add_global_arguments(global_arguments, language: 'c')
add_global_link_arguments('-pthread', language: 'c')

c = meson.get_compiler('c')

readline = dependency('readline')
dependencies = [libprotobuf, readline]
include = []
include += 'src'
include += 'src/gbtcp'
include += '.'
include += '/usr/local/include/'

if c.has_header_symbol('sys/socket.h', 'SO_REUSEPORT_LB')
	have_so_reuseport_lb = 1
else
	have_so_reuseport_lb = 0
endif
config_data.set('GT_HAVE_SO_REUSEPORT_LB', have_so_reuseport_lb) 

have_bsd44 = 0
if not get_option('without-bsd44')
	have_bsd44 = 1
endif
config_data.set('GT_HAVE_BSD44', have_bsd44)

have_bfd = 0
bfd = c.find_library('bfd', required: false)
if bfd.found() and c.has_function('bfd_openr', dependencies: [bfd])
	dependencies += bfd
	have_bfd = 1
endif
config_data.set('GT_HAVE_BFD', have_bfd)

have_xdp = 0
have_xdp_xsk = 0
if platform == 'linux' and not get_option('without-xdp')
	bpf = c.find_library('bpf', required: false)
	if c.has_header('linux/if_xdp.h') and bpf.found()
		if c.has_header('bpf/xsk.h')
			have_xdp = 1
		else
			xdp = c.find_library('xdp', required: false)
			if c.has_header('xdp/xsk.h') and xdp.found()
				have_xdp = 1
				have_xdp_xsk = 1
				dependencies += xdp
			endif
		endif
	endif
endif

if have_xdp == 1
	dependencies += bpf
endif
config_data.set('GT_HAVE_XDP', have_xdp)
config_data.set('GT_HAVE_XDP_XSK', have_xdp_xsk)

have_netmap = 0
have_vale = 0
if not get_option('without-netmap')
	if c.has_header('net/netmap_user.h')
	        have_netmap = 1
        	if not get_option('without-netmap-vale')
			have_vale = 1
		endif
	endif
endif
config_data.set('GT_HAVE_NETMAP', have_netmap)
config_data.set('GT_HAVE_VALE', have_vale)

if have_xdp == 0 and have_netmap == 0
	error('At least one transport (netmap or xdp) must be supported')
endif

if platform == 'freebsd'
	libexecinfo = c.find_library('libexecinfo', required: true)
	dependencies += libexecinfo
endif

# Build
subdir('py/gbtcp')

proto_config = {}

# [kernel]: inet.c, worker,c, ....
# [preload]: preload.c
source_config = {}
link_with_config = {}

# Set `dirs`
# dirs = ['kernel', 'socket', ...]
dirs = []
subdir('src/gbtcp')
foreach dir : dirs
	protos = []
	sources = []
	deps = []

	subdir('src/gbtcp/' + dir)

	source_config += {dir: sources}
	link_with_config += {dir: deps}

	gen_c = []
	gen_py = []

	foreach proto : protos
		proto_path = 'src/gbtcp/' + dir + '/' + proto + '.proto'
		gen_c += custom_target(proto + '_pb_c',
			input: proto_path,
			output: [proto + '.pb-c.h', proto + '.pb-c.c'],
			command: [
				protoc,
				'-I=@CURRENT_SOURCE_DIR@/src/',
				'--c_out=@OUTDIR@',
				'@INPUT@',
				'&&',
				'mv', 'gbtcp/' + dir + '/' + '@OUTPUT1@', '@OUTPUT1@',
			],
			build_by_default: true,
		)

		gen_py += custom_target(proto + '_pb2_py',
			input: proto_path,
			output: proto + '_pb2.py',
			command: [
				protoc,
				'-I=@CURRENT_SOURCE_DIR@/src/',
				'--python_out=@CURRENT_SOURCE_DIR@/py/gbtcp/proto',
				'@INPUT@',
			],
			build_by_default: true,
		)
	endforeach

	proto_config += {
		dir + '_c': gen_c
	}

	proto_config += {
		dir + '_py': gen_py
	}
endforeach

proto_targets = []
foreach name, target : proto_config
	proto_targets += target
endforeach

api_validation = custom_target('api-validation',
	output: 'api_validation.c',
	command: [
		'cp',
		'py/gbtcp/config.py',
		'@CURRENT_SOURCE_DIR@/py/gbtcp/',
		'&&',
		'python',
		'@CURRENT_SOURCE_DIR@/py/gbtcp-api',
		'&&',
		'touch',
		'@OUTPUT0@'
	],
	build_by_default: true,
	depends: proto_targets
)

lib_config = {}
foreach dir, sources : source_config
	gen_c = proto_config[dir + '_c']
	gen_py = proto_config[dir + '_py']

	build_sources = []
	foreach src : sources
		build_sources += 'src/gbtcp/' + dir + '/' + src
	endforeach

	link_with = []
	name = 'gbtcp-' + dir
	foreach dep : link_with_config[dir]
		link_with += lib_config[dep]
	endforeach

	lib = shared_library(name,
		build_sources,
		api_validation,
		gen_c,
		gen_py,
		dependencies: dependencies,
		link_with: link_with,
		link_args: ['-rdynamic'],
		include_directories: include_directories(include),
		install: false,
	)

	lib_config += {dir: lib}

endforeach

#-----------------------------------------------------------------
executable('gbtcp-netstat',
	'src/gbtcp/netstat/netstat.c',
	include_directories: include_directories(include),
	link_with: [lib_config['kernel'], lib_config['socket']],
	link_args: ['-rdynamic'],
)

executable('gbtcp-controller',
	'src/gbtcp/controller/controller.c',
	include_directories: include_directories(include),
	link_with: [lib_config['kernel']],
	link_args: ['-rdynamic'],
)

executable('gbtcpctl',
	'src/gbtcp/gbtcpctl/main.c',
	include_directories: include_directories(include),
	link_with: [lib_config['kernel']],
	link_args: ['-rdynamic'],
)

sources = []
sources += 'tools/common/gtt_subr.c'
sources += 'tools/common/gtt_pid.c'
sources += 'tools/common/gtt_worker.c'

libgbtcptools = shared_library('gbtcptools',
	sources,
	include_directories: include_directories(include),
	install: true,
	link_args: ['-rdynamic'],
)

executable('gbtcp-epoll-helloworld',
	'tools/gbtcp-epoll-helloworld/main.c',
	include_directories: include_directories(include),
	link_with: [libgbtcptools],
	link_args: ['-rdynamic'],
)

executable('gbtcp-aio-helloworld',
	'tools/gbtcp-aio-helloworld/main.c',
	include_directories: include_directories(include),
	link_with: [lib_config['kernel'], lib_config['socket'], libgbtcptools],
	link_args: ['-rdynamic'],
)

tests = []
tests += 'gbtcp-test-FP'
tests += 'gbtcp-test-slow-start'
tests += 'gbtcp-test-fork'
tests += 'gbtcp-test-ioctl-FIONSPACE'

if platform == 'linux'
	tests += 'gbtcp-test-epoll-close-fd'
	tests += 'gbtcp-test-epoll-create'
	tests += 'gbtcp-test-epoll-RDHUP'
endif

if have_xdp != 0
	tests += 'libgbtcp-test-xdp'
endif

tests += 'libgbtcp-test-dev'

# Unit tests: run standalone (no network setup needed) via `meson test`
cmocka = dependency('cmocka')
unit_tests = []
unit_tests += 'libgbtcp-test-mm'
tests += unit_tests

foreach name : tests
	link_with = []
	test_include = []
	deps = [cmocka]
	if name.startswith('lib')
		link_with += lib_config['kernel']
		link_with += lib_config['socket']
		test_include += include
	endif
	exe = executable(name,
		[ 'test/' + name + '.c', 'test/subr.c'],
		include_directories: include_directories(test_include),
		link_with: link_with,
		dependencies: deps,
		link_args: ['-rdynamic'],
	)
	if name in unit_tests
		test(name, exe,
			protocol: 'tap',
			env: ['CMOCKA_MESSAGE_OUTPUT=TAP'],
		)
	endif
endforeach
