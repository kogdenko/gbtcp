protos += 'api'
protos += 'cli'
protos += 'inet'
protos += 'ip'
protos += 'gbtcp'

sources += 'backtrace.c'
sources += 'vector.c'
sources += 'fd_event.c'
sources += 'htable.c'
sources += 'inet.c'
sources += 'ip_addr.c'
sources += 'list.c'
sources += 'mm.c'
sources += 'kernel.c'
sources += 'mod.c'
sources += 'node.c'
sources += 'pid.c'
sources += 'route.c'
sources += 'strbuf.c'
sources += 'timer.c'
sources += 'worker.c'
sources += 'log.c'
sources += 'arp.c'
sources += 'lptree.c'
sources += 'shm.c'
sources += 'sys.c'
sources += 'subr.c'
sources += 'dev.c'
sources += 'api.c'
sources += 'cli.c'
sources += 'handoff.c'

if have_xdp != 0
	sources += 'Linux/xdp.c'
endif

if have_netmap != 0
	sources += 'netmap.c'
endif

if platform == 'linux'
	sources += 'netlink.c'
endif

#elif platform == 'freebsd'
#    ldflags.append('-lexecinfo')
#    ldflags.append('-lutil')
#else
#	error('Unsupported platform: ', platform)
#endif
