protos += 'socket'

deps += 'kernel'

sources += 'epoll.c'
sources += 'file.c'
sources += 'poll.c'
sources += 'sockbuf.c'
sources += 'socket.c'
sources += 'syscall.c'
sources += 'gbtcp/socket.c'

if have_bsd44 != 0
	sources += 'bsd44/tcp_output.c'
	#sources += 'bsd44/udp_usrreq.c'
	sources += 'bsd44/uipc_socket.c'
	sources += 'bsd44/tcp_usrreq.c'
	sources += 'bsd44/tcp_input.c'
	sources += 'bsd44/in_pcb.c'
	sources += 'bsd44/tcp_debug.c'
	sources += 'bsd44/tcp_subr.c'
	#sources += 'bsd44/ip_icmp.c'
	sources += 'bsd44/ip_output.c'
	sources += 'bsd44/tcp_timer.c'
	sources += 'bsd44/ip_input.c'
	sources += 'bsd44/if_ether.c'
endif
