sources += 'nl.c'

deps += 'kernel'

if platform == 'linux'
	#sources += 'src/gbtcp/nl/linux/netlink.c'
elif platform == 'freebsd'
	sources += 'freebsd/route.c'
endif
