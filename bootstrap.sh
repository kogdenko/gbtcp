#!/bin/sh

id="unknown"
version_id="0"

os=$(uname -s)
case $os in
FreeBSD)
	id=freebsd
	;;
Linux)
	if [ -f /etc/os-release ]; then
		. /etc/os-release
		id=$ID
		version_id=$VERSION_ID
	else
		exit 1
	fi
	;;
esac

case $id in
ubuntu)
	apt install -y meson
	apt install -y libprotobuf-c-dev
	apt install -y protobuf-c-compiler
	apt install -y protobuf-compiler
	apt install -y libreadline-dev

	# For test only
	apt install -y nginx

	pip install --upgrade google-api-python-client
	;;

freebsd)
	pkg install pkgconf
	pkg install meson
	pkg install gmake
	pkg install protobuf
	pkg install protobuf-c

	# For test only
	pkg install py311-pip
	pkg install py311-google-api-python-client
	pkg install nginx
	;;
esac

# For test only
pip install psutil
pip install singleton
pip install numpy
pip install GitPython
pip install parameterized
pip install mysql-connector-python
pip install getmac
