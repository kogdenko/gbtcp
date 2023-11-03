#!/bin/sh

WORKDIR="/tmp/gbtcp_bootstrap/"
CHECKOUT=""
ARCHIVE_PATH=""
ARCHIVE_FILENAME="gbtcp.tar.gz"
SSHHOST=""
DOCKERCONTAINER=""

usage()                    
{                    
	echo "Usage: deploy.sh [-hx]{[-a]|[-c checkout]} {[-s sshhost]|[-d dockercontainer]}"
}   

rm -rf $ARCHIVE_FILENAME

while getopts "hxac:s:d:" opt; do
	case $opt in
	h)
		usage
		;;
	x)
		set -x
		;;
	a)
		git archive -o $ARCHIVE_FILENAME `git stash create`
		;;
	c)
		git archive -o $ARCHIVE_FILENAME $OPTARG
		;;
	s)
		HOST=$OPTARG
		;;
	d)
		DOCKERCONTAINER=$OPTARG
		;;
        esac
done

ARCHIVE_PATH=`realpath $ARCHIVE_FILENAME`

if [ ! -f "$ARCHIVE_PATH" ]; then
	usage
	exit 1
fi

ARCHIVE="/tmp/$ARCHIVE_FILENAME"
BOOTSTRAP="/tmp/bootstrap.sh"

deploy_via_ssh()
{
	scp test/bootstrap.sh "$HOST:$BOOTSTRAP"

	scp $ARCHIVE_PATH "$HOST:$ARCHIVE"
	ssh $HOST <<EOF
$BOOTSTRAP -w $WORKDIR -a $ARCHIVE
EOF
}

deploy_on_docker()
{
	docker cp test/bootstrap.sh "$DOCKERCONTAINER:/tmp"

	docker cp $ARCHIVE_PATH "$DOCKERCONTAINER:$ARCHIVE"
	docker exec $DOCKERCONTAINER $BOOTSTRAP -w $WORKDIR -a $ARCHIVE
}

if [ ! -z "$SSHOST" ]
then
	deploy_via_ssh
elif [ ! -z "$DOCKERCONTAINER" ]
then
	deploy_on_docker
else
	usage	
	exit 2
fi
