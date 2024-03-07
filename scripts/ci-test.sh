#!/bin/bash

BUILDFLAGS=

COVERPROF="test.coverprofile"

echo "COVERPROF: $(ls -ltra ${COVERPROF} 2>/dev/null)"

export GOCOVERDIR=/tmp

#free
rm -f ${COVERPROF:-xxxx}

#run
ginkgo -v \
	-r \
	--randomize-suites \
	--trace --race --show-node-events \
	--cover \
	--covermode=atomic \
	--coverprofile=$COVERPROF \
	--output-dir=/tmp
ret=$?



exit $ret
