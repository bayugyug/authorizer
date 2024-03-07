#!/bin/bash

BUILDFLAGS=

COVERPROF="/tmp/test.coverprofile"

echo "COVERPROF: $(ls -ltra ${COVERPROF} 2>/dev/null)"

SKIP_PKGS="payment"
# try including it in the test (no skip)
SKIP_PKGS="yaypay"

#free
rm -f ${COVERPROF:-xxxx}

#run
ginkgo -v -failFast ${BUILDFLAGS} -r --randomizeSuites --trace --race --progress -covermode=atomic -coverprofile=test.coverprofile -outputdir=/tmp/  -skipPackage=$SKIP_PKGS
ret=$?

#dump
echo "ret:$ret"

[[ -s "${COVERPROF}" ]] && {
  echo "okay"
}

exit $ret
