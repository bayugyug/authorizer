#!/bin/bash

echo "Start"

#init
COVERPROF="/tmp/test.coverprofile"

#run
echo "Checking the cover-file: $(ls -ltra ${COVERPROF} 2>/dev/null)"

#download
go get -u -v github.com/mattn/goveralls

#run
goveralls -coverprofile=${COVERPROF} -service=generic-rest-api -repotoken=$COVERALLS_REPO_TOKEN

#dump
echo "result:$?"

[[ -s "${COVERPROF}" ]] && {
  echo "coverall okay"
}

echo "Done:${COVERPROF}"
