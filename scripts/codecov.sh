#!/bin/bash

COVERAGE_PROF="/tmp/test.coverprofile"
COVERAGE_FILE="coverage.txt"

#init
>${COVERAGE_FILE}

echo "COVERAGE_PROF: $(ls -ltra ${COVERAGE_PROF} 2>/dev/null)"

if [[ -s "${COVERAGE_PROF}" ]]
then
    echo "coverage okay"
    mv -f ${COVERAGE_PROF} ${COVERAGE_FILE}
    echo "copy: $?"
else
    echo "coverage not-okay"
fi



