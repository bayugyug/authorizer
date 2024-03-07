#!/bin/bash

export ACK_GINKGO_RC=true

_info(){
        evt="$( basename $0 2>/dev/null)"
        echo $evt - $(printf "\033[32mINFO\033[0m %s" "${FUNCNAME[1]}") - "$@"
}

_warn(){
        evt="$( basename $0 2>/dev/null)"
        echo $evt -  $(printf "\033[35mWARN\033[0m %s" "${FUNCNAME[1]}") - "$@"

}

action=${1:-xxx}
app_name=${2:-authorizer}
pre_app=${app_name}
BUILDFLAGS=


echo "
${app_name}

	action: $action

"

_runPrep(){
    case "${action}" in
        ci-lint)
            BIN_CI_LINTER=$(go env GOPATH)/bin/golangci-lint
            echo "run linter: ${BIN_CI_LINTER}" 

            if [[ ! -x "${BIN_CI_LINTER}" ]]
            then
                echo "
                # binary will be $(go env GOPATH)/bin/golangci-lint
                curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.53.3


                Trying to install the linter below

                "
                curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.53.3
            fi

            # lint
            golangci-lint run
            echo "lint-result: $?"

            ;;
        ci-test)
            echo "unit testing"
	    export GOCOVERDIR=/tmp
            go install github.com/onsi/ginkgo/v2/ginkgo
            go get github.com/onsi/gomega/...
            ginkgo -v --fail-fast \
                -r --randomize-suites \
                --trace --race --show-node-events \
                -covermode=atomic \
                -coverprofile=test.coverprofile \
                --output-dir=/tmp/
                            return $?
                            ;;
                        clean)
                            echo "free up"
                            rm -fr logs/*.log   2>/dev/null
                            rm -fr temp/*       2>/dev/null
                            ;;

                        *)
                            echo "action not supported"
                            ;;
                    esac

                    return 0
                }

_runPrep "$@"

exit $?



