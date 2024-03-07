package authorizer_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAuthverifier(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Authverifier Suite")
}
