package git_test

//nolint:revive // test file
import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

func TestGit(t *testing.T) {
	t.Parallel()
	logrus.SetOutput(GinkgoWriter)
	RegisterFailHandler(Fail)
	RunSpecs(t, "git")
}
