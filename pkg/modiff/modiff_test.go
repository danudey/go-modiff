package modiff_test

//nolint:revive // test file
import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/saschagrunert/go-modiff/pkg/git"
	"github.com/saschagrunert/go-modiff/pkg/modiff"
	"github.com/sirupsen/logrus"
)

//go:embed expected.txt
var expected string

//go:embed expectedIndirect.txt
var expectedIndirect string

//go:embed expectedWithLinks.txt
var expectedWithLinks string

// The actual test suite
var _ = t.Describe("Run", func() {
	const (
		repo    = "github.com/saschagrunert/go-modiff"
		from    = "v0.10.0"
		to      = "v0.11.0"
		badRepo = "github.com/saschagrunert/go-modiff-invalid"
	)

	// To speed up testing (and ensure that reference repositories work), use our own repo as a reference
	var topLevel string
	cwd, err := os.Getwd()
	if err == nil {
		topLevel, err = git.GetTopLevel(cwd)
		if err != nil {
			topLevel = ""
		}
	}

	fmt.Println(topLevel)

	BeforeEach(func() {
		logrus.SetLevel(logrus.PanicLevel)
	})

	It("should succeed", func() {
		// Given
		config := modiff.NewConfig(repo, topLevel, from, to, false, false, true, 1)

		// When
		res, err := modiff.Run(context.Background(), config)

		// Then
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(Equal(expected))
	})

	It("should succeed with indirect mods", func() {
		// Given
		config := modiff.NewConfig(repo, topLevel, from, to, false, true, true, 1)

		// When
		res, err := modiff.Run(context.Background(), config)

		// Then
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(Equal(expectedIndirect))
	})

	It("should succeed with links", func() {
		// Given
		config := modiff.NewConfig(repo, topLevel, from, to, true, true, true, 1)

		// When
		res, err := modiff.Run(context.Background(), config)

		// Then
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(Equal(expectedWithLinks))
	})

	It("should fail if context is nil", func() {
		// Given
		// When
		res, err := modiff.Run(context.Background(), nil)

		// Then
		Expect(err).To(HaveOccurred())
		Expect(res).To(BeEmpty())
	})

	It("should detect the local repository if 'repository' not given", func() {
		// Given
		config := modiff.NewConfig("", "", from, to, false, false, true, 1)

		// When
		res, err := modiff.Run(context.Background(), config)

		// Then
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(Equal(expected))
	})

	It("should fail if 'from' equals 'to'", func() {
		// Given
		config := modiff.NewConfig(repo, topLevel, "", "", true, false, false, 1)

		// When
		res, err := modiff.Run(context.Background(), config)

		// Then
		Expect(err).To(HaveOccurred())
		Expect(res).To(BeEmpty())
	})

	It("should fail if repository is not clone-able", func() {
		// Given
		config := modiff.NewConfig("invalid", topLevel, from, "", true, false, false, 1)

		// When
		res, err := modiff.Run(context.Background(), config)

		// Then
		Expect(err).To(HaveOccurred())
		Expect(res).To(BeEmpty())
	})

	It("should fail if the specified reference repository does not exist", func() {
		// Given
		config := modiff.NewConfig("", "invalid", from, "", true, false, false, 1)

		// When
		res, err := modiff.Run(context.Background(), config)

		// Then
		Expect(err).To(HaveOccurred())
		Expect(res).To(BeEmpty())
	})

	It("should fail if the repository url is invalid", func() {
		// Given: no reference clone, so Run() will attempt to clone the bad repo
		config := modiff.NewConfig(badRepo, "", from, to, true, false, false, 1)

		// When
		res, err := modiff.Run(context.Background(), config)

		// Then
		Expect(err).To(HaveOccurred())
		Expect(res).To(BeEmpty())
	})
})

var _ = t.Describe("DetectLocalRepository", func() {
	It("should detect this repository and its module", func() {
		// Given
		cwd, err := os.Getwd()
		Expect(err).ToNot(HaveOccurred())

		// When
		repository, topLevel, err := modiff.DetectLocalRepository(cwd)

		// Then
		Expect(err).ToNot(HaveOccurred())
		Expect(topLevel).ToNot(BeEmpty())
		Expect(filepath.Join(topLevel, "go.mod")).To(BeAnExistingFile())
		Expect(repository).To(HaveSuffix("/go-modiff"))
	})

	It("should fail outside of a git repository", func() {
		// Given
		dir := GinkgoT().TempDir()

		// When
		_, _, err := modiff.DetectLocalRepository(dir)

		// Then
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not part of a git repository"))
	})

	It("should fail in a git repository without a go module", func() {
		// Given
		dir := GinkgoT().TempDir()
		Expect(git.Run(dir, "init")).To(Succeed())

		// When
		_, _, err := modiff.DetectLocalRepository(dir)

		// Then
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not contain a go module"))
	})
})

func TestCheckURLValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		url      string
		expected bool
		err      error
		client   *http.Client
	}{
		{
			name:     "Valid URL",
			url:      "https://github.com/hashicorp/consul/compare/api/v1.18.0...api/v1.20.0",
			expected: true,
			err:      nil,
		},
		{
			name:     "Invalid URL",
			url:      "https://github.com/hashicorp/consul/compare/v1.18.0...v9.99.0",
			expected: false,
			err:      nil,
		},
		{
			name:     "Request Sending Error",
			url:      "invalid-url",
			expected: false,
			err:      fmt.Errorf("error while sending request: "),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := NewGomegaWithT(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			if tt.client == nil {
				tt.client = &http.Client{}
			}
			valid, err := modiff.CheckURLValid(*tt.client, tt.url)
			g.Expect(valid).To(Equal(tt.expected))
			if tt.err != nil {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.err.Error()))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
		})
	}
}
