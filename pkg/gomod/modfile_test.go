package gomod_test

//nolint:revive // test file
import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/saschagrunert/go-modiff/pkg/gomod"
)

var _ = Describe("ModulePath", func() {
	writeModFile := func(content string) string {
		dir := GinkgoT().TempDir()
		Expect(os.WriteFile(
			filepath.Join(dir, gomod.ModFileName), []byte(content), 0o600,
		)).To(Succeed())

		return dir
	}

	It("returns the declared module path", func() {
		dir := writeModFile("module github.com/owner/repo\n\ngo 1.26\n")

		Expect(gomod.ModulePath(dir)).To(Equal("github.com/owner/repo"))
	})

	It("ignores leading comments and blank lines", func() {
		dir := writeModFile("// a comment\n\nmodule github.com/owner/repo // trailing\n")

		Expect(gomod.ModulePath(dir)).To(Equal("github.com/owner/repo"))
	})

	It("unquotes the module path", func() {
		dir := writeModFile("module \"github.com/owner/repo\"\n")

		Expect(gomod.ModulePath(dir)).To(Equal("github.com/owner/repo"))
	})

	It("skips directives which only look like the module one", func() {
		dir := writeModFile("modulefoo bar\nmodule github.com/owner/repo\n")

		Expect(gomod.ModulePath(dir)).To(Equal("github.com/owner/repo"))
	})

	It("fails if there is no module directive", func() {
		dir := writeModFile("go 1.26\n")

		_, err := gomod.ModulePath(dir)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no module directive"))
	})

	It("fails if there is no go.mod file", func() {
		_, err := gomod.ModulePath(GinkgoT().TempDir())
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("RepositoryPath", func() {
	DescribeTable("strips the major version suffix",
		func(input, expected string) {
			Expect(gomod.RepositoryPath(input)).To(Equal(expected))
		},
		Entry("v2 suffix", "github.com/owner/repo/v2", "github.com/owner/repo"),
		Entry("multi digit suffix", "github.com/owner/repo/v10", "github.com/owner/repo"),
		Entry("no suffix", "github.com/owner/repo", "github.com/owner/repo"),
		Entry("versioned repository name", "github.com/owner/repo-v2", "github.com/owner/repo-v2"),
		Entry("non numeric suffix", "github.com/owner/repo/version", "github.com/owner/repo/version"),
		Entry("submodule", "github.com/owner/repo/pkg", "github.com/owner/repo/pkg"),
		Entry("single element", "repo", "repo"),
		Entry("empty", "", ""),
	)
})
