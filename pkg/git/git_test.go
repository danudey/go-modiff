package git_test

//nolint:revive // test file
import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/saschagrunert/go-modiff/pkg/git"
	"github.com/saschagrunert/go-modiff/pkg/git/mocks"
)

var _ = Describe("git", func() {
	var (
		runner  *mocks.MockRunner
		restore func()
	)

	BeforeEach(func() {
		runner = mocks.NewMockRunner(GinkgoT())
		restore = git.SetRunner(runner)
	})

	AfterEach(func() {
		restore()
	})

	Describe("Run", func() {
		It("delegates to the runner with the git command", func() {
			runner.EXPECT().RunCmd("/repo", "git", "status").Return(nil).Once()

			Expect(git.Run("/repo", "status")).To(Succeed())
		})

		It("propagates runner errors", func() {
			boom := errors.New("boom")
			runner.EXPECT().RunCmd("/repo", "git", "fetch").Return(boom).Once()

			Expect(git.Run("/repo", "fetch")).To(MatchError(boom))
		})
	})

	Describe("RunOutput", func() {
		It("returns the trimmed stdout", func() {
			runner.EXPECT().
				RunCmdOutput("/repo", "git", "rev-parse", "HEAD").
				Return([]byte("  deadbeef\n"), nil).Once()

			out, err := git.RunOutput("/repo", "rev-parse", "HEAD")
			Expect(err).ToNot(HaveOccurred())
			Expect(out).To(Equal("deadbeef"))
		})

		It("wraps runner errors", func() {
			runner.EXPECT().
				RunCmdOutput("/repo", "git", "rev-parse", "HEAD").
				Return(nil, errors.New("exit 128")).Once()

			out, err := git.RunOutput("/repo", "rev-parse", "HEAD")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unable to execute git command"))
			Expect(out).To(BeEmpty())
		})
	})

	Describe("GetTopLevel", func() {
		It("shells out to `git rev-parse --show-toplevel`", func() {
			runner.EXPECT().
				RunCmdOutput("/some/path", "git", "rev-parse", "--show-toplevel").
				Return([]byte("/top/level\n"), nil).Once()

			top, err := git.GetTopLevel("/some/path")
			Expect(err).ToNot(HaveOccurred())
			Expect(top).To(Equal("/top/level"))
		})

		It("returns an error when git fails", func() {
			runner.EXPECT().
				RunCmdOutput("/not/a/repo", "git", "rev-parse", "--show-toplevel").
				Return(nil, errors.New("not a git repository")).Once()

			_, err := git.GetTopLevel("/not/a/repo")
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("RemoteURL", func() {
		It("shells out to `git remote get-url`", func() {
			runner.EXPECT().
				RunCmdOutput("/repo", "git", "remote", "get-url", "origin").
				Return([]byte("git@github.com:owner/repo.git\n"), nil).Once()

			url, err := git.RemoteURL("/repo", git.DefaultRemote)
			Expect(err).ToNot(HaveOccurred())
			Expect(url).To(Equal("git@github.com:owner/repo.git"))
		})

		It("returns an error when the remote is unknown", func() {
			runner.EXPECT().
				RunCmdOutput("/repo", "git", "remote", "get-url", "upstream").
				Return(nil, errors.New("no such remote")).Once()

			_, err := git.RemoteURL("/repo", "upstream")
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("NormalizeRemoteURL", func() {
		DescribeTable("returns the host and path of remote URLs",
			func(input, expected string) {
				Expect(git.NormalizeRemoteURL(input)).To(Equal(expected))
			},
			Entry("https", "https://github.com/owner/repo.git", "github.com/owner/repo"),
			Entry("https without suffix", "https://github.com/owner/repo", "github.com/owner/repo"),
			Entry("https with trailing slash", "https://github.com/owner/repo/", "github.com/owner/repo"),
			Entry("https with credentials", "https://user:token@github.com/owner/repo.git", "github.com/owner/repo"),
			Entry("scp syntax", "git@github.com:owner/repo.git", "github.com/owner/repo"),
			Entry("ssh scheme", "ssh://git@github.com/owner/repo.git", "github.com/owner/repo"),
			Entry("ssh scheme with port", "ssh://git@github.com:22/owner/repo.git", "github.com/owner/repo"),
			Entry("nested path", "https://gitlab.com/group/sub/repo.git", "gitlab.com/group/sub/repo"),
			Entry("surrounding whitespace", "  https://github.com/owner/repo.git\n", "github.com/owner/repo"),
			Entry("absolute local path", "/srv/git/repo.git", ""),
			Entry("relative local path", "../repo", ""),
			Entry("hostname without a dot", "git@localhost:owner/repo.git", ""),
			Entry("host without a path", "https://github.com", ""),
			Entry("empty", "", ""),
		)
	})

	Describe("AddWorktree", func() {
		It("invokes `git worktree add --detach <dest> <ref>`", func() {
			runner.EXPECT().
				RunCmd("/repo", "git", "worktree", "add", "--detach", "/dest", "v1.0.0").
				Return(nil).Once()

			Expect(git.AddWorktree("/repo", "/dest", "v1.0.0")).To(Succeed())
		})

		It("wraps the runner error with the destination path", func() {
			runner.EXPECT().
				RunCmd("/repo", "git", "worktree", "add", "--detach", "/dest", "bad-ref").
				Return(errors.New("unknown revision")).Once()

			err := git.AddWorktree("/repo", "/dest", "bad-ref")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("/dest"))
			Expect(err.Error()).To(ContainSubstring("worktree"))
		})
	})

	Describe("RemoveWorktree", func() {
		It("invokes `git worktree remove <dest>`", func() {
			runner.EXPECT().
				RunCmd("/repo", "git", "worktree", "remove", "/dest").
				Return(nil).Once()

			git.RemoveWorktree("/repo", "/dest")
		})

		It("swallows runner errors (logged, not returned)", func() {
			runner.EXPECT().
				RunCmd("/repo", "git", "worktree", "remove", "/dest").
				Return(errors.New("locked")).Once()

			Expect(func() { git.RemoveWorktree("/repo", "/dest") }).ToNot(Panic())
		})
	})
})
