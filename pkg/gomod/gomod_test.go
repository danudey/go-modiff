package gomod_test

//nolint:revive // test file
import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/saschagrunert/go-modiff/pkg/gomod"
)

const gitlabExampleURL = "https://gitlab.com/foo/bar"

func githubInfo(hash, ref string) gomod.Info {
	gm := gomod.Info{}
	gm.Origin.Vcs = "git"
	gm.Origin.URL = "https://github.com/example/repo"
	gm.Origin.Hash = hash
	gm.Origin.Ref = ref

	return gm
}

func googleSourceInfo(hash, ref string) gomod.Info {
	gm := gomod.Info{}
	gm.Origin.Vcs = "git"
	gm.Origin.URL = "https://go.googlesource.com/tools"
	gm.Origin.Hash = hash
	gm.Origin.Ref = ref

	return gm
}

var _ = Describe("gomod.Info", func() {
	Describe("IsGitHub", func() {
		It("returns true for GitHub origins", func() {
			gh := githubInfo("abc", "refs/tags/v1.0.0")
			Expect(gh.IsGitHub()).To(BeTrue())
		})

		It("returns false for non-GitHub origins", func() {
			gs := googleSourceInfo("abc", "refs/tags/v1.0.0")
			Expect(gs.IsGitHub()).To(BeFalse())
		})

		It("returns false for empty Info", func() {
			empty := gomod.Info{}
			Expect(empty.IsGitHub()).To(BeFalse())
		})
	})

	Describe("IsGoogleSource", func() {
		It("returns true for googlesource.com origins", func() {
			gs := googleSourceInfo("abc", "refs/tags/v1.0.0")
			Expect(gs.IsGoogleSource()).To(BeTrue())
		})

		It("returns false for non-googlesource origins", func() {
			gh := githubInfo("abc", "refs/tags/v1.0.0")
			Expect(gh.IsGoogleSource()).To(BeFalse())
		})

		It("returns false for empty Info", func() {
			empty := gomod.Info{}
			Expect(empty.IsGoogleSource()).To(BeFalse())
		})
	})

	Describe("IsGitHostWeKnow", func() {
		It("recognizes GitHub and googlesource", func() {
			gh := githubInfo("abc", "")
			gs := googleSourceInfo("abc", "")
			Expect(gh.IsGitHostWeKnow()).To(BeTrue())
			Expect(gs.IsGitHostWeKnow()).To(BeTrue())
		})

		It("does not recognize other hosts", func() {
			other := gomod.Info{}
			other.Origin.URL = gitlabExampleURL
			Expect(other.IsGitHostWeKnow()).To(BeFalse())
		})

		It("returns false for empty Info", func() {
			empty := gomod.Info{}
			Expect(empty.IsGitHostWeKnow()).To(BeFalse())
		})
	})

	Describe("CommitLink", func() {
		It("builds a GitHub commit link", func() {
			gm := githubInfo("deadbeef", "refs/tags/v1.0.0")
			Expect(gm.CommitLink()).To(Equal("https://github.com/example/repo/commit/deadbeef"))
		})

		It("builds a googlesource commit link", func() {
			gm := googleSourceInfo("cafef00d", "refs/tags/v0.1.0")
			Expect(gm.CommitLink()).To(Equal("https://go.googlesource.com/tools/+/cafef00d"))
		})

		It("dispatches by host", func() {
			gh := githubInfo("abc123", "refs/heads/main")
			Expect(gh.CommitLink()).To(Equal("https://github.com/example/repo/commit/abc123"))

			gs := googleSourceInfo("def456", "refs/heads/main")
			Expect(gs.CommitLink()).To(Equal("https://go.googlesource.com/tools/+/def456"))
		})

		It("returns empty string for unknown hosts", func() {
			other := gomod.Info{}
			other.Origin.URL = gitlabExampleURL
			other.Origin.Hash = "xyz"
			Expect(other.CommitLink()).To(Equal(""))
		})
	})

	Describe("GitHubCompareLinkTo", func() {
		DescribeTable("builds compare URLs",
			func(oldRef, oldHash, newRef, newHash, expected string) {
				oldInfo := githubInfo(oldHash, oldRef)
				newInfo := githubInfo(newHash, newRef)
				Expect(oldInfo.GitHubCompareLinkTo(&newInfo)).To(Equal(expected))
			},
			Entry("tag refs use tag names",
				"refs/tags/v1.0.0", "aaa", "refs/tags/v1.1.0", "bbb",
				"https://github.com/example/repo/compare/v1.0.0...v1.1.0"),
			Entry("no refs falls back to hashes",
				"", "aaaaaaa", "", "bbbbbbb",
				"https://github.com/example/repo/compare/aaaaaaa...bbbbbbb"),
			Entry("multi-segment refs keep remaining path after type",
				"refs/heads/release/v1", "aaa", "refs/heads/release/v2", "bbb",
				"https://github.com/example/repo/compare/release/v1...release/v2"),
			Entry("mixed: old ref, new hash",
				"refs/tags/v1.0.0", "aaa", "", "bbbbbbb",
				"https://github.com/example/repo/compare/v1.0.0...bbbbbbb"),
		)
	})

	Describe("GoogleSourceCompareLinkTo", func() {
		It("builds a googlesource compare URL", func() {
			oldInfo := googleSourceInfo("aaa", "refs/tags/v0.1.0")
			newInfo := googleSourceInfo("bbb", "refs/tags/v0.2.0")
			Expect(oldInfo.GoogleSourceCompareLinkTo(&newInfo)).
				To(Equal("https://go.googlesource.com/tools/+/aaa^1..bbb/"))
		})
	})

	Describe("CompareLinkTo", func() {
		It("dispatches to the GitHub builder", func() {
			gh := githubInfo("aaa", "refs/tags/v1.0.0")
			ghNew := githubInfo("bbb", "refs/tags/v1.1.0")
			Expect(gh.CompareLinkTo(&ghNew)).To(Equal("https://github.com/example/repo/compare/v1.0.0...v1.1.0"))
		})

		It("dispatches to the googlesource builder", func() {
			gs := googleSourceInfo("aaa", "refs/tags/v0.1.0")
			gsNew := googleSourceInfo("bbb", "refs/tags/v0.2.0")
			Expect(gs.CompareLinkTo(&gsNew)).To(Equal("https://go.googlesource.com/tools/+/aaa^1..bbb/"))
		})

		It("returns empty string for unknown hosts", func() {
			other := gomod.Info{}
			other.Origin.URL = gitlabExampleURL
			Expect(other.CompareLinkTo(&gomod.Info{})).To(Equal(""))
		})
	})
})
