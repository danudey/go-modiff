package modiff

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
)

func githubInfo(hash, ref string) GoModInfo {
	gm := GoModInfo{}
	gm.Origin.Vcs = "git"
	gm.Origin.URL = "https://github.com/example/repo"
	gm.Origin.Hash = hash
	gm.Origin.Ref = ref
	return gm
}

func googleSourceInfo(hash, ref string) GoModInfo {
	gm := GoModInfo{}
	gm.Origin.Vcs = "git"
	gm.Origin.URL = "https://go.googlesource.com/tools"
	gm.Origin.Hash = hash
	gm.Origin.Ref = ref
	return gm
}

func TestIsGitHub(t *testing.T) {
	t.Parallel()
	g := NewGomegaWithT(t)

	gh := githubInfo("abc", "refs/tags/v1.0.0")
	g.Expect(gh.isGitHub()).To(BeTrue())

	gs := googleSourceInfo("abc", "refs/tags/v1.0.0")
	g.Expect(gs.isGitHub()).To(BeFalse())

	empty := GoModInfo{}
	g.Expect(empty.isGitHub()).To(BeFalse())
}

func TestIsGoogleSource(t *testing.T) {
	t.Parallel()
	g := NewGomegaWithT(t)

	gs := googleSourceInfo("abc", "refs/tags/v1.0.0")
	g.Expect(gs.isGoogleSource()).To(BeTrue())

	gh := githubInfo("abc", "refs/tags/v1.0.0")
	g.Expect(gh.isGoogleSource()).To(BeFalse())

	empty := GoModInfo{}
	g.Expect(empty.isGoogleSource()).To(BeFalse())
}

func TestIsGitHostWeKnow(t *testing.T) {
	t.Parallel()
	g := NewGomegaWithT(t)

	gh := githubInfo("abc", "")
	g.Expect(gh.isGitHostWeKnow()).To(BeTrue())
	gs := googleSourceInfo("abc", "")
	g.Expect(gs.isGitHostWeKnow()).To(BeTrue())

	other := GoModInfo{}
	other.Origin.URL = "https://gitlab.com/foo/bar"
	g.Expect(other.isGitHostWeKnow()).To(BeFalse())

	empty := GoModInfo{}
	g.Expect(empty.isGitHostWeKnow()).To(BeFalse())
}

func TestGitHubCommitLink(t *testing.T) {
	t.Parallel()
	g := NewGomegaWithT(t)

	gm := githubInfo("deadbeef", "refs/tags/v1.0.0")
	g.Expect(gm.GitHubCommitLink()).To(Equal("https://github.com/example/repo/commit/deadbeef"))
}

func TestGoogleSourceCommitLink(t *testing.T) {
	t.Parallel()
	g := NewGomegaWithT(t)

	gm := googleSourceInfo("cafef00d", "refs/tags/v0.1.0")
	g.Expect(gm.GoogleSourceCommitLink()).To(Equal("https://go.googlesource.com/tools/+/cafef00d"))
}

func TestCommitLink(t *testing.T) {
	t.Parallel()
	g := NewGomegaWithT(t)

	gh := githubInfo("abc123", "refs/heads/main")
	g.Expect(gh.commitLink()).To(Equal("https://github.com/example/repo/commit/abc123"))

	gs := googleSourceInfo("def456", "refs/heads/main")
	g.Expect(gs.commitLink()).To(Equal("https://go.googlesource.com/tools/+/def456"))

	other := GoModInfo{}
	other.Origin.URL = "https://gitlab.com/foo/bar"
	other.Origin.Hash = "xyz"
	g.Expect(other.commitLink()).To(Equal(""))
}

func TestGitHubCompareLinkTo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		oldRef   string
		oldHash  string
		newRef   string
		newHash  string
		expected string
	}{
		{
			name:     "tag refs use tag names",
			oldRef:   "refs/tags/v1.0.0",
			oldHash:  "aaa",
			newRef:   "refs/tags/v1.1.0",
			newHash:  "bbb",
			expected: "https://github.com/example/repo/compare/v1.0.0...v1.1.0",
		},
		{
			name:     "no refs falls back to hashes",
			oldRef:   "",
			oldHash:  "aaaaaaa",
			newRef:   "",
			newHash:  "bbbbbbb",
			expected: "https://github.com/example/repo/compare/aaaaaaa...bbbbbbb",
		},
		{
			name:     "multi-segment refs keep remaining path after type",
			oldRef:   "refs/heads/release/v1",
			oldHash:  "aaa",
			newRef:   "refs/heads/release/v2",
			newHash:  "bbb",
			expected: "https://github.com/example/repo/compare/release/v1...release/v2",
		},
		{
			name:     "mixed: old ref, new hash",
			oldRef:   "refs/tags/v1.0.0",
			oldHash:  "aaa",
			newRef:   "",
			newHash:  "bbbbbbb",
			expected: "https://github.com/example/repo/compare/v1.0.0...bbbbbbb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := NewGomegaWithT(t)
			oldInfo := githubInfo(tt.oldHash, tt.oldRef)
			newInfo := githubInfo(tt.newHash, tt.newRef)
			g.Expect(oldInfo.GitHubCompareLinkTo(newInfo)).To(Equal(tt.expected))
		})
	}
}

func TestGoogleSourceCompareLinkTo(t *testing.T) {
	t.Parallel()
	g := NewGomegaWithT(t)

	oldInfo := googleSourceInfo("aaa", "refs/tags/v0.1.0")
	newInfo := googleSourceInfo("bbb", "refs/tags/v0.2.0")
	g.Expect(oldInfo.GoogleSourceCompareLinkTo(newInfo)).
		To(Equal("https://go.googlesource.com/tools/+/aaa^1..bbb/"))
}

func TestCompareLinkTo(t *testing.T) {
	t.Parallel()
	g := NewGomegaWithT(t)

	gh := githubInfo("aaa", "refs/tags/v1.0.0")
	ghNew := githubInfo("bbb", "refs/tags/v1.1.0")
	g.Expect(gh.CompareLinkTo(ghNew)).To(Equal("https://github.com/example/repo/compare/v1.0.0...v1.1.0"))

	gs := googleSourceInfo("aaa", "refs/tags/v0.1.0")
	gsNew := googleSourceInfo("bbb", "refs/tags/v0.2.0")
	g.Expect(gs.CompareLinkTo(gsNew)).To(Equal("https://go.googlesource.com/tools/+/aaa^1..bbb/"))

	other := GoModInfo{}
	other.Origin.URL = "https://gitlab.com/foo/bar"
	g.Expect(other.CompareLinkTo(GoModInfo{})).To(Equal(""))
}

func TestGetGoProxyModInfo(t *testing.T) {
	module := "github.com/example/repo"
	version := "v1.2.3"

	t.Run("returns parsed info including Origin", func(t *testing.T) {
		g := NewGomegaWithT(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g.Expect(r.URL.Path).To(Equal(fmt.Sprintf("/%s/@v/%s.info", module, version)))
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"Version":"v1.2.3","Time":"2024-01-01T00:00:00Z","Origin":{"VCS":"git","URL":"https://github.com/example/repo","Hash":"abc123","Ref":"refs/tags/v1.2.3"}}`)
		}))
		defer server.Close()

		t.Setenv("GOPROXY", server.URL)
		info, err := getGoProxyModInfo(module, version)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(info.Version).To(Equal("v1.2.3"))
		g.Expect(info.Origin.URL).To(Equal("https://github.com/example/repo"))
		g.Expect(info.Origin.Hash).To(Equal("abc123"))
		g.Expect(info.Origin.Ref).To(Equal("refs/tags/v1.2.3"))
	})

	t.Run("returns error on 404", func(t *testing.T) {
		g := NewGomegaWithT(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		t.Setenv("GOPROXY", server.URL)
		_, err := getGoProxyModInfo(module, version)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("does not exist"))
	})

	t.Run("returns error on malformed JSON", func(t *testing.T) {
		g := NewGomegaWithT(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "not json")
		}))
		defer server.Close()

		t.Setenv("GOPROXY", server.URL)
		_, err := getGoProxyModInfo(module, version)
		g.Expect(err).To(HaveOccurred())
	})

}

func TestNewConfig(t *testing.T) {
	t.Parallel()
	g := NewGomegaWithT(t)

	// Empty referenceClone stays empty
	cfg := NewConfig("github.com/foo/bar", "", "v1", "v2", true, false, 2)
	g.Expect(cfg).ToNot(BeNil())
	g.Expect(cfg.repository).To(Equal("github.com/foo/bar"))
	g.Expect(cfg.referenceClone).To(Equal(""))
	g.Expect(cfg.from).To(Equal("v1"))
	g.Expect(cfg.to).To(Equal("v2"))
	g.Expect(cfg.link).To(BeTrue())
	g.Expect(cfg.indirect).To(BeFalse())
	g.Expect(cfg.headerLevel).To(Equal(uint(2)))

	// Relative referenceClone path is resolved to absolute
	cfg = NewConfig("github.com/foo/bar", ".", "v1", "v2", false, true, 1)
	g.Expect(filepath.IsAbs(cfg.referenceClone)).To(BeTrue())
}
