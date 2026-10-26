// Package modiff is the core functionality and logic for git mod diffing
package modiff

//nolint:revive // test file
import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
)

const exampleModule = "github.com/example/repo"

func TestGetGoProxyModInfo(t *testing.T) {
	module := exampleModule
	version := "v1.2.3"

	t.Run("returns parsed info including Origin", func(t *testing.T) {
		g := NewGomegaWithT(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g.Expect(r.URL.Path).To(Equal(fmt.Sprintf("/%s/@v/%s.info", module, version)))
			w.Header().Set("Content-Type", "application/json")
			//nolint:lll // a single line json fixture
			_, _ = fmt.Fprint(w, `{"Version":"v1.2.3","Time":"2024-01-01T00:00:00Z","Origin":{"VCS":"git","URL":"https://github.com/example/repo","Hash":"abc123","Ref":"refs/tags/v1.2.3"}}`)
		}))
		defer server.Close()

		t.Setenv("GOPROXY", server.URL)
		info, err := getGoProxyModInfo(context.Background(), module, version)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(info.Version).To(Equal("v1.2.3"))
		g.Expect(info.Origin.URL).To(Equal("https://github.com/example/repo"))
		g.Expect(info.Origin.Hash).To(Equal("abc123"))
		g.Expect(info.Origin.Ref).To(Equal("refs/tags/v1.2.3"))
	})

	t.Run("returns error on 404", func(t *testing.T) {
		g := NewGomegaWithT(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		t.Setenv("GOPROXY", server.URL)
		_, err := getGoProxyModInfo(context.Background(), module, version)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("does not exist"))
	})

	t.Run("returns error on malformed JSON", func(t *testing.T) {
		g := NewGomegaWithT(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprint(w, "not json")
		}))
		defer server.Close()

		t.Setenv("GOPROXY", server.URL)
		_, err := getGoProxyModInfo(context.Background(), module, version)
		g.Expect(err).To(HaveOccurred())
	})

	t.Run("escapes uppercase letters in the module path", func(t *testing.T) {
		g := NewGomegaWithT(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g.Expect(r.URL.Path).To(Equal("/github.com/!de!ruina/timberjack/@v/v1.3.9.info"))
			_, _ = fmt.Fprint(w, `{"Version":"v1.3.9"}`)
		}))
		defer server.Close()

		t.Setenv("GOPROXY", server.URL)
		info, err := getGoProxyModInfo(context.Background(), "github.com/DeRuina/timberjack", "v1.3.9")
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(info.Version).To(Equal("v1.3.9"))
	})
}

func TestGoProxyServer(t *testing.T) {
	const exampleProxy = "https://example.com"

	for _, tc := range []struct {
		name, goproxy, expected string
	}{
		{"empty", "", defaultGoProxy},
		{"single proxy", exampleProxy, exampleProxy},
		{"trailing slash", exampleProxy + "/", exampleProxy},
		{"comma list", "https://a.example.com,https://b.example.com,direct", "https://a.example.com"},
		{"pipe list", "https://a.example.com|direct", "https://a.example.com"},
		{"skips keywords", "direct,https://b.example.com", "https://b.example.com"},
		{"only direct", "direct", defaultGoProxy},
		{"off", "off", defaultGoProxy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewGomegaWithT(t)
			t.Setenv("GOPROXY", tc.goproxy)
			g.Expect(goProxyServer()).To(Equal(tc.expected))
		})
	}
}

func TestDiffModulesNoChanges(t *testing.T) {
	t.Parallel()

	t.Run("prints a message instead of a lone header", func(t *testing.T) {
		t.Parallel()
		g := NewGomegaWithT(t)
		g.Expect(diffModules(context.Background(), modules{}, nil, false, false, false, 1)).
			To(Equal("_No dependency changes._\n"))
	})

	t.Run("keeps the empty sections when requested", func(t *testing.T) {
		t.Parallel()
		g := NewGomegaWithT(t)
		res := diffModules(context.Background(), modules{}, nil, false, false, true, 1)
		g.Expect(res).To(HavePrefix("# Dependencies\n"))
		g.Expect(res).To(ContainSubstring("## Added"))
		g.Expect(res).To(ContainSubstring("## Changed"))
		g.Expect(res).To(ContainSubstring("## Removed"))
	})
}

func TestDiffModulesGoSection(t *testing.T) {
	t.Parallel()

	t.Run("prints the go changes first", func(t *testing.T) {
		t.Parallel()
		g := NewGomegaWithT(t)
		res := diffModules(context.Background(), modules{}, []string{"- `go`: 1.25 → 1.26"}, true, false, false, 1)
		g.Expect(res).To(Equal("# Dependencies\n\n## Go\n- `go`: 1.25 → 1.26\n"))
	})

	t.Run("keeps the empty go section when requested", func(t *testing.T) {
		t.Parallel()
		g := NewGomegaWithT(t)
		res := diffModules(context.Background(), modules{}, nil, true, false, true, 1)
		g.Expect(res).To(HavePrefix("# Dependencies\n\n## Go\n_Nothing has changed._\n"))
	})

	t.Run("omits the go section if not included", func(t *testing.T) {
		t.Parallel()
		g := NewGomegaWithT(t)
		res := diffModules(context.Background(), modules{}, nil, false, false, true, 1)
		g.Expect(res).ToNot(ContainSubstring("## Go"))
	})
}

func TestDiffModulesPseudoVersions(t *testing.T) {
	g := NewGomegaWithT(t)
	const (
		before = "v0.0.0-20260414002931-afd174a4e478"
		after  = "v0.0.0-20260526163538-3dc84a4a5aaa"
	)

	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		_, _ = fmt.Fprint(w, `{"Origin":{"URL":"https://github.com/example/repo","Hash":"abc123"}}`)
	}))
	defer server.Close()

	t.Setenv("GOPROXY", server.URL)
	mods := modules{exampleModule: {
		beforeVersion: before,
		afterVersion:  after,
		linkPrefix:    exampleModule,
		name:          exampleModule,
	}}
	res := diffModules(context.Background(), mods, nil, false, true, false, 1)

	// The proxy cannot resolve abbreviated hashes, so it needs the full versions
	g.Expect(requested).To(ConsistOf(
		"/"+exampleModule+"/@v/"+before+".info",
		"/"+exampleModule+"/@v/"+after+".info",
	))
	// The output still shows the abbreviated hashes
	g.Expect(res).To(ContainSubstring("[afd174a → 3dc84a4]("))
}

func TestDiffGoVersions(t *testing.T) {
	t.Parallel()

	const (
		goVersion125 = "1.25"
		toolchain126 = "go1.26.0"
	)

	for _, tc := range []struct {
		name          string
		before, after []goVersion
		expected      []string
	}{
		{
			name:     "unchanged",
			before:   []goVersion{{goVersionName, goVersion125}, {toolchainVersionName, ""}},
			after:    []goVersion{{goVersionName, goVersion125}, {toolchainVersionName, ""}},
			expected: nil,
		},
		{
			name:     "changed",
			before:   []goVersion{{goVersionName, goVersion125}, {toolchainVersionName, "go1.25.1"}},
			after:    []goVersion{{goVersionName, "1.26"}, {toolchainVersionName, toolchain126}},
			expected: []string{"- `go`: 1.25 → 1.26", "- `toolchain`: go1.25.1 → go1.26.0"},
		},
		{
			name:     "added toolchain",
			before:   []goVersion{{goVersionName, goVersion125}, {toolchainVersionName, ""}},
			after:    []goVersion{{goVersionName, goVersion125}, {toolchainVersionName, toolchain126}},
			expected: []string{"- `toolchain`: none → go1.26.0"},
		},
		{
			name:     "removed toolchain",
			before:   []goVersion{{goVersionName, goVersion125}, {toolchainVersionName, toolchain126}},
			after:    []goVersion{{goVersionName, goVersion125}, {toolchainVersionName, ""}},
			expected: []string{"- `toolchain`: go1.26.0 → none"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := NewGomegaWithT(t)
			g.Expect(diffGoVersions(tc.before, tc.after)).To(Equal(tc.expected))
		})
	}
}

func TestParseGoVersionOutput(t *testing.T) {
	t.Parallel()
	g := NewGomegaWithT(t)

	version, err := parseGoVersionOutput("go version go1.26.1 linux/amd64\n")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(version).To(Equal("go1.26.1"))

	_, err = parseGoVersionOutput("something else")
	g.Expect(err).To(HaveOccurred())
}

func TestNewConfig(t *testing.T) {
	t.Parallel()
	g := NewGomegaWithT(t)

	// Empty referenceClone stays empty
	cfg := NewConfig("github.com/foo/bar", "", "v1", "v2", true, false, true, false, "", 2)
	g.Expect(cfg).ToNot(BeNil())
	g.Expect(cfg.repository).To(Equal("github.com/foo/bar"))
	g.Expect(cfg.referenceClone).To(Equal(""))
	g.Expect(cfg.from).To(Equal("v1"))
	g.Expect(cfg.to).To(Equal("v2"))
	g.Expect(cfg.link).To(BeTrue())
	g.Expect(cfg.indirect).To(BeFalse())
	g.Expect(cfg.empty).To(BeTrue())
	g.Expect(cfg.includeGo).To(BeFalse())
	g.Expect(cfg.goSource).To(Equal(GoVersionSourceModFile))
	g.Expect(cfg.headerLevel).To(Equal(uint(2)))

	// Relative referenceClone path is resolved to absolute
	cfg = NewConfig("github.com/foo/bar", ".", "v1", "v2", false, true, false, false, "", 1)
	g.Expect(filepath.IsAbs(cfg.referenceClone)).To(BeTrue())
}
