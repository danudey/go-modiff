// Package modiff is the core functionality and logic for git mod diffing
package modiff

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
)

func TestGetGoProxyModInfo(t *testing.T) {
	module := "github.com/example/repo"
	version := "v1.2.3"

	t.Run("returns parsed info including Origin", func(t *testing.T) {
		g := NewGomegaWithT(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g.Expect(r.URL.Path).To(Equal(fmt.Sprintf("/%s/@v/%s.info", module, version)))
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"Version":"v1.2.3","Time":"2024-01-01T00:00:00Z","Origin":{"VCS":"git","URL":"https://github.com/example/repo","Hash":"abc123","Ref":"refs/tags/v1.2.3"}}`)
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
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprint(w, "not json")
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
