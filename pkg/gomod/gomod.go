package gomod

import (
	"fmt"
	"strings"
	"time"
)

// Info is the information struct returned from proxy.golang.org
type Info struct {
	Version string    `json:"version"`
	Time    time.Time `json:"time"`
	Origin  struct {
		Vcs  string `json:"vcs"`
		URL  string `json:"url"`
		Hash string `json:"hash"`
		Ref  string `json:"ref"`
	} `json:"origin"`
}

func (gm *Info) IsGitHub() bool {
	return strings.HasPrefix(gm.Origin.URL, "https://github.com/")
}

func (gm *Info) IsGoogleSource() bool {
	return strings.HasPrefix(gm.Origin.URL, "https://go.googlesource.com/")
}

// IsGitHostWeKnow returns true if this is a git repository host that we know how to handle
func (gm *Info) IsGitHostWeKnow() bool {
	if gm.IsGitHub() || gm.IsGoogleSource() {
		return true
	}

	return false
}

// CommitLink returns a link to a given commit on the associated repository host
func (gm *Info) CommitLink() string {
	if gm.IsGitHub() {
		return gm.gitHubCommitLink()
	}
	if gm.IsGoogleSource() {
		return gm.googleSourceCommitLink()
	}

	return ""
}

// GitHubCommitLink creates a link to the given commit on Github's website
func (gm *Info) gitHubCommitLink() string {
	return fmt.Sprintf("%s/commit/%s", gm.Origin.URL, gm.Origin.Hash)
}

// GoogleSourceCommitLink creates a link to the given commit on the Google Source website
func (gm *Info) googleSourceCommitLink() string {
	return fmt.Sprintf("%s/+/%s", gm.Origin.URL, gm.Origin.Hash)
}

// CompareLinkTo creates a comparison link between two refs depending on which git host is being used
func (gm *Info) CompareLinkTo(nm *Info) string {
	if gm.IsGitHub() {
		return gm.GitHubCompareLinkTo(nm)
	}
	if gm.IsGoogleSource() {
		return gm.GoogleSourceCompareLinkTo(nm)
	}

	return ""
}

// GoogleSourceCompareLinkTo produces a comparison link between two refs for a Google Source repo
func (gm *Info) GoogleSourceCompareLinkTo(nm *Info) string {
	compareURL := fmt.Sprintf("%s/+/%s^1..%s/", gm.Origin.URL, gm.Origin.Hash, nm.Origin.Hash)

	return compareURL
}

// GitHubCompareLinkTo produces a comparison link between two refs for a Github repo
func (gm *Info) GitHubCompareLinkTo(nm *Info) string {
	var oldModRef string
	var newModRef string

	if strings.HasPrefix(gm.Origin.Ref, "refs/") {
		oldModRef = strings.SplitN(gm.Origin.Ref, "/", 3)[2]
	} else {
		oldModRef = gm.Origin.Hash
	}
	if strings.HasPrefix(nm.Origin.Ref, "refs/") {
		newModRef = strings.SplitN(nm.Origin.Ref, "/", 3)[2]
	} else {
		newModRef = nm.Origin.Hash
	}
	url := fmt.Sprintf("%s/compare/%s...%s", gm.Origin.URL, oldModRef, newModRef)

	return url
}
