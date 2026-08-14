// Package git contains functionality for interacting with Git repositories
package git

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/saschagrunert/go-modiff/pkg/utils"
	"github.com/sirupsen/logrus"
)

// DefaultRemote is the git remote consulted when looking up the URL of a
// repository.
const DefaultRemote = "origin"

// Runner executes shell commands on behalf of the git package.
// The default implementation delegates to pkg/utils; tests inject a mock.
type Runner interface {
	RunCmd(dir, cmd string, args ...string) error
	RunCmdOutput(dir, cmd string, args ...string) ([]byte, error)
}

type utilsRunner struct{}

func (utilsRunner) RunCmd(dir, cmd string, args ...string) error {
	return utils.RunCmd(dir, cmd, args...)
}

func (utilsRunner) RunCmdOutput(dir, cmd string, args ...string) ([]byte, error) {
	return utils.RunCmdOutput(dir, cmd, args...)
}

//nolint:gochecknoglobals // package-level runner is intentionally swappable for tests
var cmdRunner Runner = utilsRunner{}

// SetRunner replaces the runner used by package-level functions and returns a
// restore function that reinstalls the previous runner.
func SetRunner(r Runner) func() {
	prev := cmdRunner
	cmdRunner = r

	return func() { cmdRunner = prev }
}

// GetTopLevel takes a path to a git repository or subdirectory of one and returns the top-level directory
func GetTopLevel(path string) (string, error) {
	return RunOutput(path, "rev-parse", "--show-toplevel")
}

// RemoteURL returns the URL configured for the provided remote of the git
// repository in the provided directory
func RemoteURL(dir, remote string) (string, error) {
	return RunOutput(dir, "remote", "get-url", remote)
}

// NormalizeRemoteURL converts a git remote URL into a `host/path` repository
// name, so `git@github.com:owner/repo.git` becomes `github.com/owner/repo`.
// An empty string is returned if the URL does not address a remote host, for
// example when the remote is a local path.
func NormalizeRemoteURL(remoteURL string) string {
	rest := strings.TrimSpace(remoteURL)

	// Drop the scheme, like `https://` or `ssh://`
	if _, after, found := strings.Cut(rest, "://"); found {
		rest = after
	}

	// Drop any user info, like `git@`
	if _, after, found := strings.Cut(rest, "@"); found {
		rest = after
	}

	// Local paths are not remote repositories
	if strings.HasPrefix(rest, "/") ||
		strings.HasPrefix(rest, ".") ||
		strings.HasPrefix(rest, "~") {
		return ""
	}

	// The host is terminated by either a `/` (URL syntax) or a `:` (scp syntax)
	sep := strings.IndexAny(rest, ":/")
	if sep < 1 {
		return ""
	}
	host, path := rest[:sep], rest[sep+1:]

	// A numeric first path segment behind a `:` is a port, not a path
	if rest[sep] == ':' {
		if segment, after, found := strings.Cut(path, "/"); found {
			if _, err := strconv.Atoi(segment); err == nil {
				path = after
			}
		}
	}

	path = strings.Trim(path, "/")
	path = strings.TrimSuffix(path, ".git")

	// Hosts always carry a dot, which rules out local paths and `localhost`
	if path == "" || !strings.Contains(host, ".") {
		return ""
	}

	return host + "/" + path
}

// AddWorktree creates a new Git worktree from the provided repository at the provided destination
func AddWorktree(repoDir, destDir, gitRef string) error {
	logrus.Debugf("Setting up worktree for '%s' at %s", gitRef, destDir)
	// Detach so that refs which are already checked out elsewhere, like the
	// current branch of a reference clone, can still be used
	if err := Run(repoDir, "worktree", "add", "--detach", destDir, gitRef); err != nil {
		return fmt.Errorf("could not set up git worktree at %s: %w", destDir, err)
	}

	return nil
}

// RemoveWorktree removes a created Git worktree at the provided location
func RemoveWorktree(repoDir, destDir string) {
	logrus.Debugf("Removing worktree at %s", destDir)
	if err := Run(repoDir, "worktree", "remove", destDir); err != nil {
		logrus.WithError(err).Errorf("could not remove git worktree at %s", destDir)
	}
}

// Run executes a git command with the specified arguments, ignoring the output
func Run(dir string, args ...string) error {
	logrus.Debugf("Running command in %s: git %s", dir, strings.Join(args, " "))

	return cmdRunner.RunCmd(dir, "git", args...)
}

// RunOutput runs a git command with the specified arguments and returns the utf-8 output
func RunOutput(dir string, args ...string) (string, error) {
	logrus.Debugf("Running command in %s: git %s", dir, strings.Join(args, " "))
	output, err := cmdRunner.RunCmdOutput(dir, "git", args...)
	if err != nil {
		return "", fmt.Errorf("unable to execute git command: %w", err)
	}
	outputStr := strings.TrimSpace(string(output))

	return outputStr, nil
}
