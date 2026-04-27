// Package git contains functionality for interacting with Git repositories
package git

import (
	"fmt"
	"strings"

	"github.com/saschagrunert/go-modiff/pkg/utils"
	"github.com/sirupsen/logrus"
)

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

// AddWorktree creates a new Git worktree from the provided repository at the provided destination
func AddWorktree(repoDir, destDir, gitRef string) error {
	logrus.Debugf("Setting up worktree for '%s' at %s", gitRef, destDir)
	if err := Run(repoDir, "worktree", "add", destDir, gitRef); err != nil {
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
