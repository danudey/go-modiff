// Package modiff is the core functionality and logic for git mod diffing
package modiff

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type entry struct {
	beforeVersion string
	afterVersion  string
	linkPrefix    string
	name          string
}

type modules = map[string]entry

// Config is the structure passed to `Run`
type Config struct {
	repository     string
	referenceClone string
	from           string
	to             string
	link           bool
	indirect       bool
	headerLevel    uint
}

// GoModInfo is the information struct returned from proxy.golang.org
type GoModInfo struct {
	Version string    `json:"version"`
	Time    time.Time `json:"time"`
	Origin  struct {
		Vcs  string `json:"vcs"`
		URL  string `json:"url"`
		Hash string `json:"hash"`
		Ref  string `json:"ref"`
	} `json:"origin"`
}

// GetGitTopLevel takes a path to a git repository or subdirectory of one and returns the top-level directory
func GetGitTopLevel(path string) (string, error) {
	return runGitOutput(path, "rev-parse", "--show-toplevel")
}

// AddGitWorktree creates a new Git worktree from the provided repository at the provided destination
func AddGitWorktree(repoDir, destDir, gitRef string) error {
	logrus.Debugf("Setting up worktree for '%s' at %s", gitRef, destDir)
	if err := runGit(repoDir, "worktree", "add", destDir, gitRef); err != nil {
		return fmt.Errorf("could not set up git worktree at %s: %w", destDir, err)
	}

	return nil
}

// RemoveGitWorktree removes a created Git worktree at the provided location
func RemoveGitWorktree(repoDir, destDir string) {
	logrus.Debugf("Removing worktree at %s", destDir)
	if err := runGit(repoDir, "worktree", "remove", destDir); err != nil {
		logrus.WithError(err).Errorf("could not remove git worktree at %s", destDir)
	}
}

func (gm *GoModInfo) isGitHub() bool {
	return strings.HasPrefix(gm.Origin.URL, "https://github.com/")
}

func (gm *GoModInfo) isGoogleSource() bool {
	return strings.HasPrefix(gm.Origin.URL, "https://go.googlesource.com/")
}

func (gm *GoModInfo) isGitHostWeKnow() bool {
	if gm.isGitHub() || gm.isGoogleSource() {
		return true
	}

	return false
}

func (gm *GoModInfo) commitLink() string {
	if gm.isGitHub() {
		return gm.GitHubCommitLink()
	}
	if gm.isGoogleSource() {
		return gm.GoogleSourceCommitLink()
	}

	return ""
}

// GitHubCommitLink creates a link to the given commit on Github's website
func (gm *GoModInfo) GitHubCommitLink() string {
	return fmt.Sprintf("%s/commit/%s", gm.Origin.URL, gm.Origin.Hash)
}

// GoogleSourceCommitLink creates a link to the given commit on the Google Source website
func (gm *GoModInfo) GoogleSourceCommitLink() string {
	return fmt.Sprintf("%s/+/%s", gm.Origin.URL, gm.Origin.Hash)
}

// CompareLinkTo creates a comparison link between two refs depending on which git host is being used
func (gm *GoModInfo) CompareLinkTo(nm *GoModInfo) string {
	if gm.isGitHub() {
		return gm.GitHubCompareLinkTo(nm)
	}
	if gm.isGoogleSource() {
		return gm.GoogleSourceCompareLinkTo(nm)
	}

	return ""
}

// GoogleSourceCompareLinkTo produces a comparison link between two refs for a Google Source repo
func (gm *GoModInfo) GoogleSourceCompareLinkTo(nm *GoModInfo) string {
	compareURL := fmt.Sprintf("%s/+/%s^1..%s/", gm.Origin.URL, gm.Origin.Hash, nm.Origin.Hash)

	return compareURL
}

// GitHubCompareLinkTo produces a comparison link between two refs for a Github repo
func (gm *GoModInfo) GitHubCompareLinkTo(nm *GoModInfo) string {
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

// NewConfig creates a new configuration
func NewConfig(repository, referenceClone, from, to string, link, includeIndirect bool, headerLevel uint) *Config {
	// Make sure we have an absolute path to our reference repository if we got one
	if referenceClone != "" {
		absClone, err := filepath.Abs(referenceClone)
		if err != nil {
			logrus.WithError(err).Errorf("couldn't get absolute path to reference repository `%s`", referenceClone)
		} else {
			referenceClone = absClone
		}
	}

	return &Config{repository, referenceClone, from, to, link, includeIndirect, headerLevel}
}

// Run starts go modiff and returns the markdown string
func Run(_ context.Context, config *Config) (string, error) {
	// Enable to modules
	err := os.Setenv("GO111MODULE", "on")
	if err != nil {
		return "", fmt.Errorf("unable to set GO111MODULE env var to on: %w", err)
	}

	// Validate the flags
	if config.repository == "" {
		return "", fmt.Errorf("no repository name was provided")
	}
	if config.from == config.to {
		return "", fmt.Errorf("`to` and `from` git refs cannot be equal")
	}

	// Prepare the environment
	dir, err := os.MkdirTemp("", "go-modiff")
	if err != nil {
		return "", fmt.Errorf("unable to create temporary directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	var referenceRepo string
	fromWorktreePath := filepath.Join(dir, "from")
	toWorktreePath := filepath.Join(dir, "to")

	if config.referenceClone != "" {
		referenceRepo = config.referenceClone
		logrus.Infof("Using %s as our reference repository", referenceRepo)
	} else {
		referenceRepo = filepath.Join(dir, "reference")
		logrus.Infof("Cloning base repository for %s to %s", config.repository, referenceRepo)
		if err := runGit(dir, "clone", "--filter=blob:none", "--bare", toURL(config.repository), referenceRepo); err != nil {
			return "", fmt.Errorf("unable to run git command: %w", err)
		}
	}

	logrus.Infof("Setting up 'from' worktree for '%s' at %s", config.from, fromWorktreePath)
	if err := AddGitWorktree(referenceRepo, fromWorktreePath, config.from); err != nil {
		return "", fmt.Errorf("unable to create git worktree: %w", err)
	}

	defer RemoveGitWorktree(referenceRepo, fromWorktreePath)

	logrus.Infof("Setting up 'to' worktree for '%s' at %s", config.to, toWorktreePath)
	if err := AddGitWorktree(referenceRepo, toWorktreePath, config.to); err != nil {
		return "", fmt.Errorf("unable to create git worktree: %w", err)
	}

	defer RemoveGitWorktree(referenceRepo, toWorktreePath)

	// Retrieve and diff the modules
	mods, err := getModules(dir, config.from, config.to, config.indirect)
	if err != nil {
		return "", err
	}

	return diffModules(mods, config.link, config.headerLevel), nil
}

func toURL(name string) string {
	return "https://" + name
}

func getGoProxyModInfo(module, version string) (GoModInfo, error) {
	var goProxyServer string
	goProxyVar, exists := os.LookupEnv("GOPROXY")

	if exists {
		goProxyServer = goProxyVar
	} else {
		goProxyServer = "https://proxy.golang.org"
	}
	goModInfoURL := fmt.Sprintf("%s/%s/@v/%s.info", goProxyServer, module, version)
	modInfo := GoModInfo{}
	logrus.Debugf("Fetching go mod info for %s from %s", module, goModInfoURL)
	resp, err := http.Get(goModInfoURL)
	if err != nil {
		return modInfo, fmt.Errorf("could not get go module info from golang module proxy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return modInfo, fmt.Errorf("golang proxy says module version %s@%s does not exist", module, version)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return modInfo, fmt.Errorf("could not get response body from golang module proxy: %w", err)
	}

	if err := json.Unmarshal(body, &modInfo); err != nil {
		return modInfo, fmt.Errorf("could not decode response body from golang module proxy: %w", err)
	}

	return modInfo, nil
}

func diffModules(mods modules, addLinks bool, headerLevel uint) string {
	var added, removed, changed []string
	for name, mod := range mods {
		var oldModInfo GoModInfo
		var newModInfo GoModInfo
		var err error
		var txt string

		if mod.beforeVersion != "" {
			oldModInfo, err = getGoProxyModInfo(mod.name, mod.beforeVersion)
			if err != nil {
				logrus.WithError(err).Errorf("could not fetch module info for %s@%s", mod.linkPrefix, mod.beforeVersion)
			}
		}
		if mod.afterVersion != "" {
			newModInfo, err = getGoProxyModInfo(mod.name, mod.afterVersion)
			if err != nil {
				logrus.WithError(err).Errorf("could not fetch module info for %s@%s", mod.linkPrefix, mod.afterVersion)
			}
		}

		var modURL string
		if oldModInfo.Origin.URL != "" {
			modURL = oldModInfo.Origin.URL
		} else if newModInfo.Origin.URL != "" {
			modURL = newModInfo.Origin.URL
		}

		if modURL != "" && addLinks {
			txt = fmt.Sprintf("- [`%s`](%s): ", name, modURL)
		} else {
			txt = fmt.Sprintf("- `%s`: ", name)
		}

		if mod.beforeVersion == "" { //nolint: gocritic
			if addLinks && newModInfo.isGitHostWeKnow() {
				// Insert the tree part of the URL at index 3 to account for tag names with slashes
				txt += fmt.Sprintf("[%s](%s)",
					mod.afterVersion, newModInfo.commitLink())
			} else {
				txt += mod.afterVersion
			}
			added = append(added, txt)
		} else if mod.afterVersion == "" {
			if addLinks && oldModInfo.isGitHostWeKnow() {
				txt += fmt.Sprintf("[%s](%s)",
					mod.beforeVersion, newModInfo.commitLink())
			} else {
				txt += mod.beforeVersion
			}
			removed = append(removed, txt)
		} else if mod.beforeVersion != mod.afterVersion {
			if addLinks && oldModInfo.isGitHostWeKnow() {
				comparisonURL := oldModInfo.CompareLinkTo(&newModInfo)
				if comparisonURL == "" {
					logrus.Warnf("Unable to get comparison information for %s", mod.linkPrefix)
					txt += fmt.Sprintf("%s → %s", mod.beforeVersion, mod.afterVersion)
				} else {
					txt += fmt.Sprintf("[%s → %s](%s)",
						mod.beforeVersion, mod.afterVersion, comparisonURL)
				}
			} else {
				txt += fmt.Sprintf("%s → %s", mod.beforeVersion, mod.afterVersion)
			}
			changed = append(changed, txt)
		}
	}
	sort.Strings(added)
	sort.Strings(changed)
	sort.Strings(removed)
	logrus.Infof("%d modules added", len(added))
	logrus.Infof("%d modules changed", len(changed))
	logrus.Infof("%d modules removed", len(removed))

	// Pretty print
	builder := &strings.Builder{}
	fmt.Fprintf(
		builder, "%s Dependencies\n", strings.Repeat("#", int(headerLevel)),
	)
	forEach := func(section string, input []string) {
		fmt.Fprintf(
			builder,
			"\n%s %s\n", strings.Repeat("#", int(headerLevel)+1), section,
		)
		if len(input) > 0 {
			for _, mod := range input {
				fmt.Fprintf(builder, "%s\n", mod)
			}
		} else {
			builder.WriteString("_Nothing has changed._\n")
		}
	}
	forEach("Added", added)
	forEach("Changed", changed)
	forEach("Removed", removed)

	return builder.String()
}

func getModules(workDir, from, to string, indirect bool) (modules, error) {
	// Retrieve all modules
	before, err := retrieveModules(filepath.Join(workDir, "from"), indirect)
	if err != nil {
		return nil, err
	}
	after, err := retrieveModules(filepath.Join(workDir, "to"), indirect)
	if err != nil {
		return nil, err
	}

	// Make a list of all the lines we've seen in
	// before and in after, so we can skip any lines
	// which are in both (and therefore have not changed)
	seenBefore := make(map[string]bool)
	seenAfter := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(before))
	for scanner.Scan() {
		val := scanner.Text()
		seenBefore[val] = true
	}
	scanner = bufio.NewScanner(strings.NewReader(after))
	for scanner.Scan() {
		val := scanner.Text()
		seenAfter[val] = true
	}

	logrus.Info("Processing module diffs")
	// Parse the modules
	res := modules{}
	forEach := func(input string, do func(res *entry, version string)) {
		scanner := bufio.NewScanner(strings.NewReader(input))
		for scanner.Scan() {
			val := scanner.Text()
			if seenBefore[val] && seenAfter[val] {
				logrus.Debugf("Skipping duplicate line: %s", val)

				continue
			}

			// Skip version-less modules, like the local one
			split := strings.Split(val, " ")
			if len(split) < 2 {
				continue
			}
			// Rewrites have to be handled differently
			if len(split) > 2 && split[2] == "=>" {
				// Local rewrites without any version will be skipped
				if len(split) == 4 {
					continue
				}

				// Use the rewritten version and name if available
				if len(split) == 5 {
					split[0] = split[3]
					split[1] = split[4]
				}
			}

			name := strings.TrimSpace(split[0])
			linkPrefix := name
			logrus.Debugf("Processing module %s", name)
			// Remove the module name from the link
			if splitLink := strings.Split(linkPrefix, "/"); len(splitLink) == 4 {
				// Check if the last part of string is part of the tag.
				linkPrefixTree := strings.Join(slices.Insert(splitLink, 3, "tree"), "/")
				url := fmt.Sprintf("https://%s%s%s", linkPrefixTree, "/", strings.TrimSpace(split[1]))
				logrus.Debugf("  Module %s has an extra segment '%s'", name, splitLink[3])
				logrus.Debugf("    Checking if it's part of the repo URL by fetching %s", url)
				// If the url is valid, then we keep the linkPrefix as is
				client := http.Client{}
				if valid, err := CheckURLValid(client, url); !valid && err == nil {
					linkPrefix = strings.Join(splitLink[:3], "/")
					logrus.Debugf("    It's not; using %s as link prefix", linkPrefix)
				} else {
					logrus.Debugf("    It is; using %s as link prefix", linkPrefix)
				}
			}
			version := strings.TrimSpace(split[1])

			// Prettify pseudo versions
			vSplit := strings.Split(version, "-")
			if len(vSplit) > 2 {
				v := vSplit[len(vSplit)-1]
				if len(v) > 7 {
					version = v[:7]
				} else {
					// This should never happen but who knows what go modules
					// will do next
					version = v
				}
			}

			// Process the entry
			entry := &entry{}
			if val, ok := res[name]; ok {
				entry = &val
			}
			do(entry, version)
			entry.linkPrefix = linkPrefix
			entry.name = name
			res[name] = *entry
		}
	}
	forEach(before, func(res *entry, v string) { res.beforeVersion = v })
	forEach(after, func(res *entry, v string) { res.afterVersion = v })

	logrus.Infof("%d modules found", len(res))

	return res, nil
}

// CheckURLValid validates that a URL exists by making an HTTP HEAD request to it
func CheckURLValid(client http.Client, url string) (bool, error) {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("error while creating request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("error while sending request: %w", err)
	} else if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()

		return false, nil
	}
	_ = resp.Body.Close()

	return true, nil
}

func retrieveModules(workDir string, indirect bool) (string, error) {
	logrus.Debugf("Listing go modules in %s", workDir)
	cmdArgs := []string{"list"}
	if !indirect {
		cmdArgs = append(cmdArgs, "-f", "{{if not .Indirect }}{{.String}}{{end}}")
	}
	cmdArgs = append(cmdArgs, "-mod=readonly", "-m", "all")
	mods, err := runCmdOutput(workDir, "go", cmdArgs...)
	if err != nil {
		logrus.Error(err)

		return "", err
	}

	return strings.TrimSpace(string(mods)), nil
}

func runGit(dir string, args ...string) error {
	logrus.Debugf("Running command in %s: git %s", dir, strings.Join(args, " "))

	return runCmd(dir, "git", args...)
}

func runCmd(dir, cmd string, args ...string) error {
	_, err := runCmdOutput(dir, cmd, args...)

	return err
}

func runGitOutput(dir string, args ...string) (string, error) {
	logrus.Debugf("Running command in %s: git %s", dir, strings.Join(args, " "))
	output, err := runCmdOutput(dir, "git", args...)
	if err != nil {
		return "", fmt.Errorf("unable to execute git command: %w", err)
	}
	outputStr := strings.TrimSpace(string(output))

	return outputStr, nil
}

func runCmdOutput(dir, cmd string, args ...string) ([]byte, error) {
	c := exec.CommandContext(context.Background(), cmd, args...)
	c.Stderr = nil
	c.Dir = dir

	output, err := c.Output()
	if err != nil {
		var exitError *exec.ExitError
		stderr := []byte{}
		if errors.As(err, &exitError) {
			stderr = exitError.Stderr
		}

		return nil, fmt.Errorf(
			"unable to run cmd: %s %s, workdir: %s, stdout: %s, stderr: %v, error: %w",
			cmd,
			strings.Join(args, " "),
			dir,
			string(output),
			string(stderr),
			err,
		)
	}

	return output, nil
}
