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
}

type modules = map[string]entry

// Config is the structure passed to `Run`
type Config struct {
	repository  string
	from        string
	to          string
	link        bool
	headerLevel uint
}

// GoModInfo is the information struct returned from proxy.golang.org
type GoModInfo struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
	Origin  struct {
		Vcs  string `json:"VCS"`
		URL  string `json:"URL"`
		Hash string `json:"Hash"`
		Ref  string `json:"Ref"`
	} `json:"Origin"`
}

func (gm *GoModInfo) isGitHub() bool {
	return strings.Contains(gm.Origin.URL, "https://github.com/")
}

func (gm *GoModInfo) commitLink() string {
	return fmt.Sprintf("%s/commit/%s", gm.Origin.URL, gm.Origin.Hash)
}

func (gm *GoModInfo) CompareLinkTo(nm GoModInfo) string {
	if !gm.isGitHub() {
		return ""
	}
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
func NewConfig(repository, from, to string, link bool, headerLevel uint) *Config {
	return &Config{repository, from, to, link, headerLevel}
}

// Run starts go modiff and returns the markdown string
func Run(config *Config) (string, error) {
	// Enable to modules
	os.Setenv("GO111MODULE", "on")

	if config == nil {
		return logErr("cli context is nil")
	}
	// Validate the flags
	if config.repository == "" {
		return logErr("repository is required")
	}
	if config.from == config.to {
		return logErr("no diff possible if `from` equals `to`")
	}

	// Prepare the environment
	dir, err := os.MkdirTemp("", "go-modiff")
	if err != nil {
		return logErr(err)
	}
	defer os.RemoveAll(dir)

	referenceRepo := filepath.Join(dir, "reference")
	fromRepo := filepath.Join(dir, "from")
	toRepo := filepath.Join(dir, "to")

	logrus.Infof("Cloning base repository for %s to %s", config.repository, referenceRepo)
	if err := runGit(dir, "clone", "--filter=blob:none", "--bare", toURL(config.repository), referenceRepo); err != nil {
		return logErr(err)
	}

	logrus.Infof("Setting up 'from' repository for '%s' at %s", config.from, fromRepo)
	if err := runGit(dir, "clone", "--filter=blob:none", "--reference", referenceRepo, "-b", config.from, toURL(config.repository), fromRepo); err != nil {
		return logErr(err)
	}

	logrus.Infof("Setting up 'to' repository for '%s' at %s", config.to, toRepo)
	if err := runGit(dir, "clone", "--filter=blob:none", "--reference", referenceRepo, "-b", config.to, toURL(config.repository), toRepo); err != nil {
		return logErr(err)
	}

	// Retrieve and diff the modules
	mods, err := getModules(dir, config.from, config.to)
	if err != nil {
		return "", err
	}

	return diffModules(mods, config.link, config.headerLevel), nil
}

func toURL(name string) string {
	return "https://" + name
}

func isGitHubMod(mod GoModInfo) bool {
	return strings.Contains(mod.Origin.URL, "https://github.com/")
}

func sanitizeTag(tag string) string {
	return strings.TrimSuffix(tag, "+incompatible")
}

func getGoProxyModInfo(module, version string) (GoModInfo, error) {
	goModInfoURL := fmt.Sprintf("https://proxy.golang.org/%s/@v/%s.info", module, version)
	modInfo := GoModInfo{}
	resp, err := http.Get(goModInfoURL)
	if err != nil {
		return modInfo, fmt.Errorf("could not get go module info from golang module proxy: %w", err)
	}
	defer resp.Body.Close()

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

func logErr(msg interface{}) (string, error) {
	err := fmt.Errorf("%v", msg)
	logrus.Error(err)

	return "", err
}

func diffModules(mods modules, addLinks bool, headerLevel uint) string {
	var added, removed, changed []string
	for name, mod := range mods {
		txt := fmt.Sprintf("- %s: ", name)
		var oldModInfo GoModInfo
		var newModInfo GoModInfo
		var err error

		if mod.beforeVersion != "" {
			oldModInfo, err = getGoProxyModInfo(mod.linkPrefix, mod.beforeVersion)
			if err != nil {
				logrus.Errorf("could not fetch module info for %s@%s: %w", mod.linkPrefix, mod.beforeVersion, err)
			}
		}
		if mod.afterVersion != "" {
			newModInfo, err = getGoProxyModInfo(mod.linkPrefix, mod.afterVersion)
			if err != nil {
				logrus.Errorf("could not fetch module info for %s@%s: %w", mod.linkPrefix, mod.afterVersion, err)
			}
		}

		if mod.beforeVersion == "" { //nolint: gocritic
			if addLinks && newModInfo.isGitHub() {
				// Insert the tree part of the URL at index 3 to account for tag names with slashes
				txt += fmt.Sprintf("[%s](%s)",
					mod.afterVersion, newModInfo.commitLink())
			} else {
				txt += mod.afterVersion
			}
			added = append(added, txt)
		} else if mod.afterVersion == "" {
			if addLinks && oldModInfo.isGitHub() {
				txt += fmt.Sprintf("[%s](%s)",
					mod.beforeVersion, newModInfo.commitLink())
			} else {
				txt += mod.beforeVersion
			}
			removed = append(removed, txt)
		} else if mod.beforeVersion != mod.afterVersion {
			if addLinks && oldModInfo.isGitHub() {
				comparisonURL := oldModInfo.CompareLinkTo(newModInfo)
				if comparisonURL == "" {
					logrus.Warnf("Unable to get comparison information for %s")
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

func getModules(workDir, from, to string) (modules, error) {
	// Retrieve all modules
	before, err := retrieveModules(from, filepath.Join(workDir, "from"))
	if err != nil {
		return nil, err
	}
	after, err := retrieveModules(to, filepath.Join(workDir, "to"))
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
				logrus.Debugf("  Module %s has an extra segment '%s'; we need to see if it's part of the repository URL", name, splitLink[3])
				logrus.Debugf("    Checking this by fetching %s", url)
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
			res[name] = *entry
		}
	}
	forEach(before, func(res *entry, v string) { res.beforeVersion = v })
	forEach(after, func(res *entry, v string) { res.afterVersion = v })

	logrus.Infof("%d modules found", len(res))

	return res, nil
}

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
		resp.Body.Close()

		return false, nil
	}
	resp.Body.Close()

	return true, nil
}

func retrieveModules(rev, workDir string) (string, error) {
	logrus.Debugf("Listing go modules in %s", workDir)
	mods, err := runCmdOutput(
		workDir, "go", "list", "-mod=readonly", "-m", "all",
	)
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

func runCmdOutput(dir, cmd string, args ...string) ([]byte, error) {
	c := exec.Command(cmd, args...)
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
