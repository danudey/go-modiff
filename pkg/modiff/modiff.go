package modiff

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"

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

func isGitHubURL(name string) bool {
	return strings.HasPrefix(name, "github.com")
}

func sanitizeTag(tag string) string {
	return strings.TrimSuffix(tag, "+incompatible")
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
		splitLinkPrefix := strings.Split(mod.linkPrefix, "/")
		prefixWithTree := fmt.Sprintf("%s/%s", mod.linkPrefix, "tree")
		if mod.beforeVersion == "" { //nolint: gocritic
			if addLinks && isGitHubURL(mod.linkPrefix) {
				// Insert the tree part of the URL at index 3 to account for tag names with slashes
				if len(splitLinkPrefix) >= 3 {
					prefixWithTree = strings.Join(slices.Insert(splitLinkPrefix, 3, "tree"), "/")
				}
				txt += fmt.Sprintf("[%s](%s/%s)",
					mod.afterVersion, toURL(prefixWithTree), sanitizeTag(mod.afterVersion))
			} else {
				txt += mod.afterVersion
			}
			added = append(added, txt)
		} else if mod.afterVersion == "" {
			if addLinks && isGitHubURL(mod.linkPrefix) {
				if len(splitLinkPrefix) >= 3 {
					prefixWithTree = strings.Join(slices.Insert(splitLinkPrefix, 3, "tree"), "/")
				}
				txt += fmt.Sprintf("[%s](%s/%s)",
					mod.beforeVersion, toURL(prefixWithTree), sanitizeTag(mod.beforeVersion))
			} else {
				txt += mod.beforeVersion
			}
			removed = append(removed, txt)
		} else if mod.beforeVersion != mod.afterVersion {
			if addLinks && isGitHubURL(mod.linkPrefix) {
				prefixWithCompare := fmt.Sprintf("%s/%s", mod.linkPrefix, "compare")
				// Insert tag prefix to the afterVersion to account for tag names with slashes
				afterVersion := sanitizeTag(mod.afterVersion)
				if len(splitLinkPrefix) > 3 {
					prefixWithCompare = strings.Join(slices.Insert(splitLinkPrefix, 3, "compare"), "/")
					afterVersion = fmt.Sprintf("%s/%s", strings.Join(splitLinkPrefix[3:], "/"), afterVersion)
				}
				txt += fmt.Sprintf("[%s → %s](%s/%s...%s)",
					mod.beforeVersion, mod.afterVersion, toURL(prefixWithCompare),
					sanitizeTag(mod.beforeVersion), afterVersion)
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
