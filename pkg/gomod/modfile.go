package gomod

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// ModFileName is the name of the file declaring a go module
const ModFileName = "go.mod"

// ModulePath reads the `go.mod` file in the provided directory and returns the
// module path it declares
func ModulePath(dir string) (string, error) {
	modFile := filepath.Join(dir, ModFileName)
	file, err := os.Open(modFile)
	if err != nil {
		return "", fmt.Errorf("unable to open %s: %w", modFile, err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if comment, _, found := strings.Cut(line, "//"); found {
			line = comment
		}

		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "module" {
			continue
		}

		modulePath := strings.Trim(fields[1], "\"`")
		if modulePath == "" {
			continue
		}

		return modulePath, nil
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("unable to read %s: %w", modFile, err)
	}

	return "", fmt.Errorf("no module directive found in %s", modFile)
}

// RepositoryPath strips the major version suffix, like `/v2`, from a module
// path so that the result can be used as a repository name
func RepositoryPath(modulePath string) string {
	dir, last := path.Split(modulePath)
	if dir == "" || !strings.HasPrefix(last, "v") {
		return modulePath
	}
	if _, err := strconv.Atoi(strings.TrimPrefix(last, "v")); err != nil {
		return modulePath
	}

	return strings.TrimSuffix(dir, "/")
}
