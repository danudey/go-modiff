package utils

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

func RunCmd(dir, cmd string, args ...string) error {
	_, err := RunCmdOutput(dir, cmd, args...)

	return err
}

func RunCmdOutput(dir, cmd string, args ...string) ([]byte, error) {
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
