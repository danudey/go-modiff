package main

import (
	"context"
	"fmt"

	clidocs "github.com/urfave/cli-docs/v3"
	"github.com/urfave/cli/v3"
)

const (
	docsCommandName = "docs"
	fishCommandName = "fish"
	markdownArg     = "markdown"
	manArg          = "man"

	// manSection is the man page section go-modiff documents itself in
	manSection = 8
)

// docsCommands returns the commands generating the documentation and the shell
// completions of the provided root command
func docsCommands(root *cli.Command) []*cli.Command {
	return []*cli.Command{
		{
			Name:    docsCommandName,
			Aliases: []string{"d"},
			Usage: "generate the markdown or man page documentation and " +
				"print it to stdout",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  markdownArg,
					Usage: "print the markdown version",
				},
				&cli.BoolFlag{
					Name:  manArg,
					Usage: "print the man version",
				},
			},
			Action: func(_ context.Context, c *cli.Command) error {
				var (
					res string
					err error
				)

				switch {
				case c.Bool(manArg):
					res, err = clidocs.ToManWithSection(root, manSection)
				case c.Bool(markdownArg):
					res, err = clidocs.ToMarkdown(root)
				default:
					return fmt.Errorf(
						"either --%s or --%s has to be provided",
						markdownArg, manArg,
					)
				}
				if err != nil {
					return fmt.Errorf("unable to generate the documentation: %w", err)
				}

				fmt.Print(res)

				return nil
			},
		},
		{
			Name:    fishCommandName,
			Aliases: []string{"f"},
			Usage:   "generate the fish shell completion and print it to stdout",
			Action: func(_ context.Context, _ *cli.Command) error {
				res, err := root.ToFishCompletion()
				if err != nil {
					return fmt.Errorf("unable to generate the fish completion: %w", err)
				}

				fmt.Print(res)

				return nil
			},
		},
	}
}
