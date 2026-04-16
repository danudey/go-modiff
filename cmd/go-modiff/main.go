package main

import (
	"context"
	"fmt"
	"os"

	"github.com/saschagrunert/ccli/v3"
	"github.com/saschagrunert/go-modiff/pkg/modiff"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

const (
	repositoryArg     = "repository"
	referenceCloneArg = "reference-clone"
	fromArg           = "from"
	toArg             = "to"
	linkArg           = "link"
	headerLevelArg    = "header-level"
	includeIndirect   = "include-indirect"
	debugFlag         = "debug"
)

func main() {
	app := ccli.NewCommand()
	app.Name = "go-modiff"
	app.Version = "2.0.0"
	app.Authors = []any{
		"Sascha Grunert <mail@saschagrunert.de>",
		"Daniel Fox <dan.fox@tigera.io",
	}
	app.Usage = "Command line tool for diffing go module " +
		"dependency changes between versions"
	app.UsageText = app.Usage
	app.UseShortOptionHandling = true
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:      repositoryArg,
			Aliases:   []string{"r"},
			Usage:     "repository to be used, like: github.com/owner/repo",
			TakesFile: false,
		},
		&cli.StringFlag{
			Name:      referenceCloneArg,
			Usage:     "path to an existing clone to use as the reference",
			TakesFile: false,
		},
		&cli.StringFlag{
			Name:      fromArg,
			Aliases:   []string{"f"},
			Value:     "master",
			Usage:     "the start of the comparison, any valid git rev",
			TakesFile: false,
		},
		&cli.StringFlag{
			Name:      toArg,
			Aliases:   []string{"t"},
			Value:     "master",
			Usage:     "the end of the comparison, any valid git rev",
			TakesFile: false,
		},
		&cli.BoolFlag{
			Name:    linkArg,
			Aliases: []string{"l"},
			Usage:   "add diff links to the markdown output",
		},
		&cli.UintFlag{
			Name:    headerLevelArg,
			Aliases: []string{"i"},
			Value:   1,
			Usage:   "add a higher markdown header level depth",
		},
		&cli.BoolFlag{
			Name:    includeIndirect,
			Aliases: []string{"i"},
			Value:   false,
			Usage:   "include indirect imports",
		},
		&cli.BoolFlag{
			Name:    debugFlag,
			Aliases: []string{"d"},
			Usage:   "enable debug output",
		},
	}
	app.Action = func(ctx context.Context, c *cli.Command) error {
		// Init the logging facade
		logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
		if c.Bool("debug") {
			logrus.SetLevel(logrus.DebugLevel)
			logrus.Debug("Enabled debug output")
		} else {
			logrus.SetLevel(logrus.InfoLevel)
		}

		// Run modiff
		fmt.Println(c.Bool(includeIndirect))
		config := modiff.NewConfig(
			c.String(repositoryArg),
			c.String(referenceCloneArg),
			c.String(fromArg),
			c.String(toArg),
			c.Bool(linkArg),
			c.Bool(includeIndirect),
			c.Uint(headerLevelArg),
		)
		res, err := modiff.Run(ctx, config)
		if err != nil {
			return fmt.Errorf("unable to run: %w", err)
		}
		logrus.Info("Done, the result will be printed to `stdout`")
		fmt.Print(res)

		return nil
	}
	if err := app.Run(context.Background(), os.Args); err != nil {
		os.Exit(1)
	}
}
