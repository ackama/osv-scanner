package update

import (
	"errors"
	"fmt"
	"os"

	"github.com/google/osv-scanner/v2/internal/depsdev"
	"github.com/google/osv-scanner/v2/internal/remediation/suggest"
	"github.com/google/osv-scanner/v2/internal/resolution/client"
	"github.com/google/osv-scanner/v2/internal/resolution/manifest"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/lockfile"
	"github.com/urfave/cli/v2"
)

func Command() *cli.Command {
	return &cli.Command{
		Hidden: true,
		Name:   "update",
		Usage:  "[EXPERIMENTAL] scans a manifest file then updates dependencies",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:      "manifest",
				Aliases:   []string{"M"},
				Usage:     "path to manifest file (required)",
				TakesFile: true,
				Required:  true,
			},
			&cli.StringSliceFlag{
				Name:  "disallow-package-upgrades",
				Usage: "list of packages that disallow updates",
			},
			&cli.StringSliceFlag{
				Name:  "disallow-major-upgrades",
				Usage: "list of packages that disallow major updates",
			},
			&cli.BoolFlag{
				Name:  "ignore-dev",
				Usage: "whether to ignore development dependencies for updates",
			},
		},
		Action: func(ctx *cli.Context) error {
			return action(ctx)
		},
	}
}

type updateOptions struct {
	Manifest   string
	NoUpdates  []string
	AvoidMajor []string
	IgnoreDev  bool

	Client     client.ResolutionClient
	ManifestRW manifest.ReadWriter
}

func action(ctx *cli.Context) error {
	options := updateOptions{
		Manifest:   ctx.String("manifest"),
		NoUpdates:  ctx.StringSlice("disallow-package-upgrades"),
		AvoidMajor: ctx.StringSlice("disallow-major-upgrades"),
		IgnoreDev:  ctx.Bool("ignore-dev"),
	}
	if _, err := os.Stat(options.Manifest); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("file not found: %s", options.Manifest)
	} else if err != nil {
		return err
	}

	var err error
	options.Client.DependencyClient, err = client.NewDepsDevClient(depsdev.DepsdevAPI, "osv-scanner_update/"+version.OSVVersion)
	if err != nil {
		return err
	}
	options.ManifestRW, err = manifest.GetReadWriter(options.Manifest, "")
	if err != nil {
		return err
	}

	df, err := lockfile.OpenLocalDepFile(options.Manifest)
	if err != nil {
		return err
	}
	mf, err := options.ManifestRW.Read(df)
	df.Close() // Close the dep file and we may re-open it for writing
	if err != nil {
		return err
	}

	suggester, err := suggest.GetSuggester(mf.System())
	if err != nil {
		return err
	}
	patch, err := suggester.Suggest(ctx.Context, options.Client, mf, suggest.Options{
		IgnoreDev:  options.IgnoreDev,
		NoUpdates:  options.NoUpdates,
		AvoidMajor: options.AvoidMajor,
	})
	if err != nil {
		return err
	}

	return manifest.Overwrite(options.ManifestRW, options.Manifest, patch)
}
