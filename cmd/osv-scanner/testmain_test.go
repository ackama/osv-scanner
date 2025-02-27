package main

import (
	"context"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/google/osv-scanner/v2/internal/clients/clientimpl/localmatcher"
	"github.com/google/osv-scanner/v2/internal/testdb"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

// muffledHandler eats certain log messages to reduce noise in the test output
type muffledHandler struct {
	slog.TextHandler
}

func (c *muffledHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Level < slog.LevelError {
		// todo: work with the osv-scalibr team to see if we can reduce these
		for _, prefix := range []string{
			"Starting filesystem walk for root:",
			"End status: ",
			"Neither CPE nor PURL found for package",
			"Invalid PURL",
			"os-release[ID] not set, fallback to",
			"VERSION_ID not set in os-release",
			"osrelease.ParseOsRelease(): file does not exist",
		} {
			if strings.HasPrefix(record.Message, prefix) {
				return nil
			}
		}
	}

	return c.TextHandler.Handle(ctx, record)
}

func newMuffledHandler(w io.Writer) *muffledHandler {
	return &muffledHandler{TextHandler: *slog.NewTextHandler(w, nil)}
}

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(newMuffledHandler(log.Writer())))

	// ensure a git repository doesn't already exist in the fixtures directory,
	// in case we didn't get a chance to clean-up properly in the last run
	os.RemoveAll("./fixtures/.git")

	// Temporarily make the fixtures folder a git repository to prevent gitignore files messing with tests.
	_, err := git.PlainInit("./fixtures", false)
	if err != nil {
		panic(err)
	}

	// localmatcher.ZippedDBRemoteHost = testdb.NewZipDBCacheServer().URL
	localmatcher.ZippedDBRemoteHost = testdb.NewZipDBCherryPickServer(map[string][]string{
		"RubyGems":  {},
		"Alpine":    {"CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843", "CVE-2018-25032", "CVE-2022-37434"},
		"Packagist": {},
		"Debian":    {},
		"Go": {
			"GO-2022-0452",
			"GHSA-f3fp-gc8g-vw66",
			"GO-2023-1683",
			"GHSA-g2j6-57v7-gm8c",
			"GO-2024-3110",
			"GHSA-jfvp-7x6p-h2pv",
			"GO-2023-1682",
			"GHSA-m8cg-xc2p-r3fc",
			"GO-2022-0274",
			"GHSA-v95c-p5hm-xq8f",
			"GO-2023-1627",
			"GHSA-vpvm-3wq2-2wvm",
			"GO-2024-2491",
			"GHSA-xr7r-f8xq-vfvv",
			"GO-2022-0493",
			"GHSA-p782-xgp4-8hr8",
		},
		"Maven":    {},
		"npm":      {"GHSA-whgm-jr23-g3j9"},
		"OSS-Fuzz": {},
	}).URL

	code := m.Run()

	testutility.CleanSnapshots(m)

	os.RemoveAll("./fixtures/.git")
	os.Exit(code)
}
