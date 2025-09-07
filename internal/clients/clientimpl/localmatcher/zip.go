package localmatcher

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/google/osv-scanner/v2/internal/utility/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type ZipDB struct {
	// the name of the database
	Name string
	// the url that the zip archive was downloaded from
	ArchiveURL string
	// whether this database should make any network requests
	Offline bool
	// the path to the zip archive on disk
	StoredAt string
	// the vulnerabilities that are loaded into this database
	Vulnerabilities map[string][]osvschema.Vulnerability
	// User agent to query with
	UserAgent string
}

var ErrOfflineDatabaseNotFound = errors.New("no offline version of the OSV database is available")

func fetchRemoteArchiveCRC32CHash(ctx context.Context, url string) (uint32, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)

	if err != nil {
		return 0, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("db host returned %s", resp.Status)
	}

	for _, value := range resp.Header.Values("X-Goog-Hash") {
		if strings.HasPrefix(value, "crc32c=") {
			value = strings.TrimPrefix(value, "crc32c=")
			out, err := base64.StdEncoding.DecodeString(value)

			if err != nil {
				return 0, fmt.Errorf("could not decode crc32c= checksum: %w", err)
			}

			return binary.BigEndian.Uint32(out), nil
		}
	}

	return 0, errors.New("could not find crc32c= checksum")
}

func fetchLocalArchiveCRC32CHash(data []byte) uint32 {
	return crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))
}

func (db *ZipDB) fetchZip(ctx context.Context) ([]byte, error) {
	cache, err := os.ReadFile(db.StoredAt)

	if db.Offline {
		if err != nil {
			return nil, ErrOfflineDatabaseNotFound
		}

		return cache, nil
	}

	if err == nil {
		remoteHash, err := fetchRemoteArchiveCRC32CHash(ctx, db.ArchiveURL)

		if err != nil {
			return nil, err
		}

		if fetchLocalArchiveCRC32CHash(cache) == remoteHash {
			return cache, nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, db.ArchiveURL, nil)

	if err != nil {
		return nil, fmt.Errorf("could not retrieve OSV database archive: %w", err)
	}

	if db.UserAgent != "" {
		req.Header.Set("User-Agent", db.UserAgent)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve OSV database archive: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("db host returned %s", resp.Status)
	}

	var body []byte

	body, err = io.ReadAll(resp.Body)

	if err != nil {
		return nil, fmt.Errorf("could not read OSV database archive from response: %w", err)
	}

	err = os.MkdirAll(path.Dir(db.StoredAt), 0750)

	if err == nil {
		//nolint:gosec // being world readable is fine
		err = os.WriteFile(db.StoredAt, body, 0644)
	}

	if err != nil {
		cmdlogger.Warnf("Failed to save database to %s: %v", db.StoredAt, err)
	}

	return body, nil
}

type VulnerabilityLite struct {
	SchemaVersion    string                 `json:"schema_version,omitempty"    yaml:"schema_version,omitempty"`
	ID               string                 `json:"id"                          yaml:"id"`
	Modified         time.Time              `json:"modified"                    yaml:"modified"`
	Published        time.Time              `json:"published,omitempty"         yaml:"published,omitempty"`
	Withdrawn        time.Time              `json:"withdrawn,omitempty"         yaml:"withdrawn,omitempty"`
	Aliases          []string               `json:"aliases,omitempty"           yaml:"aliases,omitempty"`
	Related          []string               `json:"related,omitempty"           yaml:"related,omitempty"`
	Upstream         []string               `json:"upstream,omitempty"          yaml:"upstream,omitempty"`
	Summary          string                 `json:"summary,omitempty"           yaml:"summary,omitempty"`
	Details          string                 `json:"details,omitempty"           yaml:"details,omitempty"`
	Severity         []osvschema.Severity   `json:"severity,omitempty"          yaml:"severity,omitempty"`
	Affected         []AffectedLite         `json:"affected,omitempty"          yaml:"affected,omitempty"`
	References       []osvschema.Reference  `json:"references,omitempty"        yaml:"references,omitempty"`
	Credits          []osvschema.Credit     `json:"credits,omitempty"           yaml:"credits,omitempty"`
	DatabaseSpecific map[string]interface{} `json:"-" yaml:"database_specific,omitempty"`
}

type AffectedLite struct {
	Package           osvschema.Package      `json:"package,omitempty"            yaml:"package,omitempty"`
	Severity          []osvschema.Severity   `json:"severity,omitempty"           yaml:"severity,omitempty"`
	Ranges            []osvschema.Range      `json:"ranges,omitempty"             yaml:"ranges,omitempty"`
	Versions          []string               `json:"versions,omitempty"           yaml:"versions,omitempty"`
	DatabaseSpecific  map[string]interface{} `json:"-" yaml:"database_specific,omitempty"`
	EcosystemSpecific map[string]interface{} `json:"-" yaml:"ecosystem_specific,omitempty"`
}

// MarshalJSON implements the json.Marshaler interface.
//
// This method ensures Package is only present if it is not equal to the zero value.
// This is achieved by embedding the Affected struct with a pointer to Package used
// to populate the "package" key in the JSON object.
func (a AffectedLite) MarshalJSON() ([]byte, error) {
	type rawAffected AffectedLite // alias Affected to avoid recursion during Marshal
	type wrapper struct {
		Package *osvschema.Package `json:"package,omitempty"`
		rawAffected
	}
	raw := wrapper{rawAffected: rawAffected(a)}
	if a.Package == (osvschema.Package{}) {
		raw.Package = nil
	} else {
		raw.Package = &(a.Package)
	}

	return json.Marshal(raw)
}

func (a AffectedLite) ToAffected() osvschema.Affected {
	return osvschema.Affected{
		Package:           a.Package,
		Severity:          a.Severity,
		Ranges:            a.Ranges,
		Versions:          a.Versions,
		DatabaseSpecific:  a.DatabaseSpecific,
		EcosystemSpecific: a.EcosystemSpecific,
	}
}

// MarshalJSON implements the json.Marshaler interface.
//
// This method ensures all times are formatted correctly according to the schema.
func (v VulnerabilityLite) MarshalJSON() ([]byte, error) {
	type rawVulnerability VulnerabilityLite // alias Vulnerability to avoid recursion during Marshal
	type wrapper struct {
		Modified  string `json:"modified"`
		Published string `json:"published,omitempty"`
		Withdrawn string `json:"withdrawn,omitempty"`
		rawVulnerability
	}
	raw := wrapper{rawVulnerability: rawVulnerability(v)}
	raw.Modified = v.Modified.UTC().Format(time.RFC3339)
	if !v.Published.IsZero() {
		raw.Published = v.Published.UTC().Format(time.RFC3339)
	}
	if !v.Withdrawn.IsZero() {
		raw.Withdrawn = v.Withdrawn.UTC().Format(time.RFC3339)
	}

	return json.Marshal(raw)
}

func (v VulnerabilityLite) ToVulnerability() osvschema.Vulnerability {
	affected := make([]osvschema.Affected, len(v.Affected))

	for i := range v.Affected {
		affected[i] = v.Affected[i].ToAffected()
	}

	return osvschema.Vulnerability{
		SchemaVersion:    v.SchemaVersion,
		ID:               v.ID,
		Modified:         v.Modified,
		Published:        v.Published,
		Withdrawn:        v.Withdrawn,
		Aliases:          v.Aliases,
		Related:          v.Related,
		Upstream:         v.Upstream,
		Summary:          v.Summary,
		Details:          v.Details,
		Severity:         v.Severity,
		Affected:         affected,
		References:       v.References,
		Credits:          v.Credits,
		DatabaseSpecific: v.DatabaseSpecific,
	}
}

// Loads the given zip file into the database as an OSV.
// It is assumed that the file is JSON and in the working directory of the db
func (db *ZipDB) loadZipFile(zipFile *zip.File) {
	file, err := zipFile.Open()
	if err != nil {
		cmdlogger.Warnf("Could not read %s: %v", zipFile.Name, err)

		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		cmdlogger.Warnf("Could not read %s: %v", zipFile.Name, err)

		return
	}

	var vulnerability VulnerabilityLite

	if err := json.Unmarshal(content, &vulnerability); err != nil {
		cmdlogger.Warnf("%s is not a valid JSON file: %v", zipFile.Name, err)

		return
	}

	db.addVulnerability(vulnerability.ToVulnerability())
}

func (db *ZipDB) addVulnerability(vulnerability osvschema.Vulnerability) {
	for _, affected := range vulnerability.Affected {
		hash := string(affected.Package.Ecosystem) + "-" + affected.Package.Name
		vs := db.Vulnerabilities[hash]

		if vs == nil {
			vs = []osvschema.Vulnerability{}
		}

		db.Vulnerabilities[hash] = append(vs, vulnerability)
	}
}

func (db *ZipDB) writeZipFile(zipFile *zip.File, p string) error {
	dst, err := os.OpenFile(filepath.Join(p, zipFile.Name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
	if err != nil {
		return err
	}

	defer dst.Close()

	z, err := zipFile.Open()
	if err != nil {
		return err
	}

	defer z.Close()

	_, err = io.Copy(dst, z)

	return err
}

// load fetches a zip archive of the OSV database and loads known vulnerabilities
// from it (which are assumed to be in json files following the OSV spec).
//
// Internally, the archive is cached along with the date that it was fetched
// so that a new version of the archive is only downloaded if it has been
// modified, per HTTP caching standards.
func (db *ZipDB) load(ctx context.Context) error {
	db.Vulnerabilities = make(map[string][]osvschema.Vulnerability)

	body, err := db.fetchZip(ctx)

	if err != nil {
		return err
	}

	p := strings.TrimSuffix(db.StoredAt, "all.zip") + "extracted"

	err = os.MkdirAll(p, 0755)

	if err != nil {
		return err
	}
	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fmt.Errorf("could not read OSV database archive: %w", err)
	}

	// Read all the files from the zip archive
	for _, zipFile := range zipReader.File {
		if !strings.HasSuffix(zipFile.Name, ".json") {
			continue
		}

		err = db.writeZipFile(zipFile, p)

		if err != nil {
			return err
		}
	}

	err = db.loadFromDir(p)

	if err != nil {
		return err
	}

	return nil
}

func (db *ZipDB) loadFromDir(p string) error {
	errored := false

	err := filepath.Walk(p, func(path string, info fs.FileInfo, err error) error {
		if info == nil {
			return err
		}

		if err != nil {
			errored = true
			_, _ = fmt.Fprintf(os.Stderr, "\n    %v", err)

			return nil
		}

		if !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			errored = true
			_, _ = fmt.Fprintf(os.Stderr, "\n%v", err)

			return nil
		}

		var pa VulnerabilityLite
		if err := json.Unmarshal(content, &pa); err != nil {
			errored = true
			_, _ = fmt.Fprintf(os.Stderr, "%s is not a valid JSON file: %v\n", info.Name(), err)

			return nil
		}

		db.addVulnerability(pa.ToVulnerability())

		return nil
	})

	if errored {
		_, _ = fmt.Fprintf(os.Stderr, "\n")
	}

	if err != nil {
		return fmt.Errorf("could not read OSV database directory: %w", err)
	}

	return nil
}

func NewZippedDB(ctx context.Context, dbBasePath, name, url, userAgent string, offline bool) (*ZipDB, error) {
	db := &ZipDB{
		Name:       name,
		ArchiveURL: url,
		Offline:    offline,
		StoredAt:   path.Join(dbBasePath, name, "all.zip"),
		UserAgent:  userAgent,
	}
	if err := db.load(ctx); err != nil {
		return nil, fmt.Errorf("unable to fetch OSV database: %w", err)
	}

	return db, nil
}

func (db *ZipDB) VulnerabilitiesAffectingPackage(pkg imodels.PackageInfo) []*osvschema.Vulnerability {
	var vulnerabilities []*osvschema.Vulnerability

	// todo: need to confirm this actually will match the hash we generate from the osv
	hash := string(pkg.Ecosystem().String()) + "-" + pkg.Name()

	if vns, ok := db.Vulnerabilities[hash]; ok {
		for _, vulnerability := range vns {
			if vulnerability.Withdrawn.IsZero() && vulns.IsAffected(vulnerability, pkg) && !vulns.Include(vulnerabilities, vulnerability) {
				vulnerabilities = append(vulnerabilities, &vulnerability)
			}
		}
	}

	return vulnerabilities
}

// TODO: Move this to another file.
func VulnerabilitiesAffectingPackage(allVulns []osvschema.Vulnerability, pkg imodels.PackageInfo) []*osvschema.Vulnerability {
	var vulnerabilities []*osvschema.Vulnerability

	for _, vulnerability := range allVulns {
		if vulnerability.Withdrawn.IsZero() && vulns.IsAffected(vulnerability, pkg) && !vulns.Include(vulnerabilities, vulnerability) {
			vulnerabilities = append(vulnerabilities, &vulnerability)
		}
	}

	return vulnerabilities
}
