package output

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/v2/internal/imodels/ecosystem"
	depgroups "github.com/google/osv-scanner/v2/internal/utility/depgroup"
	"github.com/google/osv-scanner/v2/internal/utility/severity"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

// OSVBaseVulnerabilityURL is the base URL for detailed vulnerability views.
// Copied in from osv package to avoid referencing the osv package unnecessarily
const OSVBaseVulnerabilityURL = "https://osv.dev/"

// PrintTableResults prints the osv scan results into a human friendly table.
func PrintTableResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer, terminalWidth int) {
	if terminalWidth <= 0 {
		text.DisableColors()
	}

	outputResult := BuildResults(vulnResult)

	// Render the vulnerabilities.
	if outputResult.IsContainerScanning {
		printContainerScanningResult(outputResult, outputWriter, terminalWidth)
	} else {
		outputTable := newTable(outputWriter, terminalWidth)
		outputTable = tableBuilder(outputTable, outputResult)
		if outputTable.Length() != 0 {
			outputTable.Render()
		}

		// Render the licenses if any.
		licenseConfig := vulnResult.ExperimentalAnalysisConfig.Licenses
		if licenseConfig.Summary {
			buildLicenseSummaryTable(outputWriter, terminalWidth, vulnResult)
		}
		if len(licenseConfig.Allowlist) > 0 {
			buildLicenseViolationsTable(outputWriter, terminalWidth, vulnResult)
		}
	}
}

func newTable(outputWriter io.Writer, terminalWidth int) table.Writer {
	outputTable := table.NewWriter()
	outputTable.SetOutputMirror(outputWriter)

	// use fancy characters if we're outputting to a terminal
	if terminalWidth > 0 {
		outputTable.SetStyle(table.StyleRounded)
		outputTable.SetAllowedRowLength(terminalWidth)
	}

	outputTable.Style().Options.DoNotColorBordersAndSeparators = true
	outputTable.Style().Color.Row = text.Colors{text.Reset, text.BgHiBlack}
	outputTable.Style().Color.RowAlternate = text.Colors{text.Reset, text.BgBlack}

	return outputTable
}

func tableBuilder(outputTable table.Writer, result Result) table.Writer {
	outputTable.AppendHeader(table.Row{"OSV URL", "CVSS", "Ecosystem", "Package", "Version", "Source"})
	rows := tableBuilderInner(result, VulnTypeRegular)
	for _, elem := range rows {
		outputTable.AppendRow(elem.row, table.RowConfig{AutoMerge: elem.shouldMerge})
	}

	uncalledRows := tableBuilderInner(result, VulnTypeUncalled)
	if len(uncalledRows) != 0 {
		outputTable.AppendSeparator()
		outputTable.AppendRow(table.Row{"Uncalled vulnerabilities"})
		outputTable.AppendSeparator()

		for _, elem := range uncalledRows {
			outputTable.AppendRow(elem.row, table.RowConfig{AutoMerge: elem.shouldMerge})
		}
	}

	unimportantRows := tableBuilderInner(result, VulnTypeUnimportant)
	if len(unimportantRows) != 0 {
		outputTable.AppendSeparator()
		outputTable.AppendRow(table.Row{"Unimportant vulnerabilities"})
		outputTable.AppendSeparator()

		for _, elem := range unimportantRows {
			outputTable.AppendRow(elem.row, table.RowConfig{AutoMerge: elem.shouldMerge})
		}
	}

	return outputTable
}

func printContainerScanningResult(result Result, outputWriter io.Writer, terminalWidth int) {
	// Add a newline to separate results from logs.
	fmt.Fprintln(outputWriter)
	fmt.Fprintf(outputWriter, "Container Scanning Result (%s):\n", result.ImageInfo.OS)
	printSummary(result, outputWriter)
	// Add a newline
	fmt.Fprintln(outputWriter)

	if result.LicenseSummary.Summary {
		printLicenseSummary(result.LicenseSummary, outputWriter, terminalWidth)
	}

	for _, eco := range result.Ecosystems {
		fmt.Fprintln(outputWriter, eco.Name)

		for _, source := range eco.Sources {
			outputTable := newTable(outputWriter, terminalWidth)
			outputTable.SetTitle("Source:" + source.Name)
			tableHeader := table.Row{"Package", "Installed Version", "Fix Available", "Vuln Count", "Introduced Layer", "In Base Image"}
			if result.LicenseSummary.ShowViolations {
				tableHeader = append(tableHeader, "License Violations")
			}

			outputTable.AppendHeader(tableHeader)
			for _, pkg := range source.Packages {
				if pkg.VulnCount.AnalysisCount.Regular == 0 && len(pkg.LicenseViolations) == 0 {
					continue
				}
				outputRow := table.Row{}
				totalCount := pkg.VulnCount.AnalysisCount.Regular
				var fixAvailable string
				if pkg.FixedVersion == UnfixedDescription {
					fixAvailable = UnfixedDescription
				} else {
					if pkg.VulnCount.FixableCount.UnFixed > 0 {
						fixAvailable = "Partial fixes Available"
					} else {
						fixAvailable = "Fix Available"
					}
				}

				layer := fmt.Sprintf("# %d Layer", pkg.LayerDetail.LayerIndex)

				inBaseImage := "--"
				if pkg.LayerDetail.BaseImageInfo.Index != 0 {
					inBaseImage = getBaseImageName(pkg.LayerDetail.BaseImageInfo)
				}
				outputRow = append(outputRow, pkg.Name, getInstalledVersionOrCommit(pkg), fixAvailable, totalCount, layer, inBaseImage)
				if result.LicenseSummary.ShowViolations {
					if len(pkg.LicenseViolations) == 0 {
						outputRow = append(outputRow, "--")
					} else {
						outputRow = append(outputRow, pkg.LicenseViolations)
					}
				}
				outputTable.AppendRow(outputRow)
			}
			outputTable.Render()
		}
	}

	if result.VulnTypeSummary.Hidden != 0 {
		// Add a newline
		fmt.Fprintln(outputWriter)
		fmt.Fprintln(outputWriter, "Filtered Vulnerabilities:")
		outputTable := newTable(outputWriter, terminalWidth)
		outputTable.AppendHeader(table.Row{"Package", "Ecosystem", "Installed Version", "Filtered Vuln Count", "Filter Reasons"})
		for _, eco := range result.Ecosystems {
			for _, source := range eco.Sources {
				for _, pkg := range source.Packages {
					if pkg.VulnCount.AnalysisCount.Hidden == 0 {
						continue
					}
					outputRow := table.Row{}
					totalCount := pkg.VulnCount.AnalysisCount.Hidden
					filteredReasons := getFilteredVulnReasons(pkg.HiddenVulns)
					outputRow = append(outputRow, pkg.Name, eco.Name, getInstalledVersionOrCommit(pkg), totalCount, filteredReasons)
					outputTable.AppendRow(outputRow)
				}
			}
		}
		outputTable.Render()
	}

	// Add a newline
	fmt.Fprintln(outputWriter)

	const promptMessage = "For the most comprehensive scan results, we recommend using the HTML output: " +
		"`osv-scanner scan image --serve <image_name>`.\n" +
		"You can also view the full vulnerability list in your terminal with: " +
		"`osv-scanner scan image --format vertical <image_name>`."
	fmt.Fprintln(outputWriter, promptMessage)
}

func printLicenseSummary(licenseSummary LicenseSummary, outputWriter io.Writer, terminalWidth int) {
	outputTable := newTable(outputWriter, terminalWidth)
	outputTable.AppendHeader(table.Row{"License", "No. of package versions"})
	for _, license := range licenseSummary.LicenseCount {
		outputTable.AppendRow(table.Row{license.Name, license.Count})
	}

	outputTable.Render()

	fmt.Fprintln(outputWriter)
}

type tbInnerResponse struct {
	row         table.Row
	shouldMerge bool
}

func tableBuilderInner(result Result, vulnAnalysisType VulnAnalysisType) []tbInnerResponse {
	allOutputRows := []tbInnerResponse{}
	// workingDir := mustGetWorkingDirectory()

	for _, eco := range result.Ecosystems {
		for _, source := range eco.Sources {
			for _, pkg := range source.Packages {
				var everything []VulnResult

				everything = append(everything, pkg.RegularVulns...)
				everything = append(everything, pkg.HiddenVulns...)

				for _, vuln := range everything {
					outputRow := table.Row{}
					shouldMerge := false

					var links []string

					if vuln.VulnAnalysisType != vulnAnalysisType {
						continue
					}

					for _, id := range vuln.GroupIDs {
						links = append(links, OSVBaseVulnerabilityURL+text.Bold.Sprintf("%s", id))

						// For container scanning results, if there is a DSA, then skip printing its sub-CVEs.
						if strings.Split(id, "-")[0] == "DSA" {
							break
						}
					}

					outputRow = append(outputRow, strings.Join(links, "\n"))

					// todo: this is just to make the snapshots pass without change
					if vuln.SeverityScore == "N/A" {
						outputRow = append(outputRow, "")
					} else {
						outputRow = append(outputRow, vuln.SeverityScore)
					}

					outputRow = append(outputRow, eco.Name)

					name := pkg.Name

					// TODO(#1646): Migrate this earlier to the result struct directly
					if depgroups.IsDevGroup(ecosystem.MustParse(eco.Name).Ecosystem, pkg.DepGroups) {
						name += " (dev)"
					}
					outputRow = append(outputRow, name)
					outputRow = append(outputRow, pkg.InstalledVersion)
					outputRow = append(outputRow, pkg.Path)

					allOutputRows = append(allOutputRows, tbInnerResponse{
						row:         outputRow,
						shouldMerge: shouldMerge,
					})
				}
			}
		}
	}

	return allOutputRows
}

func MaxSeverity(group models.GroupInfo, pkg models.PackageVulns) string {
	var maxSeverity float64 = -1
	for _, vulnID := range group.IDs {
		var severities []osvschema.Severity
		for _, vuln := range pkg.Vulnerabilities {
			if vuln.ID == vulnID {
				severities = vuln.Severity
			}
		}
		score, _, _ := severity.CalculateOverallScore(severities)
		maxSeverity = max(maxSeverity, score)
	}

	if maxSeverity < 0 {
		return ""
	}

	return fmt.Sprintf("%.1f", maxSeverity)
}

func buildLicenseSummaryTable(outputWriter io.Writer, terminalWidth int, vulnResult *models.VulnerabilityResults) {
	outputTable := newTable(outputWriter, terminalWidth)
	licenseSummaryTableBuilder(outputTable, vulnResult)
	if outputTable.Length() == 0 {
		return
	}
	outputTable.Render()
}

func licenseSummaryTableBuilder(outputTable table.Writer, vulnResult *models.VulnerabilityResults) table.Writer {
	outputTable.AppendHeader(table.Row{"License", "No. of package versions"})
	for _, license := range vulnResult.LicenseSummary {
		outputTable.AppendRow(table.Row{license.Name, license.Count})
	}

	return outputTable
}

func buildLicenseViolationsTable(outputWriter io.Writer, terminalWidth int, vulnResult *models.VulnerabilityResults) {
	outputTable := newTable(outputWriter, terminalWidth)

	outputTable = licenseViolationsTableBuilder(outputTable, vulnResult)
	if outputTable.Length() == 0 {
		return
	}
	outputTable.Render()
}

func licenseViolationsTableBuilder(outputTable table.Writer, vulnResult *models.VulnerabilityResults) table.Writer {
	outputTable.AppendHeader(table.Row{"License Violation", "Ecosystem", "Package", "Version", "Source"})
	workingDir := mustGetWorkingDirectory()
	for _, pkgSource := range vulnResult.Results {
		for _, pkg := range pkgSource.Packages {
			if len(pkg.LicenseViolations) == 0 {
				continue
			}
			violations := make([]string, len(pkg.LicenseViolations))
			for i, l := range pkg.LicenseViolations {
				violations[i] = string(l)
			}
			path := pkgSource.Source.Path
			if simplifiedPath, err := filepath.Rel(workingDir, pkgSource.Source.Path); err == nil {
				path = simplifiedPath
			}
			outputTable.AppendRow(table.Row{
				strings.Join(violations, ", "),
				pkg.Package.Ecosystem,
				pkg.Package.Name,
				pkg.Package.Version,
				path,
			})
		}
	}

	return outputTable
}
