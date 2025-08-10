package minecraft

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// CVEDatabase represents known Minecraft Bedrock vulnerabilities
type CVEDatabase struct {
	Vulnerabilities map[string][]CVEEntry `json:"vulnerabilities"` // version -> CVEs
	LastUpdated    time.Time             `json:"last_updated"`
}

type CVEEntry struct {
	ID           string    `json:"id"`
	Description  string    `json:"description"`
	Severity     Severity  `json:"severity"`
	AffectedVersions []string  `json:"affected_versions"`
	FixedVersion string    `json:"fixed_version,omitempty"`
	Published    time.Time `json:"published"`
	References   []string  `json:"references"`
	ExploitPOC   bool      `json:"exploit_poc"`
	CVSS        float64   `json:"cvss_score"`
}

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
)

// VersionInfo represents detailed Minecraft version information
type VersionInfo struct {
	Version     string    `json:"version"`
	Protocol    int       `json:"protocol"`
	ReleaseDate time.Time `json:"release_date"`
	IsSupported bool      `json:"is_supported"`
}

// CVEChecker handles version fingerprinting and vulnerability checking
type CVEChecker struct {
	db        *CVEDatabase
	versions  map[string]*VersionInfo
}

func NewCVEChecker() *CVEChecker {
	return &CVEChecker{
		db:       loadCVEDatabase(),
		versions: loadVersionDatabase(),
	}
}

// CheckVersion analyzes a Minecraft version for vulnerabilities
func (c *CVEChecker) CheckVersion(version string) []CVEEntry {
	var vulnerabilities []CVEEntry

	// Normalize version string
	version = normalizeVersion(version)

	// Check direct version matches
	if cves, ok := c.db.Vulnerabilities[version]; ok {
		vulnerabilities = append(vulnerabilities, cves...)
	}

	// Check version ranges
	for ver, cves := range c.db.Vulnerabilities {
		if isVersionInRange(version, ver) {
			for _, cve := range cves {
				if isAffectedVersion(version, cve.AffectedVersions) {
					vulnerabilities = append(vulnerabilities, cve)
				}
			}
		}
	}

	return vulnerabilities
}

// GetVersionInfo retrieves detailed information about a version
func (c *CVEChecker) GetVersionInfo(version string) *VersionInfo {
	version = normalizeVersion(version)
	if info, ok := c.versions[version]; ok {
		return info
	}
	return nil
}

// Helper functions for version comparison and normalization
func normalizeVersion(version string) string {
	// Remove "v" prefix if present
	version = strings.TrimPrefix(version, "v")
	
	// Handle special version formats
	if strings.HasPrefix(version, "1.") {
		parts := strings.Split(version, ".")
		if len(parts) >= 3 {
			// Ensure at least major.minor.patch format
			return strings.Join(parts[:3], ".")
		}
	}
	
	return version
}

func isVersionInRange(version, rangeStr string) bool {
	// Handle version range formats like "<=1.16.5" or "1.14.x"
	if strings.Contains(rangeStr, "x") {
		baseVer := strings.TrimSuffix(rangeStr, ".x")
		return strings.HasPrefix(version, baseVer)
	}

	if strings.HasPrefix(rangeStr, "<=") {
		maxVer := strings.TrimPrefix(rangeStr, "<=")
		return compareVersions(version, maxVer) <= 0
	}

	if strings.HasPrefix(rangeStr, "<") {
		maxVer := strings.TrimPrefix(rangeStr, "<")
		return compareVersions(version, maxVer) < 0
	}

	if strings.HasPrefix(rangeStr, ">=") {
		minVer := strings.TrimPrefix(rangeStr, ">=")
		return compareVersions(version, minVer) >= 0
	}

	if strings.HasPrefix(rangeStr, ">") {
		minVer := strings.TrimPrefix(rangeStr, ">")
		return compareVersions(version, minVer) > 0
	}

	return version == rangeStr
}

func compareVersions(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	for i := 0; i < len(aParts) && i < len(bParts); i++ {
		if aParts[i] < bParts[i] {
			return -1
		}
		if aParts[i] > bParts[i] {
			return 1
		}
	}

	if len(aParts) < len(bParts) {
		return -1
	}
	if len(aParts) > len(bParts) {
		return 1
	}
	return 0
}

func isAffectedVersion(version string, affected []string) bool {
	for _, v := range affected {
		if isVersionInRange(version, v) {
			return true
		}
	}
	return false
}

// loadCVEDatabase loads the CVE database
// In production, this would load from a file or API
func loadCVEDatabase() *CVEDatabase {
	// Example CVE database
	return &CVEDatabase{
		Vulnerabilities: map[string][]CVEEntry{
			"<=1.16.220": {
				{
					ID:          "CVE-2021-XXXXX",
					Description: "Remote code execution vulnerability in Bedrock server",
					Severity:    Critical,
					AffectedVersions: []string{"<=1.16.220"},
					FixedVersion: "1.16.221",
					Published:   time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
					References: []string{
						"https://example.com/cve-2021-xxxxx",
					},
					ExploitPOC: true,
					CVSS:      9.8,
				},
			},
			"1.17.x": {
				{
					ID:          "CVE-2021-YYYYY",
					Description: "Denial of service in player authentication",
					Severity:    High,
					AffectedVersions: []string{"1.17.0", "1.17.1", "1.17.2"},
					FixedVersion: "1.17.3",
					Published:   time.Date(2021, 6, 1, 0, 0, 0, 0, time.UTC),
					References: []string{
						"https://example.com/cve-2021-yyyyy",
					},
					ExploitPOC: false,
					CVSS:      7.5,
				},
			},
		},
		LastUpdated: time.Now(),
	}
}

// loadVersionDatabase loads the version information database
// In production, this would load from a file or API
func loadVersionDatabase() map[string]*VersionInfo {
	return map[string]*VersionInfo{
		"1.16.220": {
			Version:     "1.16.220",
			Protocol:    431,
			ReleaseDate: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
			IsSupported: false,
		},
		"1.17.0": {
			Version:     "1.17.0",
			Protocol:    440,
			ReleaseDate: time.Date(2021, 6, 1, 0, 0, 0, 0, time.UTC),
			IsSupported: false,
		},
		"1.17.1": {
			Version:     "1.17.1",
			Protocol:    441,
			ReleaseDate: time.Date(2021, 6, 15, 0, 0, 0, 0, time.UTC),
			IsSupported: false,
		},
	}
}
