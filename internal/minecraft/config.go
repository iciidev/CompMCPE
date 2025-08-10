package minecraft

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// ConfigCheck represents a server configuration check
type ConfigCheck struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Category    CheckCategory `json:"category"`
	Severity    Severity     `json:"severity"`
	Status      CheckStatus  `json:"status"`
	Details     interface{} `json:"details,omitempty"`
	Remediation string       `json:"remediation,omitempty"`
}

type CheckCategory string

const (
	CategoryNetwork   CheckCategory = "NETWORK"
	CategorySecurity  CheckCategory = "SECURITY"
	CategoryPlugin    CheckCategory = "PLUGIN"
	CategoryResource  CheckCategory = "RESOURCE"
	CategoryGameplay  CheckCategory = "GAMEPLAY"
)

type CheckStatus string

const (
	StatusPass    CheckStatus = "PASS"
	StatusFail    CheckStatus = "FAIL"
	StatusWarning CheckStatus = "WARNING"
	StatusInfo    CheckStatus = "INFO"
)

// ConfigChecker performs server configuration analysis
type ConfigChecker struct {
	scanner     *BedrockScanner
	cveChecker  *CVEChecker
	rateLimiter *RateLimiter
	consent     bool
}

func NewConfigChecker(scanner *BedrockScanner, cveChecker *CVEChecker) *ConfigChecker {
	return &ConfigChecker{
		scanner:     scanner,
		cveChecker:  cveChecker,
		rateLimiter: NewRateLimiter(1, time.Second * 2), // Conservative rate limit
		consent:     false,
	}
}

// SetConsent sets the consent flag for invasive checks
func (cc *ConfigChecker) SetConsent(consent bool) {
	cc.consent = consent
}

// AnalyzeServer performs comprehensive configuration analysis
func (cc *ConfigChecker) AnalyzeServer(ctx context.Context, address string, port int) ([]ConfigCheck, error) {
	if err := cc.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit exceeded: %v", err)
	}

	var checks []ConfigCheck

	// Get basic server info first
	info, err := cc.scanner.ScanServer(ctx, address, port)
	if err != nil {
		return nil, fmt.Errorf("server scan failed: %v", err)
	}

	// Network security checks
	checks = append(checks, cc.checkNetworkSecurity(info)...)

	// Version and update checks
	checks = append(checks, cc.checkVersionSecurity(info)...)

	// Player limit and settings
	checks = append(checks, cc.checkPlayerSettings(info)...)

	// Plugin security (if detectable)
	if len(info.Plugins) > 0 {
		checks = append(checks, cc.checkPluginSecurity(info)...)
	}

	// Additional checks requiring consent
	if cc.consent {
		consentChecks, err := cc.runConsentRequiredChecks(ctx, address, port, info)
		if err != nil {
			checks = append(checks, ConfigCheck{
				Name:        "Consent-Required Checks",
				Description: "Some checks could not be completed",
				Category:    CategorySecurity,
				Severity:    Low,
				Status:      StatusWarning,
				Details:     err.Error(),
			})
		} else {
			checks = append(checks, consentChecks...)
		}
	}

	return checks, nil
}

func (cc *ConfigChecker) checkNetworkSecurity(info *ServerInfo) []ConfigCheck {
	var checks []ConfigCheck

	// Check default port usage
	checks = append(checks, ConfigCheck{
		Name:        "Default Port",
		Description: "Check if server uses default Bedrock port",
		Category:    CategoryNetwork,
		Severity:    Low,
		Status:      info.Port == DefaultBedrockPort ? StatusWarning : StatusPass,
		Details:     fmt.Sprintf("Server running on port %d", info.Port),
		Remediation: "Consider using a non-default port to reduce targeted scanning",
	})

	// Check player count exposure
	checks = append(checks, ConfigCheck{
		Name:        "Player Information Exposure",
		Description: "Check if server exposes detailed player information",
		Category:    CategorySecurity,
		Severity:    Medium,
		Status:      info.Players.Online > 0 ? StatusWarning : StatusPass,
		Details: map[string]interface{}{
			"online_visible": info.Players.Online > 0,
			"max_visible":    info.Players.Max > 0,
		},
		Remediation: "Consider hiding player counts if not required",
	})

	// MOTD information disclosure
	if containsSensitiveInfo(info.MOTD) {
		checks = append(checks, ConfigCheck{
			Name:        "MOTD Information Disclosure",
			Description: "Check for sensitive information in MOTD",
			Category:    CategorySecurity,
			Severity:    Medium,
			Status:      StatusWarning,
			Details:     "MOTD contains potentially sensitive information",
			Remediation: "Remove version numbers, internal details, or sensitive data from MOTD",
		})
	}

	return checks
}

func (cc *ConfigChecker) checkVersionSecurity(info *ServerInfo) []ConfigCheck {
	var checks []ConfigCheck

	// Version check
	versionInfo := cc.cveChecker.GetVersionInfo(info.Version)
	if versionInfo != nil {
		checks = append(checks, ConfigCheck{
			Name:        "Version Status",
			Description: "Check if server version is current and supported",
			Category:    CategorySecurity,
			Severity:    High,
			Status:      versionInfo.IsSupported ? StatusPass : StatusFail,
			Details: map[string]interface{}{
				"version":      info.Version,
				"is_supported": versionInfo.IsSupported,
				"release_date": versionInfo.ReleaseDate,
			},
			Remediation: "Update to the latest supported version",
		})
	}

	// CVE check
	if vulns := cc.cveChecker.CheckVersion(info.Version); len(vulns) > 0 {
		checks = append(checks, ConfigCheck{
			Name:        "Known Vulnerabilities",
			Description: "Check for known CVEs affecting this version",
			Category:    CategorySecurity,
			Severity:    Critical,
			Status:      StatusFail,
			Details:     vulns,
			Remediation: "Update to the latest version to patch known vulnerabilities",
		})
	}

	return checks
}

func (cc *ConfigChecker) checkPlayerSettings(info *ServerInfo) []ConfigCheck {
	var checks []ConfigCheck

	// Player limit configuration
	if info.Players.Max > 50 {
		checks = append(checks, ConfigCheck{
			Name:        "Player Limit Configuration",
			Description: "Check if player limit is securely configured",
			Category:    CategoryGameplay,
			Severity:    Low,
			Status:      StatusWarning,
			Details: map[string]interface{}{
				"max_players": info.Players.Max,
				"recommended": 50,
			},
			Remediation: "Consider lowering max player count to prevent DoS risks",
		})
	}

	return checks
}

func (cc *ConfigChecker) checkPluginSecurity(info *ServerInfo) []ConfigCheck {
	var checks []ConfigCheck

	// Known vulnerable plugins
	vulnerablePlugins := cc.detectVulnerablePlugins(info.Plugins)
	if len(vulnerablePlugins) > 0 {
		checks = append(checks, ConfigCheck{
			Name:        "Plugin Security",
			Description: "Check for known vulnerable plugins",
			Category:    CategoryPlugin,
			Severity:    High,
			Status:      StatusFail,
			Details:     vulnerablePlugins,
			Remediation: "Update or remove vulnerable plugins",
		})
	}

	return checks
}

func (cc *ConfigChecker) runConsentRequiredChecks(ctx context.Context, address string, port int, info *ServerInfo) ([]ConfigCheck, error) {
	var checks []ConfigCheck

	// Example of a more invasive check (requires consent)
	adminPanelCheck, err := cc.checkAdminInterfaces(ctx, address, port)
	if err != nil {
		return checks, err
	}
	checks = append(checks, adminPanelCheck...)

	return checks, nil
}

func (cc *ConfigChecker) checkAdminInterfaces(ctx context.Context, address string, port int) ([]ConfigCheck, error) {
	var checks []ConfigCheck

	// Common admin panel paths to check
	adminPaths := []string{
		"/admin",
		"/panel",
		"/console",
		"/manage",
	}

	for _, path := range adminPaths {
		// Simulate checking for admin interfaces
		// In production, this would make actual HTTP requests with proper consent
		checks = append(checks, ConfigCheck{
			Name:        "Admin Interface Exposure",
			Description: fmt.Sprintf("Check for exposed admin interface at %s", path),
			Category:    CategorySecurity,
			Severity:    High,
			Status:      StatusInfo,
			Details:     "Admin interface check simulated (consent required)",
			Remediation: "Ensure admin interfaces are properly secured and not publicly accessible",
		})
	}

	return checks, nil
}

func (cc *ConfigChecker) detectVulnerablePlugins(plugins []string) []string {
	// This would connect to a plugin vulnerability database in production
	// For now, using a mock list of vulnerable plugins
	vulnerablePlugins := map[string]bool{
		"OldAuthPlugin":     true,
		"LegacyWorldEdit":   true,
		"UnsafePermissions": true,
	}

	var detected []string
	for _, plugin := range plugins {
		if vulnerablePlugins[plugin] {
			detected = append(detected, plugin)
		}
	}

	return detected
}

func containsSensitiveInfo(motd string) bool {
	sensitivePatterns := []string{
		"version",
		"admin",
		"ip:",
		"port:",
		"debug",
		"test",
		"internal",
	}

	motdLower := strings.ToLower(motd)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(motdLower, pattern) {
			return true
		}
	}

	return false
}
