package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SocialFootprint represents social media and public data findings
type SocialFootprint struct {
	Target      string           `json:"target"`
	Timestamp   time.Time        `json:"timestamp"`
	Identities  []Identity       `json:"identities"`
	Profiles    []Profile        `json:"profiles"`
	References  []WebReference   `json:"references"`
	Statistics  SearchStatistics `json:"statistics"`
}

type Identity struct {
	Username    string   `json:"username"`
	Platform    string   `json:"platform"`
	URL         string   `json:"url"`
	Active      bool     `json:"active"`
	LastUpdated string   `json:"last_updated,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type Profile struct {
	Platform    string                 `json:"platform"`
	Metadata    map[string]interface{} `json:"metadata"`
	LastUpdated time.Time             `json:"last_updated"`
	Confidence  float64               `json:"confidence"`
}

type WebReference struct {
	URL         string    `json:"url"`
	Title       string    `json:"title"`
	Type        string    `json:"type"`
	Found       time.Time `json:"found"`
	LastChecked time.Time `json:"last_checked"`
	Excerpt     string    `json:"excerpt,omitempty"`
}

type SearchStatistics struct {
	PlatformsChecked int       `json:"platforms_checked"`
	ProfilesFound    int       `json:"profiles_found"`
	ReferencesFound  int       `json:"references_found"`
	SearchTime       float64   `json:"search_time_seconds"`
	Timestamp        time.Time `json:"timestamp"`
}

// SocialAnalyzer performs social media and public data analysis
type SocialAnalyzer struct {
	client      *http.Client
	rateLimiter *RateLimiter
	platforms   []Platform
}

type Platform struct {
	Name           string
	URLPattern     string
	CheckEndpoint  string
	RequiresAuth   bool
	RateLimit      RateLimit
	ExtractProfile func(body []byte) (*Profile, error)
}

type RateLimit struct {
	RequestsPerMinute int
	BurstSize        int
}

func NewSocialAnalyzer() *SocialAnalyzer {
	return &SocialAnalyzer{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		rateLimiter: NewRateLimiter(30, time.Minute), // 30 requests per minute
		platforms:   defaultPlatforms(),
	}
}

// AnalyzeTarget performs comprehensive social media analysis
func (sa *SocialAnalyzer) AnalyzeTarget(ctx context.Context, target string) (*SocialFootprint, error) {
	startTime := time.Now()

	footprint := &SocialFootprint{
		Target:    target,
		Timestamp: startTime,
	}

	// Process usernames and domains separately
	if strings.Contains(target, "@") {
		sa.analyzeEmail(ctx, target, footprint)
	} else if strings.Contains(target, ".") {
		sa.analyzeDomain(ctx, target, footprint)
	} else {
		sa.analyzeUsername(ctx, target, footprint)
	}

	// Calculate statistics
	footprint.Statistics = SearchStatistics{
		PlatformsChecked: len(sa.platforms),
		ProfilesFound:    len(footprint.Profiles),
		ReferencesFound:  len(footprint.References),
		SearchTime:       time.Since(startTime).Seconds(),
		Timestamp:        time.Now(),
	}

	return footprint, nil
}

func (sa *SocialAnalyzer) analyzeUsername(ctx context.Context, username string, footprint *SocialFootprint) {
	var wg sync.WaitGroup
	results := make(chan Identity, len(sa.platforms))

	for _, platform := range sa.platforms {
		wg.Add(1)
		go func(p Platform) {
			defer wg.Done()

			if err := sa.rateLimiter.Wait(ctx); err != nil {
				return
			}

			if identity, err := sa.checkPlatform(ctx, username, p); err == nil {
				results <- identity
			}
		}(platform)
	}

	// Wait for all checks to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for identity := range results {
		footprint.Identities = append(footprint.Identities, identity)
		if identity.Active {
			if profile, err := sa.getProfile(ctx, identity); err == nil {
				footprint.Profiles = append(footprint.Profiles, *profile)
			}
		}
	}
}

func (sa *SocialAnalyzer) analyzeEmail(ctx context.Context, email string, footprint *SocialFootprint) {
	// Extract domain for analysis
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return
	}

	username, domain := parts[0], parts[1]

	// Check common services that use email
	services := []string{
		"gravatar.com",
		"about.me",
		"keybase.io",
	}

	for _, service := range services {
		if err := sa.rateLimiter.Wait(ctx); err != nil {
			continue
		}

		if identity, err := sa.checkEmailService(ctx, email, service); err == nil {
			footprint.Identities = append(footprint.Identities, identity)
		}
	}

	// Also check username variations
	sa.analyzeUsername(ctx, username, footprint)
}

func (sa *SocialAnalyzer) analyzeDomain(ctx context.Context, domain string, footprint *SocialFootprint) {
	// Check for company profiles
	platforms := []string{
		"linkedin.com/company/",
		"twitter.com/",
		"facebook.com/",
		"github.com/",
	}

	for _, platform := range platforms {
		if err := sa.rateLimiter.Wait(ctx); err != nil {
			continue
		}

		url := fmt.Sprintf("https://%s%s", platform, domain)
		if refs, err := sa.checkWebReference(ctx, url); err == nil {
			footprint.References = append(footprint.References, refs...)
		}
	}
}

func (sa *SocialAnalyzer) checkPlatform(ctx context.Context, username string, platform Platform) (Identity, error) {
	url := fmt.Sprintf(platform.URLPattern, username)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return Identity{}, err
	}

	resp, err := sa.client.Do(req)
	if err != nil {
		return Identity{}, err
	}
	defer resp.Body.Close()

	active := resp.StatusCode == http.StatusOK

	return Identity{
		Username: username,
		Platform: platform.Name,
		URL:      url,
		Active:   active,
		Tags:     sa.generateTags(platform.Name, active),
	}, nil
}

func (sa *SocialAnalyzer) getProfile(ctx context.Context, identity Identity) (*Profile, error) {
	// This would implement platform-specific profile extraction
	// For demonstration, returning a mock profile
	return &Profile{
		Platform: identity.Platform,
		Metadata: map[string]interface{}{
			"url":      identity.URL,
			"active":   identity.Active,
			"verified": false,
		},
		LastUpdated: time.Now(),
		Confidence:  0.85,
	}, nil
}

func (sa *SocialAnalyzer) checkEmailService(ctx context.Context, email, service string) (Identity, error) {
	// This would implement service-specific email checks
	// For demonstration, returning a mock identity
	return Identity{
		Username:    email,
		Platform:    service,
		URL:        fmt.Sprintf("https://%s/%s", service, email),
		Active:     true,
		LastUpdated: time.Now().Format(time.RFC3339),
	}, nil
}

func (sa *SocialAnalyzer) checkWebReference(ctx context.Context, url string) ([]WebReference, error) {
	// This would implement actual web reference checking
	// For demonstration, returning a mock reference
	return []WebReference{
		{
			URL:         url,
			Title:       "Company Profile",
			Type:        "business",
			Found:       time.Now(),
			LastChecked: time.Now(),
		},
	}, nil
}

func (sa *SocialAnalyzer) generateTags(platform string, active bool) []string {
	tags := []string{platform}
	if active {
		tags = append(tags, "active")
	}
	return tags
}

func defaultPlatforms() []Platform {
	return []Platform{
		{
			Name:       "GitHub",
			URLPattern: "https://api.github.com/users/%s",
			RateLimit: RateLimit{
				RequestsPerMinute: 30,
				BurstSize:        5,
			},
		},
		{
			Name:       "Twitter",
			URLPattern: "https://api.twitter.com/2/users/by/username/%s",
			RequiresAuth: true,
			RateLimit: RateLimit{
				RequestsPerMinute: 15,
				BurstSize:        3,
			},
		},
		// Add more platforms as needed
	}
}
