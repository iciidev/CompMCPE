package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ASNInfo represents detailed ASN and IP intelligence
type ASNInfo struct {
	IP          string     `json:"ip"`
	ASN         string     `json:"asn"`
	Range       IPRange    `json:"range"`
	Organization string    `json:"organization"`
	Country     string     `json:"country"`
	City        string     `json:"city"`
	Abuse       AbuseInfo  `json:"abuse,omitempty"`
	Timestamp   time.Time  `json:"timestamp"`
}

type IPRange struct {
	Start    string `json:"start"`
	End      string `json:"end"`
	CIDR     string `json:"cidr"`
	NumHosts int    `json:"num_hosts"`
}

type AbuseInfo struct {
	Email    string   `json:"email"`
	Phone    string   `json:"phone,omitempty"`
	Network  string   `json:"network"`
	Reports  []Report `json:"reports,omitempty"`
}

type Report struct {
	Category    string    `json:"category"`
	ReportedAt  time.Time `json:"reported_at"`
	Source      string    `json:"source"`
	Description string    `json:"description"`
}

// ASNAnalyzer performs ASN and IP intelligence gathering
type ASNAnalyzer struct {
	client      *http.Client
	rateLimiter *RateLimiter
	// Cache for ASN data to prevent redundant lookups
	cache map[string]*ASNInfo
}

func NewASNAnalyzer() *ASNAnalyzer {
	return &ASNAnalyzer{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		rateLimiter: NewRateLimiter(2, time.Second), // 2 queries per second
		cache:       make(map[string]*ASNInfo),
	}
}

// AnalyzeIP performs comprehensive IP and ASN analysis
func (aa *ASNAnalyzer) AnalyzeIP(ctx context.Context, ipAddr string) (*ASNInfo, error) {
	if err := aa.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit exceeded: %v", err)
	}

	// Check cache first
	if info, exists := aa.cache[ipAddr]; exists {
		if time.Since(info.Timestamp) < 1*time.Hour {
			return info, nil
		}
	}

	// Parse and validate IP
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipAddr)
	}

	info := &ASNInfo{
		IP:        ipAddr,
		Timestamp: time.Now(),
	}

	// Query IP/ASN data from free APIs
	if err := aa.enrichWithIPInfo(ctx, info); err != nil {
		return nil, fmt.Errorf("IP info enrichment failed: %v", err)
	}

	if err := aa.enrichWithAbuseInfo(ctx, info); err != nil {
		// Don't fail completely if abuse info is unavailable
		info.Abuse = AbuseInfo{
			Email: "unavailable",
		}
	}

	// Cache the result
	aa.cache[ipAddr] = info

	return info, nil
}

func (aa *ASNAnalyzer) enrichWithIPInfo(ctx context.Context, info *ASNInfo) error {
	// Using ip-api.com (free tier) for demonstration
	// In production, use a paid API or local GeoIP database
	url := fmt.Sprintf("http://ip-api.com/json/%s", info.IP)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := aa.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		Status       string  `json:"status"`
		ASN          string  `json:"as"`
		Organization string  `json:"org"`
		Country      string  `json:"country"`
		City         string  `json:"city"`
		Lat          float64 `json:"lat"`
		Lon          float64 `json:"lon"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if result.Status != "success" {
		return fmt.Errorf("IP lookup failed")
	}

	info.ASN = strings.Split(result.ASN, " ")[0] // Extract ASN number
	info.Organization = result.Organization
	info.Country = result.Country
	info.City = result.City

	return nil
}

func (aa *ASNAnalyzer) enrichWithAbuseInfo(ctx context.Context, info *ASNInfo) error {
	// Using AbuseIPDB API format (you'll need an API key in production)
	// This is a mock implementation for demonstration
	info.Abuse = AbuseInfo{
		Email:   fmt.Sprintf("abuse@%s", strings.ToLower(info.Organization)),
		Network: info.ASN,
	}

	// In production, query actual abuse database
	if strings.Contains(strings.ToLower(info.Organization), "cloudflare") {
		info.Abuse.Reports = []Report{
			{
				Category:    "CDN",
				ReportedAt:  time.Now().Add(-24 * time.Hour),
				Source:     "COMP Intelligence",
				Description: "Known CDN provider",
			},
		}
	}

	return nil
}

// GetNetworkRange retrieves the CIDR range for an IP
func (aa *ASNAnalyzer) GetNetworkRange(ctx context.Context, ipAddr string) (*IPRange, error) {
	if err := aa.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit exceeded: %v", err)
	}

	// In production, use WHOIS or RIR database
	// This is a mock implementation
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address")
	}

	// Mock CIDR calculation
	mockCIDR := &net.IPNet{
		IP:   ip.Mask(net.CIDRMask(24, 32)),
		Mask: net.CIDRMask(24, 32),
	}

	ones, bits := mockCIDR.Mask.Size()
	numHosts := 1 << uint(bits-ones)

	return &IPRange{
		Start:    mockCIDR.IP.String(),
		End:      incrementIP(mockCIDR.IP, numHosts-1).String(),
		CIDR:     mockCIDR.String(),
		NumHosts: numHosts,
	}, nil
}

// Helper function to increment IP address
func incrementIP(ip net.IP, inc int) net.IP {
	result := make(net.IP, len(ip))
	copy(result, ip)
	
	for j := len(result) - 1; j >= 0; j-- {
		inc, result[j] = (int(result[j])+inc)/256, uint8((int(result[j])+inc)%256)
		if inc == 0 {
			break
		}
	}
	
	return result
}
