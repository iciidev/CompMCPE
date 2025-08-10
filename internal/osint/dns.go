package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSResult represents structured DNS analysis results
type DNSResult struct {
	Target      string            `json:"target"`
	Timestamp   time.Time         `json:"timestamp"`
	Records     map[string][]string `json:"records"`
	SPF         *SPFRecord       `json:"spf,omitempty"`
	DMARC       *DMARCRecord     `json:"dmarc,omitempty"`
	Subdomains  []string         `json:"subdomains,omitempty"`
	ZoneData    []string         `json:"zone_data,omitempty"`
	Errors      []string         `json:"errors,omitempty"`
}

type SPFRecord struct {
	Raw      string   `json:"raw"`
	Version  string   `json:"version"`
	Includes []string `json:"includes"`
	IPs      []string `json:"ips"`
}

type DMARCRecord struct {
	Raw    string `json:"raw"`
	Policy string `json:"policy"`
	Pct    int    `json:"pct"`
}

// DNSAnalyzer performs deep DNS analysis
type DNSAnalyzer struct {
	client     *dns.Client
	nameserver string
	rateLimiter *RateLimiter
}

// NewDNSAnalyzer creates a new DNS analyzer
func NewDNSAnalyzer(nameserver string) *DNSAnalyzer {
	return &DNSAnalyzer{
		client:     &dns.Client{},
		nameserver: nameserver,
		rateLimiter: NewRateLimiter(10, time.Second), // 10 queries per second
	}
}

// AnalyzeDomain performs comprehensive DNS analysis
func (da *DNSAnalyzer) AnalyzeDomain(ctx context.Context, domain string) (*DNSResult, error) {
	result := &DNSResult{
		Target:    domain,
		Timestamp: time.Now(),
		Records:   make(map[string][]string),
	}

	// Common record types to query
	recordTypes := []uint16{
		dns.TypeA,
		dns.TypeAAAA,
		dns.TypeMX,
		dns.TypeTXT,
		dns.TypeNS,
		dns.TypeSOA,
	}

	for _, recordType := range recordTypes {
		if err := da.rateLimiter.Wait(ctx); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("rate limit exceeded: %v", err))
			continue
		}

		records, err := da.queryRecords(domain, recordType)
		if err != nil {
			result.Errors = append(result.Errors, err.Error())
			continue
		}
		result.Records[dns.TypeToString[recordType]] = records
	}

	// Special handling for SPF and DMARC
	if txtRecords, ok := result.Records["TXT"]; ok {
		result.SPF = parseSPF(txtRecords)
		result.DMARC = parseDMARC(txtRecords, domain)
	}

	return result, nil
}

func (da *DNSAnalyzer) queryRecords(domain string, recordType uint16) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), recordType)
	m.RecursionDesired = true

	r, _, err := da.client.Exchange(m, da.nameserver+":53")
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %v", err)
	}

	var records []string
	for _, ans := range r.Answer {
		records = append(records, ans.String())
	}
	return records, nil
}

func parseSPF(records []string) *SPFRecord {
	for _, record := range records {
		if strings.HasPrefix(record, "v=spf1") {
			parts := strings.Fields(record)
			spf := &SPFRecord{
				Raw:     record,
				Version: "spf1",
			}

			for _, part := range parts[1:] {
				switch {
				case strings.HasPrefix(part, "include:"):
					spf.Includes = append(spf.Includes, strings.TrimPrefix(part, "include:"))
				case strings.HasPrefix(part, "ip4:"), strings.HasPrefix(part, "ip6:"):
					spf.IPs = append(spf.IPs, strings.SplitN(part, ":", 2)[1])
				}
			}
			return spf
		}
	}
	return nil
}

func parseDMARC(records []string, domain string) *DMARCRecord {
	dmarcDomain := "_dmarc." + domain
	for _, record := range records {
		if strings.Contains(record, dmarcDomain) {
			dmarc := &DMARCRecord{Raw: record}
			if parts := strings.Split(record, ";"); len(parts) > 1 {
				for _, part := range parts {
					part = strings.TrimSpace(part)
					if strings.HasPrefix(part, "p=") {
						dmarc.Policy = strings.TrimPrefix(part, "p=")
					} else if strings.HasPrefix(part, "pct=") {
						fmt.Sscanf(part, "pct=%d", &dmarc.Pct)
					}
				}
			}
			return dmarc
		}
	}
	return nil
}

// RateLimiter implements a simple rate limiting mechanism
type RateLimiter struct {
	tokens chan struct{}
	tick   *time.Ticker
}

func NewRateLimiter(rate int, per time.Duration) *RateLimiter {
	rl := &RateLimiter{
		tokens: make(chan struct{}, rate),
		tick:   time.NewTicker(per / time.Duration(rate)),
	}

	// Fill token bucket
	for i := 0; i < rate; i++ {
		rl.tokens <- struct{}{}
	}

	go func() {
		for range rl.tick.C {
			select {
			case rl.tokens <- struct{}{}:
			default:
			}
		}
	}()

	return rl
}

func (rl *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-rl.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
