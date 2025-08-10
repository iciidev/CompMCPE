package osint

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// CertInfo represents detailed SSL/TLS certificate information
type CertInfo struct {
	Subject     CertName    `json:"subject"`
	Issuer      CertName    `json:"issuer"`
	NotBefore   time.Time   `json:"valid_from"`
	NotAfter    time.Time   `json:"valid_until"`
	DNSNames    []string    `json:"dns_names"`
	Fingerprint string      `json:"fingerprint"`
	Version     int         `json:"version"`
	Serial      string      `json:"serial"`
	KeyUsage    []string    `json:"key_usage"`
	IsCA        bool        `json:"is_ca"`
	Warnings    []string    `json:"warnings,omitempty"`
}

type CertName struct {
	CommonName         string   `json:"common_name"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Country           []string `json:"country,omitempty"`
}

// SSLAnalyzer performs SSL/TLS certificate analysis
type SSLAnalyzer struct {
	timeout     time.Duration
	rateLimiter *RateLimiter
}

func NewSSLAnalyzer(timeout time.Duration) *SSLAnalyzer {
	return &SSLAnalyzer{
		timeout:     timeout,
		rateLimiter: NewRateLimiter(5, time.Second), // 5 queries per second
	}
}

// AnalyzeSSL performs comprehensive SSL/TLS analysis of a host
func (sa *SSLAnalyzer) AnalyzeSSL(ctx context.Context, host string, port int) (*CertInfo, error) {
	if err := sa.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit exceeded: %v", err)
	}

	dialer := &net.Dialer{
		Timeout: sa.timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", host, port), &tls.Config{
		InsecureSkipVerify: true, // We want to analyze ALL certificates
	})
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %v", err)
	}
	defer conn.Close()

	// Get the certificate chain
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	// Analyze the leaf certificate
	return sa.analyzeCert(certs[0], certs)
}

func (sa *SSLAnalyzer) analyzeCert(cert *x509.Certificate, chain []*x509.Certificate) (*CertInfo, error) {
	info := &CertInfo{
		Subject: CertName{
			CommonName:         cert.Subject.CommonName,
			Organization:       cert.Subject.Organization,
			OrganizationalUnit: cert.Subject.OrganizationalUnit,
			Country:           cert.Subject.Country,
		},
		Issuer: CertName{
			CommonName:         cert.Issuer.CommonName,
			Organization:       cert.Issuer.Organization,
			OrganizationalUnit: cert.Issuer.OrganizationalUnit,
			Country:           cert.Issuer.Country,
		},
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		DNSNames:    cert.DNSNames,
		Version:     cert.Version,
		Serial:      fmt.Sprintf("%x", cert.SerialNumber),
		IsCA:        cert.IsCA,
	}

	// Calculate SHA256 fingerprint
	info.Fingerprint = fmt.Sprintf("%x", sha256.Sum256(cert.Raw))

	// Analyze key usage
	info.KeyUsage = sa.parseKeyUsage(cert.KeyUsage)
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			info.KeyUsage = append(info.KeyUsage, "ServerAuth")
		}
	}

	// Check for potential issues
	sa.checkCertIssues(info, cert, chain)

	return info, nil
}

func (sa *SSLAnalyzer) parseKeyUsage(usage x509.KeyUsage) []string {
	var usages []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	return usages
}

func (sa *SSLAnalyzer) checkCertIssues(info *CertInfo, cert *x509.Certificate, chain []*x509.Certificate) {
	now := time.Now()

	// Check expiration
	if now.After(cert.NotAfter) {
		info.Warnings = append(info.Warnings, "Certificate has expired")
	} else if now.Add(30 * 24 * time.Hour).After(cert.NotAfter) {
		info.Warnings = append(info.Warnings, "Certificate will expire within 30 days")
	}

	// Check if self-signed
	if cert.Subject.CommonName == cert.Issuer.CommonName {
		info.Warnings = append(info.Warnings, "Self-signed certificate detected")
	}

	// Check key strength (assuming RSA)
	if pubKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		keySize := pubKey.N.BitLen()
		if keySize < 2048 {
			info.Warnings = append(info.Warnings, fmt.Sprintf("Weak key size (%d bits)", keySize))
		}
	}

	// Check signature algorithm
	switch cert.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		info.Warnings = append(info.Warnings, "Weak signature algorithm (SHA1)")
	}
}

// Helper function to format certificate chain information
func (sa *SSLAnalyzer) formatCertChain(chain []*x509.Certificate) []string {
	var result []string
	for i, cert := range chain {
		result = append(result, fmt.Sprintf("%d: %s (Issuer: %s)", 
			i, cert.Subject.CommonName, cert.Issuer.CommonName))
	}
	return result
}
