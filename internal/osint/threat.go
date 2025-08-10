package osint

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ThreatActorProfile represents identified threat actor patterns
type ThreatActorProfile struct {
	ID            string                 `json:"id"`
	Confidence    float64               `json:"confidence"`
	FirstSeen     time.Time             `json:"first_seen"`
	LastSeen      time.Time             `json:"last_seen"`
	Indicators    []ThreatIndicator     `json:"indicators"`
	Infrastructure []InfrastructureNode  `json:"infrastructure"`
	Patterns      []ActivityPattern     `json:"patterns"`
	Attribution   Attribution           `json:"attribution"`
	References    []string              `json:"references"`
}

type ThreatIndicator struct {
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Confidence  float64   `json:"confidence"`
	Source      string    `json:"source"`
}

type InfrastructureNode struct {
	Type        string                 `json:"type"`
	Identifier  string                 `json:"identifier"`
	Metadata    map[string]interface{} `json:"metadata"`
	Connected   []string               `json:"connected_to"`
	LastActive  time.Time             `json:"last_active"`
}

type ActivityPattern struct {
	Pattern     string    `json:"pattern"`
	Description string    `json:"description"`
	Frequency   int       `json:"frequency"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Confidence  float64   `json:"confidence"`
}

type Attribution struct {
	Actor       string   `json:"actor"`
	Type        string   `json:"type"`
	Confidence  float64  `json:"confidence"`
	Tags        []string `json:"tags"`
	Notes       string   `json:"notes,omitempty"`
}

// ThreatAnalyzer performs threat actor attribution analysis
type ThreatAnalyzer struct {
	patterns     map[string]*PatternMatcher
	indicators   *IndicatorDB
	rateLimiter  *RateLimiter
	mu           sync.RWMutex
}

func NewThreatAnalyzer() *ThreatAnalyzer {
	return &ThreatAnalyzer{
		patterns:    make(map[string]*PatternMatcher),
		indicators:  NewIndicatorDB(),
		rateLimiter: NewRateLimiter(5, time.Second),
	}
}

// AnalyzeTarget performs comprehensive threat analysis
func (ta *ThreatAnalyzer) AnalyzeTarget(ctx context.Context, data map[string]interface{}) (*ThreatActorProfile, error) {
	if err := ta.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit exceeded: %v", err)
	}

	profile := &ThreatActorProfile{
		ID:        generateProfileID(),
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}

	// Extract and analyze infrastructure patterns
	if err := ta.analyzeInfrastructure(ctx, data, profile); err != nil {
		return nil, fmt.Errorf("infrastructure analysis failed: %v", err)
	}

	// Analyze activity patterns
	if err := ta.analyzePatterns(ctx, data, profile); err != nil {
		return nil, fmt.Errorf("pattern analysis failed: %v", err)
	}

	// Perform attribution based on findings
	if err := ta.performAttribution(ctx, profile); err != nil {
		return nil, fmt.Errorf("attribution failed: %v", err)
	}

	return profile, nil
}

func (ta *ThreatAnalyzer) analyzeInfrastructure(ctx context.Context, data map[string]interface{}, profile *ThreatActorProfile) error {
	// Extract infrastructure components
	if ips, ok := data["ips"].([]string); ok {
		for _, ip := range ips {
			node := InfrastructureNode{
				Type:       "ip",
				Identifier: ip,
				LastActive: time.Now(),
				Metadata:   make(map[string]interface{}),
			}
			
			// Check for known indicators
			if indicators := ta.indicators.CheckIP(ip); len(indicators) > 0 {
				for _, ind := range indicators {
					profile.Indicators = append(profile.Indicators, ThreatIndicator{
						Type:       "ip_match",
						Value:      ip,
						FirstSeen:  ind.FirstSeen,
						LastSeen:   time.Now(),
						Confidence: ind.Confidence,
						Source:     "infrastructure_analysis",
					})
				}
			}
			
			profile.Infrastructure = append(profile.Infrastructure, node)
		}
	}

	// Analyze infrastructure patterns
	ta.analyzeInfrastructurePatterns(profile)

	return nil
}

func (ta *ThreatAnalyzer) analyzePatterns(ctx context.Context, data map[string]interface{}, profile *ThreatActorProfile) error {
	patterns := []struct {
		name    string
		matcher *PatternMatcher
	}{
		{"minecraft_server", NewMinecraftPatternMatcher()},
		{"network_infra", NewNetworkPatternMatcher()},
		{"hosting_pattern", NewHostingPatternMatcher()},
	}

	for _, p := range patterns {
		if matches := p.matcher.Match(data); len(matches) > 0 {
			for _, match := range matches {
				profile.Patterns = append(profile.Patterns, ActivityPattern{
					Pattern:     p.name,
					Description: match.Description,
					Frequency:   match.Frequency,
					FirstSeen:   match.FirstSeen,
					LastSeen:    match.LastSeen,
					Confidence:  match.Confidence,
				})
			}
		}
	}

	return nil
}

func (ta *ThreatAnalyzer) performAttribution(ctx context.Context, profile *ThreatActorProfile) error {
	// Calculate attribution based on collected evidence
	var totalConfidence float64
	var attributionNotes []string

	// Analyze infrastructure patterns
	infraScore := ta.calculateInfrastructureScore(profile.Infrastructure)
	if infraScore > 0.7 {
		totalConfidence += infraScore * 0.4 // Infrastructure is 40% of total confidence
		attributionNotes = append(attributionNotes, "Strong infrastructure pattern match")
	}

	// Analyze activity patterns
	patternScore := ta.calculatePatternScore(profile.Patterns)
	if patternScore > 0.6 {
		totalConfidence += patternScore * 0.3 // Patterns are 30% of total confidence
		attributionNotes = append(attributionNotes, "Consistent activity patterns detected")
	}

	// Analyze indicators
	indicatorScore := ta.calculateIndicatorScore(profile.Indicators)
	if indicatorScore > 0.5 {
		totalConfidence += indicatorScore * 0.3 // Indicators are 30% of total confidence
		attributionNotes = append(attributionNotes, "Multiple threat indicators present")
	}

	// Set attribution based on analysis
	profile.Attribution = Attribution{
		Actor:      ta.determineActor(totalConfidence, profile),
		Type:       ta.determineActorType(profile),
		Confidence: totalConfidence,
		Tags:       ta.generateTags(profile),
		Notes:      ta.formatAttributionNotes(attributionNotes),
	}

	return nil
}

func (ta *ThreatAnalyzer) calculateInfrastructureScore(infra []InfrastructureNode) float64 {
	if len(infra) == 0 {
		return 0.0
	}

	var score float64
	uniquePatterns := make(map[string]bool)

	for _, node := range infra {
		// Check for infrastructure reuse
		if ta.indicators.IsKnownInfrastructure(node.Identifier) {
			score += 0.3
		}

		// Check for pattern diversity
		pattern := ta.classifyInfrastructurePattern(node)
		if !uniquePatterns[pattern] {
			uniquePatterns[pattern] = true
			score += 0.1
		}
	}

	return normalizeScore(score)
}

func (ta *ThreatAnalyzer) calculatePatternScore(patterns []ActivityPattern) float64 {
	if len(patterns) == 0 {
		return 0.0
	}

	var score float64
	for _, pattern := range patterns {
		// Weight patterns by frequency and confidence
		score += float64(pattern.Frequency) * pattern.Confidence * 0.1
	}

	return normalizeScore(score)
}

func (ta *ThreatAnalyzer) calculateIndicatorScore(indicators []ThreatIndicator) float64 {
	if len(indicators) == 0 {
		return 0.0
	}

	var score float64
	for _, indicator := range indicators {
		score += indicator.Confidence * 0.2
	}

	return normalizeScore(score)
}

func (ta *ThreatAnalyzer) determineActor(confidence float64, profile *ThreatActorProfile) string {
	if confidence < 0.4 {
		return "Unknown Actor"
	}

	// In production, this would use a more sophisticated attribution engine
	// For now, using a simple classification
	if ta.matchesKnownGroup(profile) {
		return "Known Threat Group"
	}

	return "Unattributed Actor"
}

func (ta *ThreatAnalyzer) determineActorType(profile *ThreatActorProfile) string {
	// Analyze patterns to determine actor type
	hasGameServerPatterns := false
	hasAdvancedInfra := false
	hasPersistentActivity := false

	for _, pattern := range profile.Patterns {
		switch pattern.Pattern {
		case "minecraft_server":
			hasGameServerPatterns = true
		case "advanced_infrastructure":
			hasAdvancedInfra = true
		case "persistent_activity":
			hasPersistentActivity = true
		}
	}

	if hasAdvancedInfra && hasPersistentActivity {
		return "Advanced Persistent Threat"
	} else if hasGameServerPatterns {
		return "Game Server Operator"
	}

	return "Unknown"
}

// Helper functions
func (ta *ThreatAnalyzer) classifyInfrastructurePattern(node InfrastructureNode) string {
	// Simple pattern classification
	switch node.Type {
	case "ip":
		return "ip_infrastructure"
	case "domain":
		return "domain_infrastructure"
	default:
		return "unknown"
	}
}

func (ta *ThreatAnalyzer) matchesKnownGroup(profile *ThreatActorProfile) bool {
	// In production, this would check against a database of known threat groups
	return false
}

func (ta *ThreatAnalyzer) generateTags(profile *ThreatActorProfile) []string {
	var tags []string
	
	// Add tags based on infrastructure
	if len(profile.Infrastructure) > 5 {
		tags = append(tags, "large_infrastructure")
	}
	
	// Add tags based on patterns
	for _, pattern := range profile.Patterns {
		if pattern.Confidence > 0.8 {
			tags = append(tags, "high_confidence_"+pattern.Pattern)
		}
	}

	return tags
}

func (ta *ThreatAnalyzer) formatAttributionNotes(notes []string) string {
	if len(notes) == 0 {
		return "No significant attribution factors identified"
	}
	
	return fmt.Sprintf("Attribution based on: %v", notes)
}

func normalizeScore(score float64) float64 {
	if score > 1.0 {
		return 1.0
	}
	return score
}

func generateProfileID() string {
	return fmt.Sprintf("profile_%d", time.Now().UnixNano())
}

// IndicatorDB represents a database of known threat indicators
type IndicatorDB struct {
	indicators map[string][]ThreatIndicator
	mu        sync.RWMutex
}

func NewIndicatorDB() *IndicatorDB {
	return &IndicatorDB{
		indicators: make(map[string][]ThreatIndicator),
	}
}

func (db *IndicatorDB) CheckIP(ip string) []ThreatIndicator {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.indicators[ip]
}

func (db *IndicatorDB) IsKnownInfrastructure(identifier string) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	_, exists := db.indicators[identifier]
	return exists
}

// PatternMatcher interface for different types of pattern matching
type PatternMatcher interface {
	Match(data map[string]interface{}) []PatternMatch
}

type PatternMatch struct {
	Description string
	Frequency  int
	FirstSeen  time.Time
	LastSeen   time.Time
	Confidence float64
}

// Implement specific pattern matchers
type MinecraftPatternMatcher struct{}

func NewMinecraftPatternMatcher() *MinecraftPatternMatcher {
	return &MinecraftPatternMatcher{}
}

func (m *MinecraftPatternMatcher) Match(data map[string]interface{}) []PatternMatch {
	// Implementation would look for Minecraft-specific patterns
	return nil
}

type NetworkPatternMatcher struct{}

func NewNetworkPatternMatcher() *NetworkPatternMatcher {
	return &NetworkPatternMatcher{}
}

func (n *NetworkPatternMatcher) Match(data map[string]interface{}) []PatternMatch {
	// Implementation would look for network infrastructure patterns
	return nil
}

type HostingPatternMatcher struct{}

func NewHostingPatternMatcher() *HostingPatternMatcher {
	return &HostingPatternMatcher{}
}

func (h *HostingPatternMatcher) Match(data map[string]interface{}) []PatternMatch {
	// Implementation would look for hosting provider patterns
	return nil
}
