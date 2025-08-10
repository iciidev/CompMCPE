package admin

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// AlertManager handles system-wide notifications and warnings
type AlertManager struct {
	mu sync.RWMutex

	// Alert storage and routing
	alerts       map[string]*Alert
	subscribers  map[string][]chan<- Alert
	rules        []AlertRule
	suppressions map[string]Suppression

	// Statistics
	stats AlertStats

	// Control
	ctx    context.Context
	cancel context.CancelFunc
}

// AlertRule defines conditions for alert generation
type AlertRule struct {
	ID          string
	Name        string
	Condition   AlertCondition
	Level       string
	Message     string
	Threshold   float64
	Window      time.Duration
	Cooldown    time.Duration
	LastTriggered time.Time
}

// AlertCondition represents alert triggering logic
type AlertCondition struct {
	Metric    string
	Operator  string
	Value     float64
	Duration  time.Duration
}

// Suppression represents alert suppression rules
type Suppression struct {
	Pattern    string
	Reason     string
	ExpiresAt  time.Time
	CreatedBy  string
}

// AlertStats tracks alert system metrics
type AlertStats struct {
	TotalAlerts    int
	ActiveAlerts   int
	ResolvedAlerts int
	AlertsByLevel  map[string]int
	MTTRByLevel    map[string]time.Duration
}

func NewAlertManager() *AlertManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	am := &AlertManager{
		alerts:      make(map[string]*Alert),
		subscribers: make(map[string][]chan<- Alert),
		suppressions: make(map[string]Suppression),
		stats: AlertStats{
			AlertsByLevel: make(map[string]int),
			MTTRByLevel:   make(map[string]time.Duration),
		},
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize default rules
	am.initDefaultRules()

	// Start background processors
	go am.processAlerts()
	go am.cleanupExpiredAlerts()

	return am
}

// ProcessAlert handles new alerts and routes them to subscribers
func (am *AlertManager) ProcessAlert(alert Alert) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Check suppressions
	if am.isAlertSuppressed(alert) {
		return nil
	}

	// Deduplicate similar alerts
	if existing, exists := am.findSimilarAlert(alert); exists {
		existing.Count++
		existing.LastOccurrence = alert.Time
		return nil
	}

	// Generate alert ID if not present
	if alert.ID == "" {
		alert.ID = fmt.Sprintf("alert_%d", time.Now().UnixNano())
	}

	// Store alert
	am.alerts[alert.ID] = &alert

	// Update statistics
	am.updateStats(&alert)

	// Notify subscribers
	am.notifySubscribers(alert)

	return nil
}

// Subscribe registers a channel to receive alerts
func (am *AlertManager) Subscribe(ctx context.Context, levels []string) <-chan Alert {
	ch := make(chan Alert, 100)

	am.mu.Lock()
	for _, level := range levels {
		am.subscribers[level] = append(am.subscribers[level], ch)
	}
	am.mu.Unlock()

	// Cleanup on context cancellation
	go func() {
		<-ctx.Done()
		am.mu.Lock()
		for level, subs := range am.subscribers {
			for i, sub := range subs {
				if sub == ch {
					subs = append(subs[:i], subs[i+1:]...)
					break
				}
			}
			am.subscribers[level] = subs
		}
		am.mu.Unlock()
		close(ch)
	}()

	return ch
}

// AddRule adds a new alert rule
func (am *AlertManager) AddRule(rule AlertRule) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Validate rule
	if err := am.validateRule(rule); err != nil {
		return err
	}

	am.rules = append(am.rules, rule)
	return nil
}

// SuppressAlerts adds a suppression rule
func (am *AlertManager) SuppressAlerts(pattern string, duration time.Duration, reason string, user string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.suppressions[pattern] = Suppression{
		Pattern:    pattern,
		Reason:     reason,
		ExpiresAt:  time.Now().Add(duration),
		CreatedBy:  user,
	}
}

// ResolveAlert marks an alert as resolved
func (am *AlertManager) ResolveAlert(id string, resolution string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	alert, exists := am.alerts[id]
	if !exists {
		return fmt.Errorf("alert %s not found", id)
	}

	if alert.Resolved {
		return nil
	}

	alert.Resolved = true
	alert.Resolution = resolution
	alert.ResolvedAt = time.Now()

	// Update MTTR statistics
	mtrr := alert.ResolvedAt.Sub(alert.Time)
	am.stats.MTTRByLevel[alert.Level] = am.updateMTTR(
		am.stats.MTTRByLevel[alert.Level],
		mtrr,
		am.stats.AlertsByLevel[alert.Level],
	)

	am.stats.ResolvedAlerts++
	am.stats.ActiveAlerts--

	return nil
}

// GetActiveAlerts returns all unresolved alerts
func (am *AlertManager) GetActiveAlerts() []Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	var active []Alert
	for _, alert := range am.alerts {
		if !alert.Resolved {
			active = append(active, *alert)
		}
	}

	// Sort by severity and time
	sort.Slice(active, func(i, j int) bool {
		if active[i].Level != active[j].Level {
			return am.alertLevelPriority(active[i].Level) > am.alertLevelPriority(active[j].Level)
		}
		return active[i].Time.After(active[j].Time)
	})

	return active
}

// GetAlertStats returns current alert statistics
func (am *AlertManager) GetAlertStats() AlertStats {
	am.mu.RLock()
	defer am.mu.RUnlock()

	// Return a copy to prevent data races
	stats := AlertStats{
		TotalAlerts:    am.stats.TotalAlerts,
		ActiveAlerts:   am.stats.ActiveAlerts,
		ResolvedAlerts: am.stats.ResolvedAlerts,
		AlertsByLevel:  make(map[string]int),
		MTTRByLevel:    make(map[string]time.Duration),
	}

	for k, v := range am.stats.AlertsByLevel {
		stats.AlertsByLevel[k] = v
	}
	for k, v := range am.stats.MTTRByLevel {
		stats.MTTRByLevel[k] = v
	}

	return stats
}

// Internal methods

func (am *AlertManager) initDefaultRules() {
	defaultRules := []AlertRule{
		{
			ID:      "high_cpu",
			Name:    "High CPU Usage",
			Level:   "WARNING",
			Message: "CPU usage exceeds threshold",
			Condition: AlertCondition{
				Metric:    "cpu_usage",
				Operator:  ">",
				Value:     80,
				Duration: time.Minute * 5,
			},
			Threshold: 80,
			Window:    time.Minute * 5,
			Cooldown:  time.Minute * 15,
		},
		{
			ID:      "memory_pressure",
			Name:    "Memory Pressure",
			Level:   "WARNING",
			Message: "High memory usage detected",
			Condition: AlertCondition{
				Metric:    "memory_usage",
				Operator:  ">",
				Value:     90,
				Duration: time.Minute * 5,
			},
			Threshold: 90,
			Window:    time.Minute * 5,
			Cooldown:  time.Minute * 15,
		},
	}

	for _, rule := range defaultRules {
		am.rules = append(am.rules, rule)
	}
}

func (am *AlertManager) processAlerts() {
	ticker := time.NewTicker(time.Second * 30)
	defer ticker.Stop()

	for {
		select {
		case <-am.ctx.Done():
			return
		case <-ticker.C:
			am.evaluateRules()
		}
	}
}

func (am *AlertManager) cleanupExpiredAlerts() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-am.ctx.Done():
			return
		case <-ticker.C:
			am.mu.Lock()
			now := time.Now()
			
			// Clean up old resolved alerts
			for id, alert := range am.alerts {
				if alert.Resolved && now.Sub(alert.ResolvedAt) > time.Hour*24*7 {
					delete(am.alerts, id)
				}
			}

			// Clean up expired suppressions
			for pattern, suppression := range am.suppressions {
				if now.After(suppression.ExpiresAt) {
					delete(am.suppressions, pattern)
				}
			}
			am.mu.Unlock()
		}
	}
}

func (am *AlertManager) evaluateRules() {
	am.mu.Lock()
	defer am.mu.Unlock()

	now := time.Now()
	for _, rule := range am.rules {
		// Skip if in cooldown
		if now.Sub(rule.LastTriggered) < rule.Cooldown {
			continue
		}

		// Evaluate condition
		if am.evaluateCondition(rule.Condition) {
			alert := Alert{
				ID:        fmt.Sprintf("%s_%d", rule.ID, now.UnixNano()),
				Level:     rule.Level,
				Message:   rule.Message,
				Time:     now,
				Source:   "alert_manager",
			}
			am.ProcessAlert(alert)
		}
	}
}

func (am *AlertManager) evaluateCondition(condition AlertCondition) bool {
	// This would connect to the metrics system
	// For now, return false to prevent false alerts
	return false
}

func (am *AlertManager) isAlertSuppressed(alert Alert) bool {
	for _, suppression := range am.suppressions {
		if suppression.ExpiresAt.After(time.Now()) && matchesPattern(alert, suppression.Pattern) {
			return true
		}
	}
	return false
}

func (am *AlertManager) findSimilarAlert(alert Alert) (*Alert, bool) {
	for _, existing := range am.alerts {
		if !existing.Resolved &&
			existing.Level == alert.Level &&
			existing.Message == alert.Message &&
			existing.Source == alert.Source &&
			time.Since(existing.Time) < time.Minute*5 {
			return existing, true
		}
	}
	return nil, false
}

func (am *AlertManager) updateStats(alert *Alert) {
	am.stats.TotalAlerts++
	am.stats.ActiveAlerts++
	am.stats.AlertsByLevel[alert.Level]++
}

func (am *AlertManager) notifySubscribers(alert Alert) {
	subs := am.subscribers[alert.Level]
	for _, ch := range subs {
		select {
		case ch <- alert:
		default:
			// Don't block if subscriber is slow
		}
	}
}

func (am *AlertManager) validateRule(rule AlertRule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID is required")
	}
	if rule.Condition.Metric == "" {
		return fmt.Errorf("rule condition metric is required")
	}
	if rule.Window <= 0 {
		return fmt.Errorf("rule window must be positive")
	}
	return nil
}

func (am *AlertManager) alertLevelPriority(level string) int {
	switch level {
	case "CRITICAL":
		return 4
	case "ERROR":
		return 3
	case "WARNING":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

func (am *AlertManager) updateMTTR(current, new time.Duration, count int) time.Duration {
	if count == 0 {
		return new
	}
	return (current*time.Duration(count) + new) / time.Duration(count+1)
}

func matchesPattern(alert Alert, pattern string) bool {
	// This would implement pattern matching logic
	// For now, just check exact match
	return alert.Message == pattern
}
