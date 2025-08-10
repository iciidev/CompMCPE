package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// Monitor handles real-time system monitoring and statistics
type Monitor struct {
	mu sync.RWMutex

	// Performance metrics
	metrics      *MetricsCollector
	userStats    *UserStatistics
	moduleStats  *ModuleStatistics
	alertManager *AlertManager

	// Channels
	metricsChan  chan Metric
	statsChan    chan Statistic
	alertsChan   chan Alert

	// Control
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// MetricsCollector gathers system performance data
type MetricsCollector struct {
	samples     []SystemMetrics
	sampleSize  int
	interval    time.Duration
	lastUpdate  time.Time
}

// UserStatistics tracks user activity patterns
type UserStatistics struct {
	ActiveUsers    map[string]*UserMetrics `json:"active_users"`
	TotalSessions  int                     `json:"total_sessions"`
	PeakUsers      int                     `json:"peak_users"`
	AverageUptime  float64                 `json:"average_uptime"`
}

type UserMetrics struct {
	CommandCount    int                    `json:"command_count"`
	ModuleUsage    map[string]int         `json:"module_usage"`
	SessionTime    time.Duration          `json:"session_time"`
	LastActive     time.Time              `json:"last_active"`
	Performance    map[string]interface{} `json:"performance"`
}

// ModuleStatistics tracks module performance and usage
type ModuleStatistics struct {
	Modules       map[string]*ModuleMetrics `json:"modules"`
	TotalCalls    int                       `json:"total_calls"`
	SuccessRate   float64                   `json:"success_rate"`
	AverageTime   float64                   `json:"average_time"`
}

type ModuleMetrics struct {
	Calls        int           `json:"calls"`
	Errors       int           `json:"errors"`
	TotalTime    time.Duration `json:"total_time"`
	AverageTime  float64       `json:"average_time"`
	LastRun      time.Time     `json:"last_run"`
	ActiveUsers  []string      `json:"active_users"`
}

// Metric represents a single performance measurement
type Metric struct {
	Name      string
	Value     float64
	Timestamp time.Time
	Labels    map[string]string
}

// Statistic represents aggregated statistical data
type Statistic struct {
	Category    string
	Name        string
	Value       interface{}
	Period      time.Duration
	UpdateTime  time.Time
}

func NewMonitor(ctx context.Context) *Monitor {
	ctx, cancel := context.WithCancel(ctx)
	
	m := &Monitor{
		metrics:     NewMetricsCollector(100, time.Second*5),
		userStats:   &UserStatistics{ActiveUsers: make(map[string]*UserMetrics)},
		moduleStats: &ModuleStatistics{Modules: make(map[string]*ModuleMetrics)},
		alertManager: NewAlertManager(),
		metricsChan: make(chan Metric, 1000),
		statsChan:   make(chan Statistic, 1000),
		alertsChan:  make(chan Alert, 100),
		ctx:        ctx,
		cancel:     cancel,
	}

	// Start monitoring routines
	m.wg.Add(3)
	go m.collectMetrics()
	go m.processStatistics()
	go m.monitorAlerts()

	return m
}

func (m *Monitor) Stop() {
	m.cancel()
	m.wg.Wait()
}

// RecordUserActivity records user actions and updates statistics
func (m *Monitor) RecordUserActivity(userID string, action string, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	metrics, exists := m.userStats.ActiveUsers[userID]
	if !exists {
		metrics = &UserMetrics{
			ModuleUsage:  make(map[string]int),
			Performance:  make(map[string]interface{}),
			LastActive:   time.Now(),
		}
		m.userStats.ActiveUsers[userID] = metrics
	}

	metrics.CommandCount++
	metrics.LastActive = time.Now()
	metrics.SessionTime += duration

	// Update peak users if needed
	if len(m.userStats.ActiveUsers) > m.userStats.PeakUsers {
		m.userStats.PeakUsers = len(m.userStats.ActiveUsers)
	}

	// Send metric for processing
	m.metricsChan <- Metric{
		Name:      "user_activity",
		Value:     float64(duration.Milliseconds()),
		Timestamp: time.Now(),
		Labels: map[string]string{
			"user_id": userID,
			"action":  action,
		},
	}
}

// RecordModuleExecution records module performance metrics
func (m *Monitor) RecordModuleExecution(moduleName string, duration time.Duration, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	metrics, exists := m.moduleStats.Modules[moduleName]
	if !exists {
		metrics = &ModuleMetrics{
			ActiveUsers: make([]string, 0),
		}
		m.moduleStats.Modules[moduleName] = metrics
	}

	metrics.Calls++
	metrics.TotalTime += duration
	metrics.LastRun = time.Now()
	metrics.AverageTime = float64(metrics.TotalTime.Nanoseconds()) / float64(metrics.Calls)

	if err != nil {
		metrics.Errors++
	}

	m.moduleStats.TotalCalls++
	m.moduleStats.AverageTime = calculateAverageTime(m.moduleStats.Modules)
	m.moduleStats.SuccessRate = calculateSuccessRate(m.moduleStats.Modules)

	// Send metric for processing
	m.metricsChan <- Metric{
		Name:      "module_execution",
		Value:     float64(duration.Milliseconds()),
		Timestamp: time.Now(),
		Labels: map[string]string{
			"module": moduleName,
			"status": fmt.Sprintf("%v", err == nil),
		},
	}
}

// GetSystemMetrics returns current system performance metrics
func (m *Monitor) GetSystemMetrics() SystemMetrics {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)

	return SystemMetrics{
		CPUUsage:    m.metrics.GetCPUUsage(),
		MemoryUsage: float64(stats.Alloc) / float64(stats.Sys),
		DiskUsage:   m.metrics.GetDiskUsage(),
		StartTime:   m.metrics.GetStartTime(),
		Uptime:      time.Since(m.metrics.GetStartTime()).String(),
	}
}

// GetUserStatistics returns aggregated user statistics
func (m *Monitor) GetUserStatistics() *UserStatistics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Create a copy to prevent data races
	stats := &UserStatistics{
		ActiveUsers:   make(map[string]*UserMetrics),
		TotalSessions: m.userStats.TotalSessions,
		PeakUsers:     m.userStats.PeakUsers,
		AverageUptime: m.userStats.AverageUptime,
	}

	for id, metrics := range m.userStats.ActiveUsers {
		statsCopy := *metrics
		stats.ActiveUsers[id] = &statsCopy
	}

	return stats
}

// GetModuleStatistics returns aggregated module statistics
func (m *Monitor) GetModuleStatistics() *ModuleStatistics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Create a copy to prevent data races
	stats := &ModuleStatistics{
		Modules:     make(map[string]*ModuleMetrics),
		TotalCalls: m.moduleStats.TotalCalls,
		SuccessRate: m.moduleStats.SuccessRate,
		AverageTime: m.moduleStats.AverageTime,
	}

	for name, metrics := range m.moduleStats.Modules {
		statsCopy := *metrics
		stats.Modules[name] = &statsCopy
	}

	return stats
}

// Internal monitoring routines

func (m *Monitor) collectMetrics() {
	defer m.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			metrics := m.GetSystemMetrics()
			m.metrics.AddSample(metrics)

			// Check for threshold violations
			if metrics.CPUUsage > 80 {
				m.alertsChan <- Alert{
					Level:   "WARNING",
					Message: fmt.Sprintf("High CPU usage: %.2f%%", metrics.CPUUsage),
					Time:    time.Now(),
					Source:  "system_monitor",
				}
			}
		}
	}
}

func (m *Monitor) processStatistics() {
	defer m.wg.Done()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case metric := <-m.metricsChan:
			m.processMetric(metric)
		case <-ticker.C:
			m.aggregateStatistics()
		}
	}
}

func (m *Monitor) monitorAlerts() {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return
		case alert := <-m.alertsChan:
			m.alertManager.ProcessAlert(alert)
		}
	}
}

// Helper functions

func (m *Monitor) processMetric(metric Metric) {
	// Process and store metric
	switch metric.Name {
	case "user_activity":
		// Update user-specific metrics
		if userID, ok := metric.Labels["user_id"]; ok {
			m.updateUserMetrics(userID, metric)
		}
	case "module_execution":
		// Update module-specific metrics
		if module, ok := metric.Labels["module"]; ok {
			m.updateModuleMetrics(module, metric)
		}
	}
}

func (m *Monitor) aggregateStatistics() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Calculate system-wide statistics
	m.userStats.AverageUptime = calculateAverageUptime(m.userStats.ActiveUsers)
	
	// Clean up inactive users
	now := time.Now()
	for userID, metrics := range m.userStats.ActiveUsers {
		if now.Sub(metrics.LastActive) > time.Hour {
			delete(m.userStats.ActiveUsers, userID)
		}
	}
}

func calculateAverageTime(modules map[string]*ModuleMetrics) float64 {
	if len(modules) == 0 {
		return 0
	}

	var total float64
	var count int
	for _, m := range modules {
		total += m.AverageTime
		count++
	}
	return total / float64(count)
}

func calculateSuccessRate(modules map[string]*ModuleMetrics) float64 {
	if len(modules) == 0 {
		return 0
	}

	var totalCalls, totalErrors int
	for _, m := range modules {
		totalCalls += m.Calls
		totalErrors += m.Errors
	}

	if totalCalls == 0 {
		return 0
	}

	return 100 * (1 - float64(totalErrors)/float64(totalCalls))
}

func calculateAverageUptime(users map[string]*UserMetrics) float64 {
	if len(users) == 0 {
		return 0
	}

	var total float64
	for _, metrics := range users {
		total += float64(metrics.SessionTime.Seconds())
	}
	return total / float64(len(users))
}
