package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Dashboard represents the admin control panel
type Dashboard struct {
	mu sync.RWMutex

	// Real-time monitoring
	activeUsers    map[string]*UserSession
	systemMetrics  *SystemMetrics
	activeModules  map[string]*ModuleStatus
	alerts        []Alert

	// Control features
	maintenanceMode bool
	forcedCommands  map[string]*ForcedCommand
	ghostedUsers    map[string]bool

	// Audit and logging
	auditLog     *AuditLog
	logTail      *LogTailer
	eventStream  chan Event
}

type UserSession struct {
	UserID      string    `json:"user_id"`
	Plan        string    `json:"plan"`
	LoginTime   time.Time `json:"login_time"`
	LastActive  time.Time `json:"last_active"`
	IP          string    `json:"ip"`
	ActiveCmds  []string  `json:"active_commands"`
	Permissions []string  `json:"permissions"`
}

type SystemMetrics struct {
	CPUUsage    float64   `json:"cpu_usage"`
	MemoryUsage float64   `json:"memory_usage"`
	DiskUsage   float64   `json:"disk_usage"`
	StartTime   time.Time `json:"start_time"`
	Uptime      string    `json:"uptime"`
}

type ModuleStatus struct {
	Name         string    `json:"name"`
	Status       string    `json:"status"`
	LastRun      time.Time `json:"last_run"`
	SuccessRate  float64   `json:"success_rate"`
	AverageTime  float64   `json:"average_time"`
	ActiveUsers  int       `json:"active_users"`
}

type Alert struct {
	ID        string    `json:"id"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Time      time.Time `json:"time"`
	Source    string    `json:"source"`
	Resolved  bool      `json:"resolved"`
}

type ForcedCommand struct {
	CommandID   string    `json:"command_id"`
	Command     string    `json:"command"`
	TargetUsers []string  `json:"target_users"`
	ExecTime    time.Time `json:"exec_time"`
	Status      string    `json:"status"`
}

type Event struct {
	Type      string                 `json:"type"`
	Time      time.Time             `json:"time"`
	Source    string                `json:"source"`
	Data      map[string]interface{} `json:"data"`
}

// NewDashboard creates a new admin dashboard
func NewDashboard() *Dashboard {
	return &Dashboard{
		activeUsers:    make(map[string]*UserSession),
		activeModules:  make(map[string]*ModuleStatus),
		forcedCommands: make(map[string]*ForcedCommand),
		ghostedUsers:   make(map[string]bool),
		systemMetrics:  &SystemMetrics{StartTime: time.Now()},
		eventStream:    make(chan Event, 1000),
		auditLog:      NewAuditLog(),
		logTail:       NewLogTailer(),
	}
}

// MonitorUser tracks user activity in real-time
func (d *Dashboard) MonitorUser(userID string, session *UserSession) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.activeUsers[userID] = session
	d.logEvent("user_session", map[string]interface{}{
		"user_id": userID,
		"action":  "session_start",
		"plan":    session.Plan,
	})
}

// UpdateUserActivity updates user's last active timestamp
func (d *Dashboard) UpdateUserActivity(userID string, cmd string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if session, exists := d.activeUsers[userID]; exists {
		session.LastActive = time.Now()
		session.ActiveCmds = append(session.ActiveCmds, cmd)
		
		// Check for ghosting
		if d.ghostedUsers[userID] {
			d.logEvent("ghosted_command", map[string]interface{}{
				"user_id": userID,
				"command": cmd,
			})
		}
	}
}

// ForceCommand schedules a command for forced execution
func (d *Dashboard) ForceCommand(cmd *ForcedCommand) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Validate command
	if err := d.validateForcedCommand(cmd); err != nil {
		return err
	}

	// Store command
	d.forcedCommands[cmd.CommandID] = cmd
	
	// Log forced command
	d.logEvent("forced_command", map[string]interface{}{
		"command_id": cmd.CommandID,
		"command":    cmd.Command,
		"targets":    cmd.TargetUsers,
	})

	return nil
}

// ToggleMaintenance enables/disables maintenance mode
func (d *Dashboard) ToggleMaintenance(enabled bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.maintenanceMode = enabled
	
	// Log maintenance mode change
	d.logEvent("maintenance_mode", map[string]interface{}{
		"enabled": enabled,
	})

	// Alert all active users
	if enabled {
		d.broadcastAlert(Alert{
			Level:   "WARNING",
			Message: "System entering maintenance mode",
			Time:    time.Now(),
			Source:  "admin",
		})
	}
}

// ToggleGhosting enables/disables command ghosting for a user
func (d *Dashboard) ToggleGhosting(userID string, enabled bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.ghostedUsers[userID] = enabled
	
	d.logEvent("ghost_mode", map[string]interface{}{
		"user_id": userID,
		"enabled": enabled,
	})
}

// GetSystemMetrics returns current system metrics
func (d *Dashboard) GetSystemMetrics() *SystemMetrics {
	d.mu.RLock()
	defer d.mu.RUnlock()

	d.systemMetrics.Uptime = time.Since(d.systemMetrics.StartTime).String()
	return d.systemMetrics
}

// GetActiveUsers returns all active user sessions
func (d *Dashboard) GetActiveUsers() map[string]*UserSession {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Create a copy to prevent data races
	users := make(map[string]*UserSession)
	for k, v := range d.activeUsers {
		users[k] = v
	}
	return users
}

// GetModuleStatus returns status of all modules
func (d *Dashboard) GetModuleStatus() map[string]*ModuleStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Create a copy to prevent data races
	modules := make(map[string]*ModuleStatus)
	for k, v := range d.activeModules {
		modules[k] = v
	}
	return modules
}

// TailLogs returns recent log entries
func (d *Dashboard) TailLogs(ctx context.Context, n int) <-chan string {
	return d.logTail.Tail(ctx, n)
}

// AddAlert adds a new system alert
func (d *Dashboard) AddAlert(alert Alert) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.alerts = append(d.alerts, alert)
	
	// Log alert
	d.logEvent("alert", map[string]interface{}{
		"level":   alert.Level,
		"message": alert.Message,
		"source":  alert.Source,
	})
}

// GetPendingAlerts returns unresolved alerts
func (d *Dashboard) GetPendingAlerts() []Alert {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var pending []Alert
	for _, alert := range d.alerts {
		if !alert.Resolved {
			pending = append(pending, alert)
		}
	}
	return pending
}

// Internal helper functions

func (d *Dashboard) validateForcedCommand(cmd *ForcedCommand) error {
	// Validate command syntax
	if cmd.Command == "" {
		return fmt.Errorf("empty command")
	}

	// Validate target users exist
	for _, userID := range cmd.TargetUsers {
		if _, exists := d.activeUsers[userID]; !exists {
			return fmt.Errorf("user %s not found", userID)
		}
	}

	return nil
}

func (d *Dashboard) broadcastAlert(alert Alert) {
	for userID := range d.activeUsers {
		// In production, this would send to user's session
		d.logEvent("alert_broadcast", map[string]interface{}{
			"user_id": userID,
			"alert":   alert,
		})
	}
}

func (d *Dashboard) logEvent(eventType string, data map[string]interface{}) {
	event := Event{
		Type:   eventType,
		Time:   time.Now(),
		Source: "dashboard",
		Data:   data,
	}

	// Send to event stream
	select {
	case d.eventStream <- event:
	default:
		// Channel full, log overflow
	}

	// Record in audit log
	d.auditLog.Record(event)
}

// UI Components

type DashboardView struct {
	viewport    viewport.Model
	dashboard   *Dashboard
	activeTab   string
	updateTick  time.Time
	style      *lipgloss.Style
}

func NewDashboardView(dash *Dashboard) *DashboardView {
	return &DashboardView{
		dashboard:  dash,
		viewport:   viewport.New(80, 24),
		activeTab:  "overview",
		style:     lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()),
	}
}

func (v *DashboardView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return v, tea.Quit
		case "tab":
			v.cycleTab()
		}
	case tea.WindowSizeMsg:
		v.viewport.Width = msg.Width
		v.viewport.Height = msg.Height - 4 // Leave room for status bar
	}

	v.viewport.Update(msg)
	return v, cmd
}

func (v *DashboardView) View() string {
	var content string

	switch v.activeTab {
	case "overview":
		content = v.renderOverview()
	case "users":
		content = v.renderUsers()
	case "modules":
		content = v.renderModules()
	case "logs":
		content = v.renderLogs()
	}

	return v.style.Render(content)
}

func (v *DashboardView) cycleTab() {
	tabs := []string{"overview", "users", "modules", "logs"}
	for i, tab := range tabs {
		if tab == v.activeTab {
			v.activeTab = tabs[(i+1)%len(tabs)]
			break
		}
	}
}
