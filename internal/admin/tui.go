package admin

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#7CFC00")).
		MarginLeft(2)

	infoStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#5F9EA0"))

	warningStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFD700"))

	errorStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FF4500"))

	criticalStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FF0000"))

	tabStyle = lipgloss.NewStyle().
		Padding(0, 1).
		Border(lipgloss.NormalBorder(), false, false, true, false).
		BorderForeground(lipgloss.Color("#666666"))

	activeTabStyle = tabStyle.Copy().
		Bold(true).
		BorderForeground(lipgloss.Color("#7CFC00"))
)

// DashboardTUI represents the terminal UI for the admin dashboard
type DashboardTUI struct {
	dashboard    *Dashboard
	userManager  *UserManager
	alertManager *AlertManager
	monitor      *Monitor

	// UI components
	viewport    viewport.Model
	spinner     spinner.Model
	tabs        []string
	activeTab   string
	width       int
	height      int

	// State
	ready       bool
	err         error
	lastUpdate  time.Time
	updateChan  chan struct{}
}

func NewDashboardTUI(dash *Dashboard, users *UserManager, alerts *AlertManager, mon *Monitor) *DashboardTUI {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#7CFC00"))

	return &DashboardTUI{
		dashboard:    dash,
		userManager:  users,
		alertManager: alerts,
		monitor:      mon,
		spinner:     s,
		tabs:        []string{"Overview", "Users", "Modules", "Alerts", "Logs"},
		activeTab:   "Overview",
		updateChan:  make(chan struct{}, 1),
	}
}

func (dt *DashboardTUI) Init() tea.Cmd {
	return tea.Batch(
		dt.spinner.Tick,
		dt.checkForUpdates,
	)
}

func (dt *DashboardTUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return dt, tea.Quit
		case "tab":
			dt.nextTab()
		case "shift+tab":
			dt.prevTab()
		case "r":
			dt.updateChan <- struct{}{}
		}

	case tea.WindowSizeMsg:
		dt.width = msg.Width
		dt.height = msg.Height
		dt.viewport = viewport.New(msg.Width, msg.Height-6) // Leave room for header and footer
		dt.viewport.Style = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#666666"))
		dt.ready = true

	case spinner.TickMsg:
		var spinnerCmd tea.Cmd
		dt.spinner, spinnerCmd = dt.spinner.Update(msg)
		cmds = append(cmds, spinnerCmd)
	}

	// Update viewport
	dt.viewport.SetContent(dt.renderContent())
	vp, cmd := dt.viewport.Update(msg)
	dt.viewport = vp
	cmds = append(cmds, cmd)

	return dt, tea.Batch(cmds...)
}

func (dt *DashboardTUI) View() string {
	if !dt.ready {
		return fmt.Sprintf("\n\n   %s Loading...", dt.spinner.View())
	}

	var b strings.Builder

	// Render header
	b.WriteString(dt.renderHeader())
	b.WriteString("\n")

	// Render tabs
	b.WriteString(dt.renderTabs())
	b.WriteString("\n")

	// Render main content
	b.WriteString(dt.viewport.View())

	// Render footer
	b.WriteString(dt.renderFooter())

	return b.String()
}

func (dt *DashboardTUI) renderHeader() string {
	title := titleStyle.Render("COMP Admin Dashboard")
	status := dt.renderSystemStatus()
	padding := strings.Repeat(" ", dt.width-lipgloss.Width(title)-lipgloss.Width(status))
	
	return lipgloss.JoinHorizontal(lipgloss.Center, title, padding, status)
}

func (dt *DashboardTUI) renderTabs() string {
	var renderedTabs []string

	for _, t := range dt.tabs {
		var style lipgloss.Style
		if t == dt.activeTab {
			style = activeTabStyle
		} else {
			style = tabStyle
		}
		renderedTabs = append(renderedTabs, style.Render(t))
	}

	row := lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)
	gap := dt.width - lipgloss.Width(row)
	if gap > 0 {
		row = lipgloss.JoinHorizontal(lipgloss.Top, row, strings.Repeat(" ", gap))
	}

	return row
}

func (dt *DashboardTUI) renderContent() string {
	var content string

	switch dt.activeTab {
	case "Overview":
		content = dt.renderOverview()
	case "Users":
		content = dt.renderUsers()
	case "Modules":
		content = dt.renderModules()
	case "Alerts":
		content = dt.renderAlerts()
	case "Logs":
		content = dt.renderLogs()
	}

	return content
}

func (dt *DashboardTUI) renderOverview() string {
	metrics := dt.monitor.GetSystemMetrics()
	stats := dt.monitor.GetModuleStatistics()

	var b strings.Builder

	// System metrics
	b.WriteString(titleStyle.Render("System Metrics"))
	b.WriteString("\n\n")
	b.WriteString(fmt.Sprintf("CPU Usage:    %s\n", renderGauge(metrics.CPUUsage, 50)))
	b.WriteString(fmt.Sprintf("Memory Usage: %s\n", renderGauge(metrics.MemoryUsage, 50)))
	b.WriteString(fmt.Sprintf("Disk Usage:   %s\n", renderGauge(metrics.DiskUsage, 50)))
	b.WriteString(fmt.Sprintf("Uptime:       %s\n", metrics.Uptime))
	b.WriteString("\n")

	// Active sessions
	sessions := dt.dashboard.GetActiveUsers()
	b.WriteString(titleStyle.Render("Active Sessions"))
	b.WriteString("\n\n")
	for id, session := range sessions {
		b.WriteString(fmt.Sprintf("User: %s (%s)\n", id, session.Plan))
		b.WriteString(fmt.Sprintf("  Last Active: %s\n", time.Since(session.LastActive).Round(time.Second)))
		if len(session.ActiveCmds) > 0 {
			b.WriteString(fmt.Sprintf("  Current: %s\n", session.ActiveCmds[len(session.ActiveCmds)-1]))
		}
	}

	return b.String()
}

func (dt *DashboardTUI) renderUsers() string {
	users, err := dt.userManager.ListUsers(context.Background())
	if err != nil {
		return errorStyle.Render(fmt.Sprintf("Error: %v", err))
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render("User Management"))
	b.WriteString("\n\n")

	for _, user := range users {
		b.WriteString(fmt.Sprintf("ID: %s\n", user.ID))
		b.WriteString(fmt.Sprintf("Username: %s\n", user.Username))
		b.WriteString(fmt.Sprintf("Role: %s\n", user.Role))
		b.WriteString(fmt.Sprintf("Plan: %s\n", user.Plan))
		b.WriteString(fmt.Sprintf("Last Login: %s\n", user.LastLogin.Format(time.RFC822)))
		b.WriteString(fmt.Sprintf("Status: %s\n", user.Status))
		b.WriteString("\n")
	}

	return b.String()
}

func (dt *DashboardTUI) renderModules() string {
	stats := dt.monitor.GetModuleStatistics()

	var b strings.Builder
	b.WriteString(titleStyle.Render("Module Status"))
	b.WriteString("\n\n")

	for name, module := range stats.Modules {
		b.WriteString(fmt.Sprintf("Module: %s\n", name))
		b.WriteString(fmt.Sprintf("  Calls: %d\n", module.Calls))
		b.WriteString(fmt.Sprintf("  Success Rate: %.1f%%\n", 100-float64(module.Errors)/float64(module.Calls)*100))
		b.WriteString(fmt.Sprintf("  Avg Time: %.2fms\n", module.AverageTime/float64(time.Millisecond)))
		b.WriteString(fmt.Sprintf("  Active Users: %d\n", len(module.ActiveUsers)))
		b.WriteString("\n")
	}

	return b.String()
}

func (dt *DashboardTUI) renderAlerts() string {
	alerts := dt.alertManager.GetActiveAlerts()

	var b strings.Builder
	b.WriteString(titleStyle.Render("Active Alerts"))
	b.WriteString("\n\n")

	for _, alert := range alerts {
		var style lipgloss.Style
		switch alert.Level {
		case "CRITICAL":
			style = criticalStyle
		case "ERROR":
			style = errorStyle
		case "WARNING":
			style = warningStyle
		default:
			style = infoStyle
		}

		b.WriteString(style.Render(fmt.Sprintf("[%s] %s\n", alert.Level, alert.Message)))
		b.WriteString(fmt.Sprintf("  Time: %s\n", alert.Time.Format(time.RFC822)))
		b.WriteString(fmt.Sprintf("  Source: %s\n", alert.Source))
		if alert.Count > 1 {
			b.WriteString(fmt.Sprintf("  Occurrences: %d\n", alert.Count))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func (dt *DashboardTUI) renderLogs() string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	logs := make([]string, 0)
	logCh := dt.dashboard.TailLogs(ctx, 100)
	for log := range logCh {
		logs = append(logs, log)
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render("System Logs"))
	b.WriteString("\n\n")

	for _, log := range logs {
		b.WriteString(log)
		b.WriteString("\n")
	}

	return b.String()
}

func (dt *DashboardTUI) renderSystemStatus() string {
	metrics := dt.monitor.GetSystemMetrics()
	alerts := dt.alertManager.GetActiveAlerts()

	var style lipgloss.Style
	var status string

	if len(alerts) > 0 {
		critical := 0
		for _, alert := range alerts {
			if alert.Level == "CRITICAL" {
				critical++
			}
		}
		if critical > 0 {
			style = criticalStyle
			status = fmt.Sprintf("ALERTS: %d Critical", critical)
		} else {
			style = warningStyle
			status = fmt.Sprintf("ALERTS: %d Active", len(alerts))
		}
	} else if metrics.CPUUsage > 80 || metrics.MemoryUsage > 80 {
		style = warningStyle
		status = "HIGH LOAD"
	} else {
		style = infoStyle
		status = "NORMAL"
	}

	return style.Render(status)
}

func (dt *DashboardTUI) renderFooter() string {
	help := " q: quit • tab: next tab • r: refresh "
	padding := strings.Repeat(" ", dt.width-lipgloss.Width(help))
	return "\n" + lipgloss.JoinHorizontal(lipgloss.Center, help, padding)
}

func (dt *DashboardTUI) nextTab() {
	for i, t := range dt.tabs {
		if t == dt.activeTab {
			dt.activeTab = dt.tabs[(i+1)%len(dt.tabs)]
			break
		}
	}
}

func (dt *DashboardTUI) prevTab() {
	for i, t := range dt.tabs {
		if t == dt.activeTab {
			if i == 0 {
				dt.activeTab = dt.tabs[len(dt.tabs)-1]
			} else {
				dt.activeTab = dt.tabs[i-1]
			}
			break
		}
	}
}

func (dt *DashboardTUI) checkForUpdates() tea.Msg {
	for {
		select {
		case <-dt.updateChan:
			dt.lastUpdate = time.Now()
			return nil
		case <-time.After(time.Second):
			return nil
		}
	}
}

// Helper functions

func renderGauge(value float64, width int) string {
	filled := int(value / 100 * float64(width))
	if filled > width {
		filled = width
	}

	var style lipgloss.Style
	switch {
	case value >= 90:
		style = criticalStyle
	case value >= 75:
		style = warningStyle
	default:
		style = infoStyle
	}

	bar := style.Render(strings.Repeat("█", filled) + strings.Repeat("░", width-filled))
	return fmt.Sprintf("%s %.1f%%", bar, value)
}
