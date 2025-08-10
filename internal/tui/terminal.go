package tui

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gliderlabs/ssh"
	"comp/internal/database"
	"comp/internal/modules"
)

var (
	titleStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#00FF00")).
		Bold(true)

	warningStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFF00"))

	errorStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FF0000"))

	infoStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#00FFFF"))
)

type Terminal struct {
	sess     ssh.Session
	program  *tea.Program
	modules  *modules.ModuleManager
}

type model struct {
	user        *database.User
	spinner     spinner.Model
	running     bool
	err         error
	output      string
	// commands
	runReconCmd func() tea.Cmd
	runVulnCmd  func() tea.Cmd
}

func NewTerminal(sess ssh.Session, mm *modules.ModuleManager) *Terminal {
	return &Terminal{sess: sess, modules: mm}
}

func (t *Terminal) Start(user *database.User) error {
	m := model{
		user:    user,
		spinner: spinner.New(spinner.WithSpinner(spinner.Points)),
	}

	// Wire commands to execute real modules
	m.runReconCmd = func() tea.Cmd {
		return func() tea.Msg {
			start := time.Now()
			res, err := t.modules.ExecuteModule("recon")
			if err != nil {
				return execResultMsg{ok: false, text: fmt.Sprintf("recon error: %v", err)}
			}
			pretty := prettyJSON(res.Data)
			return execResultMsg{ok: res.Success, text: fmt.Sprintf("[recon] %.2fs\n%s", elapsedTimeOr(res, start), pretty)}
		}
	}
	m.runVulnCmd = func() tea.Cmd {
		return func() tea.Msg {
			start := time.Now()
			// Provide safe defaults; adjust as needed
			res, err := t.modules.ExecuteModule("vuln", "--target", "127.0.0.1", "--ports", "80")
			if err != nil {
				return execResultMsg{ok: false, text: fmt.Sprintf("vuln error: %v", err)}
			}
			pretty := prettyJSON(res.Data)
			return execResultMsg{ok: res.Success, text: fmt.Sprintf("[vuln] %.2fs\n%s", elapsedTimeOr(res, start), pretty)}
		}
	}

	p := tea.NewProgram(
		m,
		tea.WithInput(t.sess),
		tea.WithOutput(t.sess),
		tea.WithAltScreen(),
	)

	t.program = p
	return p.Start()
}

func (m model) Init() tea.Cmd {
	// No fake chatter; only tick spinner when running
	if m.running {
		return m.spinner.Tick
	}
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "1":
			m.running = true
			return m, m.runReconCmd
		case "3":
			m.running = true
			return m, m.runVulnCmd
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		if m.running {
			return m, cmd
		}
		return m, nil

	case execResultMsg:
		m.running = false
		if !msg.ok {
			m.err = fmt.Errorf(msg.text)
		} else {
			m.err = nil
		}
		m.output = msg.text
		return m, nil
	}

	return m, nil
}

func (m model) View() string {
	var s strings.Builder

	// Header
	s.WriteString(titleStyle.Render("COMP CONTROL SYSTEM\n"))
	s.WriteString(fmt.Sprintf("User: %s | Role: %s | Plan: %s\n\n",
		m.user.Username, m.user.Role, m.user.Plan))

	// Status
	s.WriteString(infoStyle.Render("STATUS\n"))
	if m.running {
		s.WriteString(m.spinner.View() + " Running...\n\n")
	} else {
		s.WriteString("Idle\n\n")
	}
	if m.err != nil {
		s.WriteString(errorStyle.Render(m.err.Error()) + "\n\n")
	}
	if m.output != "" {
		s.WriteString(infoStyle.Render("Last Output:\n"))
		s.WriteString(m.output + "\n\n")
	}

	s.WriteString("1. Run Recon Module\n")
	s.WriteString("3. Run Vulnerability Scan (127.0.0.1:80)\n")
	if m.user.Role == "Admin" {
		s.WriteString("5. Admin Dashboard (coming soon)\n")
	}
	s.WriteString("\nPress 'q' to quit\n")

	return s.String()
}

type execResultMsg struct {
	ok   bool
	text string
}

// helper to pretty print JSON
func prettyJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "<no data>"
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return string(raw)
	}
	return string(b)
}

// helper to compute elapsed if module didn't fill it
func elapsedTimeOr(r *modules.ModuleResult, start time.Time) float64 {
	if r != nil && r.ElapsedTime > 0 {
		return r.ElapsedTime
	}
	return time.Since(start).Seconds()
}
