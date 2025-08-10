package tui

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gliderlabs/ssh"
	"comp/internal/database"
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
	sess    ssh.Session
	program *tea.Program
}

type model struct {
	user        *database.User
	spinner     spinner.Model
	ready       bool
	err         error
	systemChats []string
}

func NewTerminal(sess ssh.Session) *Terminal {
	return &Terminal{sess: sess}
}

func (t *Terminal) Start(user *database.User) error {
	m := model{
		user:    user,
		spinner: spinner.New(spinner.WithSpinner(spinner.Points)),
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
	return tea.Batch(
		m.spinner.Tick,
		simulateSystemChatter,
	)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case systemChatterMsg:
		m.systemChats = append(m.systemChats, string(msg))
		if len(m.systemChats) > 5 {
			m.systemChats = m.systemChats[1:]
		}
		return m, simulateSystemChatter
	}

	return m, nil
}

func (m model) View() string {
	var s strings.Builder

	// Header
	s.WriteString(titleStyle.Render("COMP CONTROL SYSTEM\n"))
	s.WriteString(fmt.Sprintf("User: %s | Role: %s | Plan: %s\n\n", 
		m.user.Username, m.user.Role, m.user.Plan))

	// System chatter
	s.WriteString(infoStyle.Render("SYSTEM STATUS\n"))
	s.WriteString(m.spinner.View() + " System Active\n\n")
	for _, chat := range m.systemChats {
		s.WriteString(chat + "\n")
	}

	// Menu
	s.WriteString("\nCOMMANDS:\n")
	s.WriteString("1. Network Reconnaissance\n")
	s.WriteString("2. OSINT Operations\n")
	s.WriteString("3. Vulnerability Discovery\n")
	s.WriteString("4. Target Profiling\n")
	if m.user.Role == "Admin" {
		s.WriteString("5. Admin Dashboard\n")
	}
	s.WriteString("\nPress 'q' to quit\n")

	return s.String()
}

type systemChatterMsg string

func simulateSystemChatter() tea.Msg {
	messages := []string{
		"[SYS] Network buffer optimized",
		"[SYS] Scanning engine ready",
		"[SYS] Memory pools allocated",
		"[SYS] Protocol handlers initialized",
		"[SYS] Target database synchronized",
	}

	time.Sleep(time.Second * 2)
	return systemChatterMsg(messages[time.Now().Unix()%int64(len(messages))])
}
