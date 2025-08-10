package core

import (
	"fmt"
	"io"
	"sync"

	"github.com/gliderlabs/ssh"
	"comp/internal/database"
	"comp/internal/tui"
)

type Plan string

const (
	PlanFree    Plan = "CompFree"
	PlanIX      Plan = "CompIX"
	PlanX       Plan = "CompX"
	PlanKingX   Plan = "CompKingX"
)

type Role string

const (
	RoleAdmin    Role = "Admin"
	RoleOperator Role = "Operator"
	RoleObserver Role = "Observer"
)

type Server struct {
	db        *database.BoltDB
	sessions  map[string]*Session
	mu        sync.RWMutex
}

type Session struct {
	ID       string
	User     *database.User
	Terminal *tui.Terminal
}

func NewServer(db *database.BoltDB) *Server {
	return &Server{
		db:       db,
		sessions: make(map[string]*Session),
	}
}

func (s *Server) HandleSSH(sess ssh.Session) {
	term := tui.NewTerminal(sess)
	
	// Authentication
	user, err := s.authenticate(sess)
	if err != nil {
		fmt.Fprintln(sess, "Access Denied.")
		return
	}

	// Create session
	session := &Session{
		ID:       sess.Context().Value(ssh.ContextKeySessionID).(string),
		User:     user,
		Terminal: term,
	}

	// Store session
	s.mu.Lock()
	s.sessions[session.ID] = session
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.sessions, session.ID)
		s.mu.Unlock()
	}()

	// Start TUI
	if err := term.Start(user); err != nil && err != io.EOF {
		fmt.Fprintf(sess, "Session error: %v\n", err)
	}
}

func (s *Server) authenticate(sess ssh.Session) (*database.User, error) {
	// TODO: Implement actual authentication
	// For now, return a mock admin user
	return &database.User{
		Username: sess.User(),
		Role:     string(RoleAdmin),
		Plan:     string(PlanKingX),
	}, nil
}
