package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/gliderlabs/ssh"
	"comp/internal/core"
	"comp/internal/database"
)

const (
	defaultPort = 2222
	banner = `
   ▄████▄   ▒█████   ███▄ ▄███▓ ██▓███  
  ▒██▀ ▀█  ▒██▒  ██▒▓██▒▀█▀ ██▒▓██░  ██▒
  ▒▓█    ▄ ▒██░  ██▒▓██    ▓██░▓██░ ██▓▒
  ▒▓▓▄ ▄██▒▒██   ██░▒██    ▒██ ▒██▄█▓▒ ▒
  ▒ ▓███▀ ░░ ████▓▒░▒██▒   ░██▒▒██▒ ░  ░
  ░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ░  ░▒▓▒░ ░  ░
    ░  ▒     ░ ▒ ▒░ ░  ░      ░░▒ ░     
  ░        ░ ░ ░ ▒  ░      ░   ░░       
  ░ ░          ░ ░         ░            
  ░                                     
  `
)

func main() {
	// Initialize database
	dbPath := filepath.Join("data", "comp.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	db, err := database.NewBoltDB(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Initialize core server
	server := core.NewServer(db)

	// Configure SSH server
	s := &ssh.Server{
		Addr:    fmt.Sprintf(":%d", defaultPort),
		Handler: server.HandleSSH,
		Banner:  func() string { return banner },
	}

	log.Printf("Starting COMP server on port %d...", defaultPort)
	log.Fatal(s.ListenAndServe())
}
