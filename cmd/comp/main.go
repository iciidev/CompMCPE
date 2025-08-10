package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/gliderlabs/ssh"
	"comp/internal/core"
	"comp/internal/database"
	"comp/internal/modules"
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
	// Setup signal handling
	_, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// Initialize database
	dbPath := filepath.Join("data", "comp.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	db, err := database.NewBoltDB(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize module manager
	moduleManager, err := modules.NewModuleManager(filepath.Join("modules", "c", "build"))
	if err != nil {
		log.Fatalf("Failed to initialize module manager: %v", err)
	}

	// Load all modules
	if err := moduleManager.LoadModules(); err != nil {
		log.Printf("Warning: Failed to load some modules: %v", err)
	}

	// Initialize core server
	server := core.NewServer(db, moduleManager)

	// Configure SSH server
	s := &ssh.Server{
		Addr:    fmt.Sprintf(":%d", defaultPort),
		Handler: server.HandleSSH,
		Banner:  func() string { return banner },
	}

	// Start server in background
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("COMP server listening on port %d...", defaultPort)
		if err := s.ListenAndServe(); err != nil && err != ssh.ErrServerClosed {
			log.Printf("SSH server error: %v", err)
			cancel()
		}
	}()

	// Wait for shutdown signal
	<-signals
	log.Println("Shutdown signal received, closing server...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Close SSH server
	if err := s.Close(); err != nil {
		log.Printf("Error closing SSH server: %v", err)
	}

	// Wait for all connections to close
	serverClosed := make(chan struct{})
	go func() {
		wg.Wait()
		close(serverClosed)
	}()

	select {
	case <-serverClosed:
		log.Println("Server shutdown complete")
	case <-shutdownCtx.Done():
		log.Println("Server shutdown timed out")
	}

	// Close database
	if err := db.Close(); err != nil {
		log.Printf("Error closing database: %v", err)
	}


}
