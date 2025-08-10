package modules

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

// ModuleManager handles loading and executing C modules
type ModuleType string

const (
	ModuleRecon       ModuleType = "recon"
	ModuleVuln        ModuleType = "vuln"
	ModuleExploit     ModuleType = "exploit"
	ModuleScan        ModuleType = "scan"
	ModuleFingerprint ModuleType = "fingerprint"
)

// ModuleManager handles loading and executing C modules
type ModuleManager struct {
	mu      sync.RWMutex
	modules map[string]*Module
	binDir  string
}

// Module represents a loaded C module
type Module struct {
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	Description string   `json:"description"`
	Type        string   `json:"type"`
	Plans       []string `json:"plans"`
}

// ModuleResult represents the output from a module execution
type ModuleResult struct {
	Success     bool            `json:"success"`
	ElapsedTime float64         `json:"elapsed_time"`
	Data        json.RawMessage `json:"data,omitempty"`
	Error       string          `json:"error,omitempty"`
}

// NewModuleManager creates a new module manager
func NewModuleManager(binDir string) (*ModuleManager, error) {
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return nil, fmt.Errorf("create bin directory: %v", err)
	}

	return &ModuleManager{
		modules: make(map[string]*Module),
		binDir:  binDir,
	}, nil
}

// LoadModules scans the binary directory and loads all modules
func (mm *ModuleManager) LoadModules() error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	// Clear existing modules
	mm.modules = make(map[string]*Module)

	// Define known modules and their metadata
	knownModules := []Module{
		{
			Name:        "recon",
			Description: "Network reconnaissance module",
			Type:        "recon",
			Plans:       []string{"CompFree", "CompIX", "CompX", "CompKingX"},
		},
		{
			Name:        "vuln",
			Description: "Vulnerability scanning module",
			Type:        "security",
			Plans:       []string{"CompX", "CompKingX"},
		},
		// Add other modules here
	}

	// Load each module
	for _, mod := range knownModules {
		path := filepath.Join(mm.binDir, mod.Name)
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("module %s not found: %v", mod.Name, err)
		}
		
		mod.Path = path
		mm.modules[mod.Name] = &mod
	}

	return nil
}

// ExecuteModule runs a module with given parameters
func (mm *ModuleManager) ExecuteModule(name string, args ...string) (*ModuleResult, error) {
	mm.mu.RLock()
	mod, exists := mm.modules[name]
	mm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("module %s not found", name)
	}

	// Execute module
	cmd := exec.Command(mod.Path, args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("module error: %s", exitErr.Stderr)
		}
		return nil, fmt.Errorf("execute module: %v", err)
	}

	// Parse JSON result
	var result ModuleResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("parse module output: %v", err)
	}

	return &result, nil
}

// ListModules returns all loaded modules
func (mm *ModuleManager) ListModules() []*Module {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	modules := make([]*Module, 0, len(mm.modules))
	for _, mod := range mm.modules {
		modules = append(modules, mod)
	}
	return modules
}

// GetModule returns a specific module by name
func (mm *ModuleManager) GetModule(name string) (*Module, bool) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	mod, exists := mm.modules[name]
	return mod, exists
}

// CheckModuleAccess verifies if a user with given plan can access a module
func (mm *ModuleManager) CheckModuleAccess(moduleName, plan string) bool {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	mod, exists := mm.modules[moduleName]
	if !exists {
		return false
	}

	for _, allowedPlan := range mod.Plans {
		if allowedPlan == plan {
			return true
		}
	}
	return false
}
