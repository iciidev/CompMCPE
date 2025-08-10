package modules

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
)

// ModuleType represents different types of C modules
type ModuleType string

const (
	ModuleRecon        ModuleType = "recon"
	ModuleExploit      ModuleType = "exploit"
	ModuleScan         ModuleType = "scan"
	ModuleFingerprint  ModuleType = "fingerprint"
)

// ModuleResult represents the standardized output from C modules
type ModuleResult struct {
	Success     bool            `json:"success"`
	Data        json.RawMessage `json:"data"`
	Error       string          `json:"error,omitempty"`
	ElapsedTime float64         `json:"elapsed_time"`
}

// ModuleManager handles C module execution and communication
type ModuleManager struct {
	modulesPath string
}

func NewModuleManager(basePath string) *ModuleManager {
	return &ModuleManager{
		modulesPath: filepath.Join(basePath, "modules", "c"),
	}
}

func (m *ModuleManager) ExecuteModule(moduleType ModuleType, args ...string) (*ModuleResult, error) {
	// Determine module binary name based on OS
	var moduleName string
	switch runtime.GOOS {
	case "windows":
		moduleName = fmt.Sprintf("%s.exe", moduleType)
	default:
		moduleName = string(moduleType)
	}

	// Full path to module binary
	modulePath := filepath.Join(m.modulesPath, moduleName)

	// Execute module
	cmd := exec.Command(modulePath, args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("module execution failed: %v", err)
	}

	// Parse result
	var result ModuleResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse module output: %v", err)
	}

	return &result, nil
}

// Feature access based on plan
func CanAccessModule(plan string, moduleType ModuleType) bool {
	planModules := map[string][]ModuleType{
		"CompFree": {
			ModuleRecon,
		},
		"CompIX": {
			ModuleRecon,
			ModuleFingerprint,
		},
		"CompX": {
			ModuleRecon,
			ModuleFingerprint,
			ModuleScan,
		},
		"CompKingX": {
			ModuleRecon,
			ModuleFingerprint,
			ModuleScan,
			ModuleExploit,
		},
	}

	allowedModules, ok := planModules[plan]
	if !ok {
		return false
	}

	for _, allowed := range allowedModules {
		if allowed == moduleType {
			return true
		}
	}
	return false
}
