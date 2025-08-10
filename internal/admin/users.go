package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

// UserManager handles user account and plan management
type UserManager struct {
	mu sync.RWMutex

	// Storage
	db *bbolt.DB

	// Active sessions and state
	activeSessions map[string]*UserSession
	planFeatures   map[string][]string
	rolePerms     map[string][]string

	// Audit logging
	auditLog *AuditLog
}

// UserAccount represents a user in the system
type UserAccount struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Role        string    `json:"role"`
	Plan        string    `json:"plan"`
	CreatedAt   time.Time `json:"created_at"`
	LastLogin   time.Time `json:"last_login"`
	Status      string    `json:"status"`
	Permissions []string  `json:"permissions"`
}

// PlanChange represents a user plan modification
type PlanChange struct {
	UserID    string    `json:"user_id"`
	OldPlan   string    `json:"old_plan"`
	NewPlan   string    `json:"new_plan"`
	ChangedAt time.Time `json:"changed_at"`
	ChangedBy string    `json:"changed_by"`
	Reason    string    `json:"reason"`
}

// Feature represents a plan-gated feature
type Feature struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Plans       []string `json:"plans"`
	Module      string   `json:"module"`
}

func NewUserManager(dbPath string) (*UserManager, error) {
	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open db: %v", err)
	}

	// Initialize buckets
	err = db.Update(func(tx *bbolt.Tx) error {
		buckets := []string{"users", "sessions", "plans", "audit"}
		for _, bucket := range buckets {
			_, err := tx.CreateBucketIfNotExists([]byte(bucket))
			if err != nil {
				return fmt.Errorf("create bucket %s: %v", bucket, err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("init buckets: %v", err)
	}

	um := &UserManager{
		db:             db,
		activeSessions: make(map[string]*UserSession),
		planFeatures:   make(map[string][]string),
		rolePerms:      make(map[string][]string),
		auditLog:       NewAuditLog(),
	}

	// Initialize default plans and roles
	um.initDefaultPlans()
	um.initDefaultRoles()

	return um, nil
}

// CreateUser creates a new user account
func (um *UserManager) CreateUser(ctx context.Context, account *UserAccount) error {
	if err := um.validateAccount(account); err != nil {
		return err
	}

	return um.db.Update(func(tx *bbolt.Tx) error {
		users := tx.Bucket([]byte("users"))
		
		// Check if username exists
		if users.Get([]byte(account.Username)) != nil {
			return fmt.Errorf("username %s already exists", account.Username)
		}

		// Generate ID if not provided
		if account.ID == "" {
			account.ID = fmt.Sprintf("user_%d", time.Now().UnixNano())
		}

		// Set creation time
		account.CreatedAt = time.Now()

		// Serialize account
		data, err := json.Marshal(account)
		if err != nil {
			return fmt.Errorf("marshal account: %v", err)
		}

		// Store account
		if err := users.Put([]byte(account.ID), data); err != nil {
			return fmt.Errorf("store account: %v", err)
		}

		// Log creation
		um.auditLog.Record(Event{
			Type:   "user_created",
			Time:   time.Now(),
			Source: "user_manager",
			Data: map[string]interface{}{
				"user_id":   account.ID,
				"username": account.Username,
				"role":     account.Role,
				"plan":     account.Plan,
			},
		})

		return nil
	})
}

// UpdateUser updates an existing user account
func (um *UserManager) UpdateUser(ctx context.Context, account *UserAccount) error {
	return um.db.Update(func(tx *bbolt.Tx) error {
		users := tx.Bucket([]byte("users"))

		// Check if user exists
		existing := users.Get([]byte(account.ID))
		if existing == nil {
			return fmt.Errorf("user %s not found", account.ID)
		}

		// Merge with existing data
		var oldAccount UserAccount
		if err := json.Unmarshal(existing, &oldAccount); err != nil {
			return fmt.Errorf("unmarshal existing: %v", err)
		}

		// Record plan change if applicable
		if oldAccount.Plan != account.Plan {
			if err := um.recordPlanChange(tx, &PlanChange{
				UserID:    account.ID,
				OldPlan:   oldAccount.Plan,
				NewPlan:   account.Plan,
				ChangedAt: time.Now(),
			}); err != nil {
				return err
			}
		}

		// Update account
		data, err := json.Marshal(account)
		if err != nil {
			return fmt.Errorf("marshal account: %v", err)
		}

		if err := users.Put([]byte(account.ID), data); err != nil {
			return fmt.Errorf("store account: %v", err)
		}

		// Log update
		um.auditLog.Record(Event{
			Type:   "user_updated",
			Time:   time.Now(),
			Source: "user_manager",
			Data: map[string]interface{}{
				"user_id":   account.ID,
				"username": account.Username,
				"changes":  um.diffAccounts(&oldAccount, account),
			},
		})

		return nil
	})
}

// GetUser retrieves a user account
func (um *UserManager) GetUser(ctx context.Context, userID string) (*UserAccount, error) {
	var account UserAccount

	err := um.db.View(func(tx *bbolt.Tx) error {
		users := tx.Bucket([]byte("users"))
		
		data := users.Get([]byte(userID))
		if data == nil {
			return fmt.Errorf("user %s not found", userID)
		}

		return json.Unmarshal(data, &account)
	})

	if err != nil {
		return nil, err
	}

	return &account, nil
}

// ListUsers returns all user accounts
func (um *UserManager) ListUsers(ctx context.Context) ([]*UserAccount, error) {
	var accounts []*UserAccount

	err := um.db.View(func(tx *bbolt.Tx) error {
		users := tx.Bucket([]byte("users"))
		
		return users.ForEach(func(k, v []byte) error {
			var account UserAccount
			if err := json.Unmarshal(v, &account); err != nil {
				return fmt.Errorf("unmarshal account: %v", err)
			}
			accounts = append(accounts, &account)
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	return accounts, nil
}

// CheckFeatureAccess checks if a user has access to a feature
func (um *UserManager) CheckFeatureAccess(ctx context.Context, userID string, feature string) (bool, error) {
	account, err := um.GetUser(ctx, userID)
	if err != nil {
		return false, err
	}

	// Check if feature is available in user's plan
	features, ok := um.planFeatures[account.Plan]
	if !ok {
		return false, nil
	}

	for _, f := range features {
		if f == feature {
			return true, nil
		}
	}

	return false, nil
}

// GetUserPermissions returns all permissions for a user
func (um *UserManager) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	account, err := um.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Combine role permissions and plan features
	perms := make(map[string]bool)

	// Add role permissions
	for _, p := range um.rolePerms[account.Role] {
		perms[p] = true
	}

	// Add plan features
	for _, f := range um.planFeatures[account.Plan] {
		perms[f] = true
	}

	// Convert to slice
	var permissions []string
	for p := range perms {
		permissions = append(permissions, p)
	}

	return permissions, nil
}

// Internal methods

func (um *UserManager) initDefaultPlans() {
	um.planFeatures = map[string][]string{
		"CompFree": {
			"basic_recon",
			"dns_lookup",
			"port_scan",
		},
		"CompIX": {
			"basic_recon",
			"dns_lookup",
			"port_scan",
			"ssl_scan",
			"subdomain_enum",
			"minecraft_query",
		},
		"CompX": {
			"basic_recon",
			"dns_lookup",
			"port_scan",
			"ssl_scan",
			"subdomain_enum",
			"minecraft_query",
			"vuln_scan",
			"exploit_sim",
			"social_osint",
		},
		"CompKingX": {
			"basic_recon",
			"dns_lookup",
			"port_scan",
			"ssl_scan",
			"subdomain_enum",
			"minecraft_query",
			"vuln_scan",
			"exploit_sim",
			"social_osint",
			"threat_intel",
			"advanced_osint",
			"custom_modules",
		},
	}
}

func (um *UserManager) initDefaultRoles() {
	um.rolePerms = map[string][]string{
		"admin": {
			"user_manage",
			"system_config",
			"module_force",
			"maintenance",
			"audit_view",
		},
		"operator": {
			"module_run",
			"report_view",
			"scan_schedule",
		},
		"observer": {
			"report_view",
		},
	}
}

func (um *UserManager) validateAccount(account *UserAccount) error {
	if account.Username == "" {
		return fmt.Errorf("username required")
	}

	if account.Role == "" {
		return fmt.Errorf("role required")
	}

	if account.Plan == "" {
		return fmt.Errorf("plan required")
	}

	// Validate role
	if _, ok := um.rolePerms[account.Role]; !ok {
		return fmt.Errorf("invalid role: %s", account.Role)
	}

	// Validate plan
	if _, ok := um.planFeatures[account.Plan]; !ok {
		return fmt.Errorf("invalid plan: %s", account.Plan)
	}

	return nil
}

func (um *UserManager) recordPlanChange(tx *bbolt.Tx, change *PlanChange) error {
	plans := tx.Bucket([]byte("plans"))
	
	key := fmt.Sprintf("%s_%d", change.UserID, change.ChangedAt.UnixNano())
	data, err := json.Marshal(change)
	if err != nil {
		return fmt.Errorf("marshal plan change: %v", err)
	}

	return plans.Put([]byte(key), data)
}

func (um *UserManager) diffAccounts(old, new *UserAccount) map[string]interface{} {
	diff := make(map[string]interface{})

	if old.Role != new.Role {
		diff["role"] = map[string]string{
			"old": old.Role,
			"new": new.Role,
		}
	}

	if old.Plan != new.Plan {
		diff["plan"] = map[string]string{
			"old": old.Plan,
			"new": new.Plan,
		}
	}

	if old.Status != new.Status {
		diff["status"] = map[string]string{
			"old": old.Status,
			"new": new.Status,
		}
	}

	return diff
}
