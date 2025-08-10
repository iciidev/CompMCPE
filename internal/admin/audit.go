package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

// AuditLog manages immutable logging of all system events
type AuditLog struct {
	mu       sync.RWMutex
	db       *bbolt.DB
	buffer   []Event
	watchers []chan<- Event
}

// AuditQuery represents a query for audit log entries
type AuditQuery struct {
	StartTime time.Time
	EndTime   time.Time
	Types     []string
	Sources   []string
	UserIDs   []string
	Limit     int
}

// NewAuditLog creates a new audit logging system
func NewAuditLog() *AuditLog {
	db, err := bbolt.Open("audit.db", 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		panic(fmt.Sprintf("failed to open audit log: %v", err))
	}

	// Create buckets
	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("events"))
		if err != nil {
			return fmt.Errorf("create events bucket: %v", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte("indexes"))
		if err != nil {
			return fmt.Errorf("create indexes bucket: %v", err)
		}
		return nil
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create buckets: %v", err))
	}

	return &AuditLog{
		db:     db,
		buffer: make([]Event, 0, 1000),
	}
}

// Record adds a new event to the audit log
func (al *AuditLog) Record(event Event) {
	al.mu.Lock()
	defer al.mu.Unlock()

	// Store in database
	err := al.db.Update(func(tx *bbolt.Tx) error {
		events := tx.Bucket([]byte("events"))
		if events == nil {
			return fmt.Errorf("events bucket not found")
		}

		// Generate key based on timestamp and type
		key := fmt.Sprintf("%d_%s_%s", event.Time.UnixNano(), event.Type, generateID())
		
		// Marshal event
		data, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("marshal event: %v", err)
		}

		// Store event
		if err := events.Put([]byte(key), data); err != nil {
			return fmt.Errorf("store event: %v", err)
		}

		// Update indexes
		indexes := tx.Bucket([]byte("indexes"))
		if indexes == nil {
			return fmt.Errorf("indexes bucket not found")
		}

		// Index by type
		typeKey := fmt.Sprintf("type_%s_%s", event.Type, key)
		if err := indexes.Put([]byte(typeKey), []byte(key)); err != nil {
			return fmt.Errorf("index type: %v", err)
		}

		// Index by source
		sourceKey := fmt.Sprintf("source_%s_%s", event.Source, key)
		if err := indexes.Put([]byte(sourceKey), []byte(key)); err != nil {
			return fmt.Errorf("index source: %v", err)
		}

		return nil
	})

	if err != nil {
		// Log error but don't fail - audit logging must be resilient
		fmt.Printf("Error recording audit event: %v\n", err)
	}

	// Add to buffer for real-time monitoring
	al.buffer = append(al.buffer, event)
	if len(al.buffer) > 1000 {
		al.buffer = al.buffer[1:]
	}

	// Notify watchers
	for _, watcher := range al.watchers {
		select {
		case watcher <- event:
		default:
			// Don't block if watcher is slow
		}
	}
}

// Query searches the audit log based on criteria
func (al *AuditLog) Query(ctx context.Context, query AuditQuery) ([]Event, error) {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var events []Event

	err := al.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("events"))
		if b == nil {
			return fmt.Errorf("events bucket not found")
		}

		c := b.Cursor()

		// Calculate key range based on time
		startKey := fmt.Sprintf("%d", query.StartTime.UnixNano())
		endKey := fmt.Sprintf("%d", query.EndTime.UnixNano())

		for k, v := c.Seek([]byte(startKey)); k != nil && bytes.Compare(k, []byte(endKey)) <= 0; k, v = c.Next() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			var event Event
			if err := json.Unmarshal(v, &event); err != nil {
				continue
			}

			// Apply filters
			if !al.matchesFilters(event, query) {
				continue
			}

			events = append(events, event)
			if query.Limit > 0 && len(events) >= query.Limit {
				break
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("query audit log: %v", err)
	}

	return events, nil
}

// Watch returns a channel that receives real-time audit events
func (al *AuditLog) Watch(ctx context.Context) <-chan Event {
	ch := make(chan Event, 100)
	
	al.mu.Lock()
	al.watchers = append(al.watchers, ch)
	al.mu.Unlock()

	// Remove watcher when context is done
	go func() {
		<-ctx.Done()
		al.mu.Lock()
		for i, w := range al.watchers {
			if w == ch {
				al.watchers = append(al.watchers[:i], al.watchers[i+1:]...)
				break
			}
		}
		al.mu.Unlock()
		close(ch)
	}()

	return ch
}

// GetRecentEvents returns the most recent events from the buffer
func (al *AuditLog) GetRecentEvents(n int) []Event {
	al.mu.RLock()
	defer al.mu.RUnlock()

	if n > len(al.buffer) {
		n = len(al.buffer)
	}

	events := make([]Event, n)
	copy(events, al.buffer[len(al.buffer)-n:])
	return events
}

// Internal helper functions

func (al *AuditLog) matchesFilters(event Event, query AuditQuery) bool {
	// Check event type
	if len(query.Types) > 0 {
		typeMatch := false
		for _, t := range query.Types {
			if event.Type == t {
				typeMatch = true
				break
			}
		}
		if !typeMatch {
			return false
		}
	}

	// Check source
	if len(query.Sources) > 0 {
		sourceMatch := false
		for _, s := range query.Sources {
			if event.Source == s {
				sourceMatch = true
				break
			}
		}
		if !sourceMatch {
			return false
		}
	}

	// Check user IDs if present in event data
	if len(query.UserIDs) > 0 {
		if userID, ok := event.Data["user_id"].(string); ok {
			userMatch := false
			for _, id := range query.UserIDs {
				if userID == id {
					userMatch = true
					break
				}
			}
			if !userMatch {
				return false
			}
		}
	}

	return true
}

// LogTailer provides real-time log streaming
type LogTailer struct {
	mu       sync.RWMutex
	watchers map[chan<- string]struct{}
}

func NewLogTailer() *LogTailer {
	return &LogTailer{
		watchers: make(map[chan<- string]struct{}),
	}
}

// Tail returns a channel that receives log entries
func (lt *LogTailer) Tail(ctx context.Context, n int) <-chan string {
	ch := make(chan string, n)

	lt.mu.Lock()
	lt.watchers[ch] = struct{}{}
	lt.mu.Unlock()

	// Remove watcher when context is done
	go func() {
		<-ctx.Done()
		lt.mu.Lock()
		delete(lt.watchers, ch)
		lt.mu.Unlock()
		close(ch)
	}()

	return ch
}

// Write implements io.Writer for log tailing
func (lt *LogTailer) Write(p []byte) (n int, err error) {
	line := string(p)

	lt.mu.RLock()
	for ch := range lt.watchers {
		select {
		case ch <- line:
		default:
			// Don't block if watcher is slow
		}
	}
	lt.mu.RUnlock()

	return len(p), nil
}
