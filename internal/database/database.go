package database

import (
	"encoding/json"
	"time"

	"github.com/boltdb/bolt"
)

var (
	userBucket = []byte("users")
	logsBucket = []byte("logs")
)

type BoltDB struct {
	db *bolt.DB
}

type User struct {
	Username    string    `json:"username"`
	Role        string    `json:"role"`
	Plan        string    `json:"plan"`
	LastLogin   time.Time `json:"last_login"`
	ActiveUntil time.Time `json:"active_until"`
}

func NewBoltDB(path string) (*BoltDB, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}

	// Create buckets if they don't exist
	err = db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range [][]byte{userBucket, logsBucket} {
			_, err := tx.CreateBucketIfNotExists(bucket)
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return &BoltDB{db: db}, nil
}

func (b *BoltDB) Close() error {
	return b.db.Close()
}

func (b *BoltDB) CreateUser(user *User) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(userBucket)
		encoded, err := json.Marshal(user)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(user.Username), encoded)
	})
}

func (b *BoltDB) GetUser(username string) (*User, error) {
	var user User
	err := b.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(userBucket)
		data := bucket.Get([]byte(username))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &user)
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (b *BoltDB) LogActivity(username, action, target string) error {
	entry := struct {
		Time     time.Time `json:"time"`
		Username string    `json:"username"`
		Action   string    `json:"action"`
		Target   string    `json:"target"`
	}{
		Time:     time.Now(),
		Username: username,
		Action:   action,
		Target:   target,
	}

	return b.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(logsBucket)
		encoded, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(time.Now().Format(time.RFC3339Nano)), encoded)
	})
}
