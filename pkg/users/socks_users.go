package users

import (
	"crypto/subtle"
	"encoding/json"
	"os"
	"sync"
)

// UserManager handles SOCKS5 / HTTP user credentials persisted in JSON.
type UserManager struct {
	filepath string
	users    map[string]string // username -> password
	mu       sync.RWMutex
}

// NewUserManager creates a new UserManager.
func NewUserManager(filepath string) *UserManager {
	if filepath == "" {
		filepath = "users.json"
	}
	um := &UserManager{
		filepath: filepath,
		users:    make(map[string]string),
	}
	um.load()
	return um
}

func (m *UserManager) load() {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.filepath)
	if err != nil || len(data) == 0 {
		return
	}

	// 1. Try plain map[string]string: {"user": "pass"}
	var uMap map[string]string
	if err := json.Unmarshal(data, &uMap); err == nil && uMap != nil {
		m.users = uMap
		return
	}

	// 2. Try nested object: {"users": {"user": "pass"}}
	var nestedMap struct {
		Users map[string]string `json:"users"`
	}
	if err := json.Unmarshal(data, &nestedMap); err == nil && nestedMap.Users != nil {
		m.users = nestedMap.Users
		return
	}

	// 3. Try array format: {"users": [{"username": "...", "password": "..."}]}
	var listFormat struct {
		Users []struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"users"`
	}
	if err := json.Unmarshal(data, &listFormat); err == nil && len(listFormat.Users) > 0 {
		m.users = make(map[string]string)
		for _, u := range listFormat.Users {
			if u.Username != "" {
				m.users[u.Username] = u.Password
			}
		}
		return
	}

	// 4. Try bare array: [{"username": "...", "password": "..."}]
	var bareList []struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(data, &bareList); err == nil && len(bareList) > 0 {
		m.users = make(map[string]string)
		for _, u := range bareList {
			if u.Username != "" {
				m.users[u.Username] = u.Password
			}
		}
	}
}

func (m *UserManager) save() error {
	data, err := json.MarshalIndent(m.users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.filepath, data, 0644)
}

// Authenticate checks if username and password match using constant-time comparison.
func (m *UserManager) Authenticate(username, password string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.users) == 0 {
		return false
	}
	pass, ok := m.users[username]
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(pass), []byte(password)) == 1
}

// HasUser checks if a username exists in database.
func (m *UserManager) HasUser(username string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.users[username]
	return ok
}

// AddUser adds or updates a user credential.
func (m *UserManager) AddUser(username, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.users[username] = password
	return m.save()
}

// DeleteUser removes a user.
func (m *UserManager) DeleteUser(username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.users, username)
	return m.save()
}

// GetAllUsers returns a copy of all registered users.
func (m *UserManager) GetAllUsers() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make(map[string]string, len(m.users))
	for k, v := range m.users {
		res[k] = v
	}
	return res
}
