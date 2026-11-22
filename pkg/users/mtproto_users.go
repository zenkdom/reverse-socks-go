package users

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var hexRegex = regexp.MustCompile(`[^0-9a-fA-F]`)

// MtprotoClient represents a single registered Telegram MTProto client.
type MtprotoClient struct {
	ClientName    string  `json:"client_name"`
	Secret        string  `json:"secret"`          // 32 hex chars
	Domain        string  `json:"domain"`          // e.g. google.com
	FakeTLSSecret string  `json:"fake_tls_secret"` // ee + secret + hex(domain)
	Tag           *string `json:"tag"`             // Promo channel tag (32 hex chars) or nil
	CreatedAt     string  `json:"created_at"`
}

type mtprotoFile struct {
	Clients []MtprotoClient `json:"clients"`
}

// NormalizeHexSecret normalizes secret to (rawHex32, domain, fakeTLSSecret).
func NormalizeHexSecret(secretStr string, domain string) (string, string, string) {
	if domain == "" {
		domain = "google.com"
	}
	cleaned := strings.ToLower(strings.TrimSpace(secretStr))

	if cleaned == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		rawHex := hex.EncodeToString(b)
		domainHex := hex.EncodeToString([]byte(domain))
		return rawHex, domain, fmt.Sprintf("ee%s%s", rawHex, domainHex)
	}

	if strings.HasPrefix(cleaned, "ee") && len(cleaned) > 34 {
		rawHex := cleaned[2:34]
		domainHex := cleaned[34:]
		if dBytes, err := hex.DecodeString(domainHex); err == nil && len(dBytes) > 0 {
			domain = string(dBytes)
		}
		return rawHex, domain, cleaned
	}

	rawHex := hexRegex.ReplaceAllString(cleaned, "")
	if len(rawHex) < 32 {
		rawHex = fmt.Sprintf("%032s", rawHex)
	} else if len(rawHex) > 32 {
		rawHex = rawHex[:32]
	}

	domainHex := hex.EncodeToString([]byte(domain))
	fakeTLS := fmt.Sprintf("ee%s%s", rawHex, domainHex)
	return rawHex, domain, fakeTLS
}

// NormalizeTag normalizes promo tag from @MTProxybot (32 hex chars).
func NormalizeTag(tagStr string) *string {
	cleaned := hexRegex.ReplaceAllString(strings.TrimSpace(tagStr), "")
	cleaned = strings.ToLower(cleaned)
	if len(cleaned) == 32 {
		return &cleaned
	}
	return nil
}

// MtprotoUserManager manages MTProto clients and persistence.
type MtprotoUserManager struct {
	filepath      string
	defaultSecret string
	defaultDomain string
	defaultTag    *string
	clients       map[string]MtprotoClient // client_name -> client
	mu            sync.RWMutex
}

// NewMtprotoUserManager creates and loads an MtprotoUserManager.
func NewMtprotoUserManager(filepath, defaultSecret, defaultDomain, defaultTag string) *MtprotoUserManager {
	if filepath == "" {
		filepath = "mtproto_users.json"
	}
	if defaultDomain == "" {
		defaultDomain = "google.com"
	}
	m := &MtprotoUserManager{
		filepath:      filepath,
		defaultSecret: defaultSecret,
		defaultDomain: defaultDomain,
		defaultTag:    NormalizeTag(defaultTag),
		clients:       make(map[string]MtprotoClient),
	}
	m.load()
	return m
}

func (m *MtprotoUserManager) load() {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.filepath)
	if err == nil && len(data) > 0 {
		var f mtprotoFile
		if err := json.Unmarshal(data, &f); err == nil {
			for _, c := range f.Clients {
				m.clients[c.ClientName] = c
			}
		}
	}

	if len(m.clients) == 0 && m.defaultSecret != "" {
		rawHex, dom, fakeTLS := NormalizeHexSecret(m.defaultSecret, m.defaultDomain)
		defClient := MtprotoClient{
			ClientName:    "default",
			Secret:        rawHex,
			Domain:        dom,
			FakeTLSSecret: fakeTLS,
			Tag:           m.defaultTag,
			CreatedAt:     time.Now().Format("2006-01-02 15:04:05"),
		}
		m.clients["default"] = defClient
		_ = m.saveLocked()
	} else if def, ok := m.clients["default"]; ok && def.Tag == nil && m.defaultTag != nil {
		def.Tag = m.defaultTag
		m.clients["default"] = def
		_ = m.saveLocked()
	}
}

func (m *MtprotoUserManager) saveLocked() error {
	list := make([]MtprotoClient, 0, len(m.clients))
	for _, c := range m.clients {
		list = append(list, c)
	}
	f := mtprotoFile{Clients: list}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.filepath, data, 0644)
}

// GetSecretsMap returns a map of client_name -> 16-byte raw secret.
func (m *MtprotoUserManager) GetSecretsMap() map[string][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make(map[string][]byte, len(m.clients))
	for name, client := range m.clients {
		if raw, err := hex.DecodeString(client.Secret); err == nil && len(raw) == 16 {
			res[name] = raw
		}
	}
	return res
}

// GetTagForUser returns promo tag for user, if any.
func (m *MtprotoUserManager) GetTagForUser(name string) *string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if client, ok := m.clients[name]; ok {
		return client.Tag
	}
	return nil
}

// GetAllClients returns a copy of all registered clients.
func (m *MtprotoUserManager) GetAllClients() []MtprotoClient {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]MtprotoClient, 0, len(m.clients))
	for _, c := range m.clients {
		list = append(list, c)
	}
	return list
}

// AddClient adds a new MTProto client.
func (m *MtprotoUserManager) AddClient(clientName, secret, domain, tag string) (bool, string, *MtprotoClient) {
	clientName = strings.TrimSpace(clientName)
	if clientName == "" {
		return false, "Имя клиента MTProto не может быть пустым", nil
	}

	dom := domain
	if dom == "" {
		dom = m.defaultDomain
	}
	rawHex, dom, fakeTLS := NormalizeHexSecret(secret, dom)

	var tagPtr *string
	if strings.TrimSpace(tag) != "" {
		tagPtr = NormalizeTag(tag)
		if tagPtr == nil {
			return false, "Тег промо-канала должен содержать ровно 32 hex-символа (16 байт) из @MTProxybot", nil
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	client := MtprotoClient{
		ClientName:    clientName,
		Secret:        rawHex,
		Domain:        dom,
		FakeTLSSecret: fakeTLS,
		Tag:           tagPtr,
		CreatedAt:     time.Now().Format("2006-01-02 15:04:05"),
	}

	m.clients[clientName] = client
	if err := m.saveLocked(); err != nil {
		return false, err.Error(), nil
	}

	return true, "Клиент успешно добавлен", &client
}

// SetClientTag sets or updates promo TAG for an MTProto client.
func (m *MtprotoUserManager) SetClientTag(clientName, tag string) (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	client, ok := m.clients[clientName]
	if !ok {
		return false, "Клиент не найден"
	}

	if strings.TrimSpace(tag) == "" {
		client.Tag = nil
	} else {
		tagPtr := NormalizeTag(tag)
		if tagPtr == nil {
			return false, "Тег промо-канала должен содержать ровно 32 hex-символа"
		}
		client.Tag = tagPtr
	}

	m.clients[clientName] = client
	if err := m.saveLocked(); err != nil {
		return false, err.Error()
	}
	return true, "Тег успешно обновлен"
}

// DeleteClient deletes an MTProto client.
func (m *MtprotoUserManager) DeleteClient(clientName string) (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.clients[clientName]; !ok {
		return false, "Клиент не найден"
	}
	delete(m.clients, clientName)
	if err := m.saveLocked(); err != nil {
		return false, err.Error()
	}
	return true, "Клиент успешно удален"
}
