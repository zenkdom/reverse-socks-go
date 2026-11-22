package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"reverse-socks/pkg/control"
	"reverse-socks/pkg/users"
)

type failedAttempt struct {
	count int
	until time.Time
}

// WebServer provides the HTTP admin dashboard on port 9001.
type WebServer struct {
	agentManager       *control.AgentManager
	userManager        *users.UserManager
	mtprotoUserManager *users.MtprotoUserManager
	host               string
	port               int
	adminUser          string
	adminPass          string
	socks5Port         int
	mtprotoPort        int
	mtprotoSecret      string
	mtprotoDomain      string
	mtprotoTag         string
	sessions           map[string]time.Time
	sessionsMu         sync.RWMutex
	loginAttempts      map[string]*failedAttempt
	loginAttemptsMu    sync.Mutex
	server             *http.Server
}

// NewWebServer creates a new WebServer.
func NewWebServer(
	am *control.AgentManager,
	um *users.UserManager,
	mum *users.MtprotoUserManager,
	host string,
	port int,
	adminUser string,
	adminPass string,
	socks5Port int,
	mtprotoPort int,
	mtprotoSecret string,
	mtprotoDomain string,
	mtprotoTag string,
) *WebServer {
	if adminUser == "" {
		adminUser = "admin"
	}
	if adminPass == "" {
		adminPass = "changeme"
	}
	return &WebServer{
		agentManager:       am,
		userManager:        um,
		mtprotoUserManager: mum,
		host:               host,
		port:               port,
		adminUser:          adminUser,
		adminPass:          adminPass,
		socks5Port:         socks5Port,
		mtprotoPort:        mtprotoPort,
		mtprotoSecret:      mtprotoSecret,
		mtprotoDomain:      mtprotoDomain,
		mtprotoTag:         mtprotoTag,
		sessions:           make(map[string]time.Time),
		loginAttempts:      make(map[string]*failedAttempt),
	}
}

// Start starts HTTP server.
func (ws *WebServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", ws.handleLogin)
	mux.HandleFunc("/logout", ws.handleLogout)
	mux.HandleFunc("/api/status", ws.authWrap(ws.handleAPIStatus))
	mux.HandleFunc("/users/add", ws.authWrap(ws.handleAddUser))
	mux.HandleFunc("/users/delete", ws.authWrap(ws.handleDeleteUser))
	mux.HandleFunc("/mtproto/add", ws.authWrap(ws.handleAddMtproto))
	mux.HandleFunc("/mtproto/set_tag", ws.authWrap(ws.handleSetMtprotoTag))
	mux.HandleFunc("/mtproto/delete", ws.authWrap(ws.handleDeleteMtproto))
	mux.HandleFunc("/dashboard", ws.authWrap(ws.handleDashboard))
	mux.HandleFunc("/", ws.authWrap(ws.handleDashboard))

	addr := fmt.Sprintf("%s:%d", ws.host, ws.port)
	ws.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind admin web panel on %s: %w", addr, err)
	}

	log.Printf("[*] Admin Web Panel listening on http://%s (User: %s)", ln.Addr(), ws.adminUser)
	ws.server.Addr = ln.Addr().String()
	go func() {
		_ = ws.server.Serve(ln)
	}()
	return nil
}

// Addr returns the listening address.
func (ws *WebServer) Addr() string {
	if ws.server != nil {
		return ws.server.Addr
	}
	return ""
}

// Stop stops HTTP server.
func (ws *WebServer) Stop() error {
	if ws.server != nil {
		return ws.server.Close()
	}
	return nil
}

func (ws *WebServer) checkAuth(r *http.Request) bool {
	// Check Basic Auth with constant-time comparison
	if u, p, ok := r.BasicAuth(); ok {
		uMatch := subtle.ConstantTimeCompare([]byte(u), []byte(ws.adminUser)) == 1
		pMatch := subtle.ConstantTimeCompare([]byte(p), []byte(ws.adminPass)) == 1
		if uMatch && pMatch {
			return true
		}
	}

	// Check cookie
	if cookie, err := r.Cookie("admin_session"); err == nil && cookie.Value != "" {
		ws.sessionsMu.RLock()
		exp, ok := ws.sessions[cookie.Value]
		ws.sessionsMu.RUnlock()
		if ok && time.Now().Before(exp) {
			return true
		}
	}
	return false
}

func (ws *WebServer) authWrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ws.checkAuth(r) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				w.Header().Set("WWW-Authenticate", `Basic realm="Socks Admin"`)
				http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

func (ws *WebServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}

	if r.Method == http.MethodPost {
		// Rate limiting check
		ws.loginAttemptsMu.Lock()
		att, exists := ws.loginAttempts[clientIP]
		if exists && att.count >= 5 && time.Now().Before(att.until) {
			ws.loginAttemptsMu.Unlock()
			retryAfter := int(time.Until(att.until).Seconds())
			http.Error(w, fmt.Sprintf("Слишком много неудачных попыток входа. Попробуйте через %d секунд.", retryAfter), http.StatusTooManyRequests)
			return
		}
		ws.loginAttemptsMu.Unlock()

		_ = r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		uMatch := subtle.ConstantTimeCompare([]byte(username), []byte(ws.adminUser)) == 1
		pMatch := subtle.ConstantTimeCompare([]byte(password), []byte(ws.adminPass)) == 1

		if uMatch && pMatch {
			// Clear failed attempts
			ws.loginAttemptsMu.Lock()
			delete(ws.loginAttempts, clientIP)
			ws.loginAttemptsMu.Unlock()

			b := make([]byte, 24)
			_, _ = rand.Read(b)
			token := hex.EncodeToString(b)

			ws.sessionsMu.Lock()
			ws.sessions[token] = time.Now().Add(24 * time.Hour)
			ws.sessionsMu.Unlock()

			http.SetCookie(w, &http.Cookie{
				Name:     "admin_session",
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				Expires:  time.Now().Add(24 * time.Hour),
			})
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		// Record failed attempt
		ws.loginAttemptsMu.Lock()
		if att == nil {
			att = &failedAttempt{}
			ws.loginAttempts[clientIP] = att
		}
		att.count++
		if att.count >= 5 {
			att.until = time.Now().Add(5 * time.Minute)
		}
		ws.loginAttemptsMu.Unlock()

		http.Redirect(w, r, "/login?error="+url.QueryEscape("Invalid username or password"), http.StatusFound)
		return
	}

	errorMsg := r.URL.Query().Get("error")
	errorHTML := ""
	if errorMsg != "" {
		errorHTML = fmt.Sprintf(`<div class="alert error">%s</div>`, html.EscapeString(errorMsg))
	}

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign In | SOCKS5 Control Admin</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
body { background-color: #0f172a; color: #f8fafc; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
.card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 32px; width: 100%%; max-width: 400px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
h1 { font-size: 24px; font-weight: 700; margin-bottom: 8px; color: #6366f1; text-align: center; }
p.sub { color: #94a3b8; font-size: 14px; text-align: center; margin-bottom: 24px; }
.form-group { margin-bottom: 18px; }
label { display: block; font-size: 13px; font-weight: 600; color: #cbd5e1; margin-bottom: 6px; }
input { width: 100%%; padding: 10px 12px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #f8fafc; font-size: 14px; }
input:focus { outline: none; border-color: #6366f1; }
button { width: 100%%; padding: 12px; background: #6366f1; color: white; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; transition: background 0.2s; }
button:hover { background: #4f46e5; }
.alert { padding: 10px 14px; border-radius: 6px; font-size: 13px; margin-bottom: 18px; }
.alert.error { background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5; }
</style>
</head>
<body>
<div class="card">
  <h1>SOCKS5 Control (Go)</h1>
  <p class="sub">Server Administration Dashboard</p>
  %s
  <form method="POST" action="/login">
    <div class="form-group">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" required autocomplete="username" autofocus>
    </div>
    <div class="form-group">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required autocomplete="current-password">
    </div>
    <button type="submit">Sign In</button>
  </form>
</div>
</body>
</html>`, errorHTML)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(htmlContent))
}

func (ws *WebServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("admin_session"); err == nil {
		ws.sessionsMu.Lock()
		delete(ws.sessions, cookie.Value)
		ws.sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "admin_session",
		Value:   "deleted",
		Path:    "/",
		Expires: time.Unix(0, 0),
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (ws *WebServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")
	errMsg := r.URL.Query().Get("error")

	notificationHTML := ""
	if msg != "" {
		notificationHTML = fmt.Sprintf(`<div class="alert success">%s</div>`, html.EscapeString(msg))
	} else if errMsg != "" {
		notificationHTML = fmt.Sprintf(`<div class="alert error">%s</div>`, html.EscapeString(errMsg))
	}

	agents := ws.agentManager.GetAgentStatusList()
	socksUsers := ws.userManager.GetAllUsers()
	mtprotoClients := make([]users.MtprotoClient, 0)
	if ws.mtprotoUserManager != nil {
		mtprotoClients = ws.mtprotoUserManager.GetAllClients()
	}

	// Agents table
	var agentsRows strings.Builder
	if len(agents) == 0 {
		agentsRows.WriteString(`<tr><td colspan="6" class="empty">No active reverse nodes. Connect a socks-reverse node сервер.</td></tr>`)
	} else {
		for _, a := range agents {
			uptime := formatDuration(a.UptimeSeconds)
			isLastBadge := ""
			if a.IsLastUsed {
				isLastBadge = `<span class="badge" style="background: rgba(99, 102, 241, 0.2); color: #818cf8; border: 1px solid #6366f1;">ПОСЛЕДНЯЯ</span> `
			}
			transportBadge := `<span class="badge" style="font-size:10px; background:#1e293b; color:#94a3b8; border:1px solid #334155;">PLAIN TCP</span>`
			if a.IsFakeTLS {
				sni := a.SNIDomain
				if sni == "" {
					sni = "google.com"
				}
				transportBadge = fmt.Sprintf(`<span class="badge active" style="font-size:10px; background:rgba(99,102,241,0.2); color:#818cf8; border:1px solid #6366f1;">🔒 Fake-TLS (%s)</span>`, html.EscapeString(sni))
			}

			ipDisplay := fmt.Sprintf(`<code>%s</code>`, html.EscapeString(a.RemoteIP))
			if a.ExitIP != "" && a.ExitIP != a.RemoteIP {
				ipDisplay = fmt.Sprintf(`<code>%s</code> <span style='font-size:10px; color:#34d399; font-weight:600;'>✓ Exit IP</span><br><span style='font-size:11px; color:#64748b;'>Шлюз: %s</span>`, html.EscapeString(a.ExitIP), html.EscapeString(a.RemoteIP))
			}

			agentsRows.WriteString(fmt.Sprintf(`<tr>
  <td><span class="badge active">ONLINE</span> %s<strong>%s</strong></td>
  <td>%s</td>
  <td>%s</td>
  <td>%s</td>
  <td>%d</td>
  <td>%d</td>
</tr>`, isLastBadge, html.EscapeString(a.AgentID), transportBadge, ipDisplay, uptime, a.ActiveConnections, a.TotalHandled))
		}
	}

	// SOCKS5 Users table
	var usersRows strings.Builder
	if len(socksUsers) == 0 {
		usersRows.WriteString(`<tr><td colspan="5" class="empty">User list is empty. Add a new user below.</td></tr>`)
	} else {
		for uname, passwd := range socksUsers {
			usersRows.WriteString(fmt.Sprintf(`<tr>
  <td><strong>%s</strong></td>
  <td><code>%s</code></td>
  <td><span style='color:#64748b;'>—</span></td>
  <td>-</td>
  <td>
    <form method="POST" action="/users/delete" style="display:inline;" onsubmit="return confirm('Delete user %s?');">
      <input type="hidden" name="username" value="%s">
      <button type="submit" class="btn-danger">Delete</button>
    </form>
  </td>
</tr>`, html.EscapeString(uname), html.EscapeString(passwd), html.EscapeString(uname), html.EscapeString(uname)))
		}
	}

	// MTProto Clients table
	var mtprotoRows strings.Builder
	if len(mtprotoClients) == 0 {
		mtprotoRows.WriteString(`<tr><td colspan="7" class="empty">MTProto client list is empty. Create a new client below.</td></tr>`)
	} else {
		for _, c := range mtprotoClients {
			cTag := ""
			tagBadge := `<span style="font-size:10px; color:#64748b;">No TAG attached</span>`
			if c.Tag != nil && *c.Tag != "" {
				cTag = *c.Tag
				tagBadge = `<span class="badge active" style="font-size:9px; background:rgba(245,158,11,0.2); color:#fbbf24; border:1px solid #f59e0b;">✓ TAG АКТИВЕН</span>`
			}

			mtprotoRows.WriteString(fmt.Sprintf(`<tr>
  <td><span class="badge active" style="font-size:10px;">TG</span> <strong>%s</strong></td>
  <td><code style="font-size:12px; color:#38bdf8;">%s</code></td>
  <td><code style="color:#34d399; font-size:11px;">%s</code></td>
  <td>
    <form method="POST" action="/mtproto/set_tag" style="display:flex; gap:4px; align-items:center;">
      <input type="hidden" name="client_name" value="%s">
      <input type="text" name="tag" value="%s" placeholder="32 hex bot tag" style="width:160px; padding:4px 6px; font-size:11px; background:#0f172a; border:1px solid #334155; border-radius:4px; color:#fbbf24; font-family:monospace;" title="32-значный hex TAG промо-канала из @MTProxybot">
      <button type="submit" class="btn-primary" style="padding:4px 7px; font-size:11px; background:#f59e0b; color:#0f172a; font-weight:700;" title="Сохранить TAG промо-канала">💾</button>
    </form>
    <div style="margin-top:2px;">%s</div>
  </td>
  <td><span style='color:#64748b;'>—</span></td>
  <td>%s</td>
  <td style="white-space:nowrap;">
    <div style="display:flex; flex-direction:column; gap:4px;">
      <div style="display:flex; gap:4px;">
        <button type="button" class="btn-primary" style="background:#10b981; font-size:11px; padding:4px 8px; cursor:pointer;" title="Подключиться в Telegram через Fake-TLS" onclick="openTgForSecret('%s')">🚀 Fake-TLS</button>
        <button type="button" class="btn-primary" style="background:#0284c7; font-size:11px; padding:4px 8px; cursor:pointer;" title="Подключиться в Telegram по Hex32" onclick="openTgForSecret('%s')">🚀 Hex32</button>
      </div>
      <div style="display:flex; gap:4px; align-items:center;">
        <button type="button" class="btn-primary" style="background:#334155; font-size:11px; padding:4px 7px; cursor:pointer;" title="Скопировать ссылку Fake-TLS" onclick="copyTgForSecret('%s', 'Fake-TLS')">📋 Fake-TLS</button>
        <button type="button" class="btn-primary" style="background:#1e293b; border:1px solid #475569; font-size:11px; padding:4px 7px; cursor:pointer;" title="Скопировать ссылку Hex32" onclick="copyTgForSecret('%s', 'Hex32')">📋 Hex32</button>
        <form method="POST" action="/mtproto/delete" style="display:inline; margin-left:auto;" onsubmit="return confirm('Удалить MTProto клиента %s?');">
          <input type="hidden" name="client_name" value="%s">
          <button type="submit" class="btn-danger" style="padding:4px 8px; font-size:11px;" title="Delete client">✕</button>
        </form>
      </div>
    </div>
  </td>
</tr>`, html.EscapeString(c.ClientName), html.EscapeString(c.Secret), html.EscapeString(c.FakeTLSSecret),
				html.EscapeString(c.ClientName), html.EscapeString(cTag), tagBadge, html.EscapeString(c.CreatedAt),
				html.EscapeString(c.FakeTLSSecret), html.EscapeString(c.Secret),
				html.EscapeString(c.FakeTLSSecret), html.EscapeString(c.Secret),
				html.EscapeString(c.ClientName), html.EscapeString(c.ClientName)))
		}
	}

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dashboard | SOCKS5 & MTProto Control (Go)</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
body { background: #0f172a; color: #f8fafc; min-height: 100vh; padding: 24px; }
.container { max-width: 1200px; margin: 0 auto; }
header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; border-bottom: 1px solid #334155; padding-bottom: 16px; }
h1 { font-size: 22px; color: #6366f1; font-weight: 700; }
.btn-logout { background: #334155; color: #cbd5e1; border: none; padding: 8px 16px; border-radius: 6px; font-size: 13px; cursor: pointer; text-decoration: none; font-weight: 600; }
.btn-logout:hover { background: #475569; }
.card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; margin-bottom: 24px; }
.card h2 { font-size: 17px; margin-bottom: 16px; color: #cbd5e1; display: flex; justify-content: space-between; align-items: center; }
table { width: 100%%; border-collapse: collapse; font-size: 13px; text-align: left; }
th { background: #0f172a; padding: 10px 14px; font-weight: 600; color: #94a3b8; border-bottom: 1px solid #334155; }
td { padding: 12px 14px; border-bottom: 1px solid #334155; vertical-align: middle; }
tr:last-child td { border-bottom: none; }
.badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
.badge.active { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
code { background: #0f172a; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
.form-inline { display: flex; gap: 12px; margin-top: 16px; align-items: flex-end; flex-wrap: wrap; }
.form-inline .group { display: flex; flex-direction: column; gap: 4px; }
.form-inline label { font-size: 12px; font-weight: 600; color: #94a3b8; }
.form-inline input { padding: 8px 12px; background: #0f172a; border: 1px solid #334155; border-radius: 6px; color: #f8fafc; font-size: 13px; }
.btn-primary { background: #6366f1; color: white; border: none; padding: 9px 18px; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; }
.btn-danger { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; padding: 5px 10px; border-radius: 4px; font-size: 12px; cursor: pointer; }
.btn-danger:hover { background: #ef4444; color: white; }
.alert { padding: 12px 16px; border-radius: 8px; font-size: 14px; margin-bottom: 24px; }
.alert.success { background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; color: #6ee7b7; }
.alert.error { background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5; }
td.empty { text-align: center; color: #64748b; padding: 24px; }
</style>
<script>
function openTgForSecret(sec) {
  var host = window.location.hostname;
  var port = %d;
  window.location.href = "tg://proxy?server=" + host + "&port=" + port + "&secret=" + sec;
}
function copyTgForSecret(sec, mode) {
  var host = window.location.hostname;
  var port = %d;
  var link = "tg://proxy?server=" + host + "&port=" + port + "&secret=" + sec;
  navigator.clipboard.writeText(link).then(function() {
    alert("Ссылка " + mode + " скопирована в буфер обмена:\n" + link);
  });
}
</script>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>⚡ SOCKS5 & MTProto Proxy Control (Go High-Speed)</h1>
      <p style="font-size:12px; color:#94a3b8; margin-top:4px;">Высокопроизводительный обратный прокси-кластер на Go | SOCKS5: порт %d | MTProto: порт %d</p>
    </div>
    <a href="/logout" class="btn-logout">Sign Out</a>
  </header>

  %s

  <!-- Reverse Nodes -->
  <div class="card">
    <h2>Подключенные Reverse-Ноды (Выход в интернет)</h2>
    <table>
      <thead>
        <tr>
          <th>ID Агента</th>
          <th>Transport</th>
          <th>IP Ноды / Выход</th>
          <th>Аптайм</th>
          <th>Active Connections</th>
          <th>Total Relayed</th>
        </tr>
      </thead>
      <tbody>
        %s
      </tbody>
    </table>
  </div>

  <!-- MTProto Clients -->
  <div class="card">
    <h2>Клиенты Telegram MTProto Proxy (Fake-TLS + Hex32)</h2>
    <table>
      <thead>
        <tr>
          <th>Клиент</th>
          <th>Hex32 Secret</th>
          <th>Fake-TLS Secret</th>
          <th>Promo TAG (@MTProxybot)</th>
          <th>Последняя нода</th>
          <th>Создан</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        %s
      </tbody>
    </table>

    <form method="POST" action="/mtproto/add" class="form-inline">
      <div class="group">
        <label>Имя клиента</label>
        <input type="text" name="client_name" required placeholder="Например: my_telegram">
      </div>
      <div class="group">
        <label>Secret (32 hex или пусто для авто)</label>
        <input type="text" name="secret" placeholder="Автогенерация ключа">
      </div>
      <div class="group">
        <label>Fake-TLS Домен</label>
        <input type="text" name="domain" value="%s">
      </div>
      <div class="group">
        <label>Promo TAG (опционально)</label>
        <input type="text" name="tag" placeholder="32-hex тег из бота">
      </div>
      <button type="submit" class="btn-primary">Добавить клиента MTProto</button>
    </form>
  </div>

  <!-- SOCKS5 Users -->
  <div class="card">
    <h2>SOCKS5 Users / SOCKS4 / HTTP</h2>
    <table>
      <thead>
        <tr>
          <th>Username</th>
          <th>Password</th>
          <th>Последняя нода</th>
          <th>Создан</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        %s
      </tbody>
    </table>

    <form method="POST" action="/users/add" class="form-inline">
      <div class="group">
        <label>Username</label>
        <input type="text" name="username" required>
      </div>
      <div class="group">
        <label>Password</label>
        <input type="text" name="password" required>
      </div>
      <button type="submit" class="btn-primary">Добавить пользователя SOCKS5</button>
    </form>
  </div>

</div>
</body>
</html>`, ws.mtprotoPort, ws.mtprotoPort, ws.socks5Port, ws.mtprotoPort, notificationHTML, agentsRows.String(), mtprotoRows.String(), ws.mtprotoDomain, usersRows.String())

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(htmlContent))
}

func (ws *WebServer) handleAddUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	u := strings.TrimSpace(r.FormValue("username"))
	p := strings.TrimSpace(r.FormValue("password"))
	if u == "" || p == "" {
		http.Redirect(w, r, "/?error="+url.QueryEscape("Логин и пароль обязательны"), http.StatusFound)
		return
	}
	_ = ws.userManager.AddUser(u, p)
	http.Redirect(w, r, "/?msg="+url.QueryEscape("Пользователь SOCKS5 добавлен"), http.StatusFound)
}

func (ws *WebServer) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	u := strings.TrimSpace(r.FormValue("username"))
	if u != "" {
		_ = ws.userManager.DeleteUser(u)
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape("Пользователь удален"), http.StatusFound)
}

func (ws *WebServer) handleAddMtproto(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("client_name"))
	sec := strings.TrimSpace(r.FormValue("secret"))
	dom := strings.TrimSpace(r.FormValue("domain"))
	tag := strings.TrimSpace(r.FormValue("tag"))

	if ws.mtprotoUserManager != nil {
		ok, msg, _ := ws.mtprotoUserManager.AddClient(name, sec, dom, tag)
		if !ok {
			http.Redirect(w, r, "/?error="+url.QueryEscape(msg), http.StatusFound)
			return
		}
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape("MTProto клиент добавлен"), http.StatusFound)
}

func (ws *WebServer) handleSetMtprotoTag(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("client_name"))
	tag := strings.TrimSpace(r.FormValue("tag"))

	if ws.mtprotoUserManager != nil {
		ok, msg := ws.mtprotoUserManager.SetClientTag(name, tag)
		if !ok {
			http.Redirect(w, r, "/?error="+url.QueryEscape(msg), http.StatusFound)
			return
		}
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape("Тег промо-канала обновлен"), http.StatusFound)
}

func (ws *WebServer) handleDeleteMtproto(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("client_name"))
	if ws.mtprotoUserManager != nil && name != "" {
		_, _ = ws.mtprotoUserManager.DeleteClient(name)
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape("MTProto клиент удален"), http.StatusFound)
}

func (ws *WebServer) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]any{
		"agents":         ws.agentManager.GetAgentStatusList(),
		"total_requests": ws.agentManager.TotalRequests.Load(),
		"failovers":      ws.agentManager.FailoverCount.Load(),
		"socks5_port":    ws.socks5Port,
		"mtproto_port":   ws.mtprotoPort,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func formatDuration(sec int64) string {
	d := time.Duration(sec) * time.Second
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}
