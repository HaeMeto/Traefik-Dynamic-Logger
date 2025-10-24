package traefik_dynamic_logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Config struct {
	APIEndpoint  string `json:"apiEndpoint,omitempty"`
	BlockTTL     int    `json:"blockTTL,omitempty"`
	MaxBodyBytes int    `json:"maxBodyBytes,omitempty"`
	PathPrefix   string `json:"pathPrefix,omitempty"`
	ExtraHeaders string `json:"extraHeaders,omitempty"`

	// 🔽 Dinamis dari Traefik dynamic config
	DenyIPs          []string `json:"denyIPs,omitempty"`
	DenyCountries    []string `json:"denyCountries,omitempty"`
	DenyEmailDomains []string `json:"denyEmailDomains,omitempty"`
	EmailHeaders     []string `json:"emailHeaders,omitempty"`  // default: X-Email, X-Forwarded-Email
	CountryHeader    string   `json:"countryHeader,omitempty"` // default: X-Sec-Country (dari ForwardAuth) atau CF-IPCountry

	// 🔽 Optional: sinkronisasi list dari API terpusat
	ListURL        string `json:"listURL,omitempty"`        // GET endpoint → { ips:[], countries:[], emails:[] }
	RefreshSeconds int    `json:"refreshSeconds,omitempty"` // default: 30-60s

	// Verbose whoami-like logging
    Verbose      bool `json:"verbose,omitempty"`       // print blok mirip whoami
    DumpLocalIPs bool `json:"dumpLocalIPs,omitempty"`  // tampilkan semua IP interface
    LogHeaders   bool `json:"logHeaders,omitempty"`    // tampilkan seluruh headers
    LogCookies   bool `json:"logCookies,omitempty"`    // tampilkan Cookie header (default false)

	// JSON log (untuk Fail2Ban)
	JSONLogPath     string `json:"jsonLogPath,omitempty"`     // contoh: /var/log/traefik_plugin/requests.json
	JSONLogHeaders  bool   `json:"jsonLogHeaders,omitempty"`  // default true
	JSONLogCookies  bool   `json:"jsonLogCookies,omitempty"`  // default false
	JSONLogBody     bool   `json:"jsonLogBody,omitempty"`     // hati-hati PII; default false
}

func CreateConfig() *Config {
	return &Config{
        BlockTTL:       300,
        MaxBodyBytes:   64 * 1024,
        EmailHeaders:   []string{"X-Email", "X-Forwarded-Email"},
        CountryHeader:  "X-Sec-Country",
        RefreshSeconds: 60,
        Verbose:        true,   // default nyalakan; matikan di prod kalau perlu
        DumpLocalIPs:   false,
        LogHeaders:     true,
        LogCookies:     false,
		JSONLogHeaders: true,
		JSONLogCookies: false,
		JSONLogBody:    false,
    }
}

type denySets struct {
	ips    map[string]struct{}
	cc     map[string]struct{}
	emails map[string]struct{}
	mu     sync.RWMutex
}

type DynamicLogger struct {
	next         http.Handler
	apiEndpoint  string
	blockTTL     time.Duration
	maxBodyBytes int
	pathPrefix   string
	extraHeaders map[string]string

	// local block cache (TTL) → auto dari /log 403
	blockList sync.Map

	// runtime deny sets (config + remote sync)
	sets *denySets

	// config
	emailHeaders  []string
	countryHeader string

	// remote list sync
	listURL        string
	refreshSeconds int
	stopCh         chan struct{}

	verbose      bool
    dumpLocalIPs bool
    logHeaders   bool
    logCookies   bool

	jsonLogPath    string
	jsonLogHeaders bool
	jsonLogCookies bool
	jsonLogBody    bool
	fileMu         sync.Mutex
}

type whoamiLog struct {
  Event       string              `json:"event"`        // "request", "denied", "blocked_cached", "blocked_api", "allowed"
  TS          string              `json:"ts"`
  Hostname    string              `json:"hostname,omitempty"`
  RemoteAddr  string              `json:"remoteAddr"`
  ClientIP    string              `json:"clientIp"`
  ClientChain []string            `json:"clientChain,omitempty"`
  Method      string              `json:"method"`
  Path        string              `json:"path"`
  Query       string              `json:"query,omitempty"`
  Proto       string              `json:"proto"`
  Host        string              `json:"host"`
  Headers     map[string][]string `json:"headers,omitempty"`
  Body        string              `json:"body,omitempty"`
  TLSProto    string              `json:"tlsProto,omitempty"`
  TLSCipher   string              `json:"tlsCipher,omitempty"`
  TLSServer   string              `json:"tlsSNI,omitempty"`
  LocalIPs    []string            `json:"localIPs,omitempty"`
  Decision    string              `json:"decision"`      // "allow" / "deny"
  Reason      string              `json:"reason,omitempty"`
}

func New(_ any, next http.Handler, cfg *Config, _ string) (http.Handler, error) {
	eh := map[string]string{}
	if cfg.ExtraHeaders != "" {
		for _, p := range strings.Split(cfg.ExtraHeaders, ";") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			kv := strings.SplitN(p, "=", 2)
			if len(kv) == 2 {
				eh[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}
	m := &DynamicLogger{
		next:           next,
		apiEndpoint:    strings.TrimRight(cfg.APIEndpoint, "/"),
		blockTTL:       time.Duration(cfg.BlockTTL) * time.Second,
		maxBodyBytes:   cfg.MaxBodyBytes,
		pathPrefix:     cfg.PathPrefix,
		extraHeaders:   eh,
		sets:           &denySets{ips: map[string]struct{}{}, cc: map[string]struct{}{}, emails: map[string]struct{}{}},
		emailHeaders:   cfg.EmailHeaders,
		countryHeader:  cfg.CountryHeader,
		listURL:        cfg.ListURL,
		refreshSeconds: cfg.RefreshSeconds,
		stopCh:         make(chan struct{}),
		verbose:      cfg.Verbose,
		dumpLocalIPs: cfg.DumpLocalIPs,
		logHeaders:   cfg.LogHeaders,
		logCookies:   cfg.LogCookies,
		jsonLogPath:    cfg.JSONLogPath,
		jsonLogHeaders: cfg.JSONLogHeaders,
		jsonLogCookies: cfg.JSONLogCookies,
		jsonLogBody:    cfg.JSONLogBody,
	}
	// seed from dynamic config
	m.seedSets(cfg)
	// start remote sync if configured
	if m.listURL != "" && m.refreshSeconds > 0 {
		go m.syncLoop()
	}
	return m, nil
}

func (m *DynamicLogger) seedSets(cfg *Config) {
	m.sets.mu.Lock()
	defer m.sets.mu.Unlock()
	m.sets.ips = toSet(cfg.DenyIPs, false)
	m.sets.cc = toSet(cfg.DenyCountries, true)        // store uppercase
	m.sets.emails = toSet(cfg.DenyEmailDomains, true) // store lowercase
}

func (m *DynamicLogger) writeJSONL(v any) {
  if m.jsonLogPath == "" {
    return
  }
  b, err := json.Marshal(v)
  if err != nil {
    return
  }
  b = append(b, '\n')
  m.fileMu.Lock()
  defer m.fileMu.Unlock()
  f, err := os.OpenFile(m.jsonLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
  if err != nil {
    return
  }
  _, _ = f.Write(b)
  _ = f.Close()
}

func toSet(arr []string, norm bool) map[string]struct{} {
	s := map[string]struct{}{}
	for _, v := range arr {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if norm {
			// if it's country/email we normalize differently
			if len(v) == 2 {
				v = strings.ToUpper(v)
			} else {
				v = strings.ToLower(v)
			}
		}
		s[v] = struct{}{}
	}
	return s
}

func clientIPFromRemote(addr string) string {
    if ip, _, err := net.SplitHostPort(addr); err == nil {
        return ip
    }
    return addr
}

func clientChain(req *http.Request) []string {
    var chain []string
    if cf := strings.TrimSpace(req.Header.Get("CF-Connecting-IP")); cf != "" {
        chain = append(chain, cf+" (CF-Connecting-IP)")
    }
    if xr := strings.TrimSpace(req.Header.Get("X-Real-Ip")); xr != "" {
        chain = append(chain, xr+" (X-Real-IP)")
    }
    if xff := strings.TrimSpace(req.Header.Get("X-Forwarded-For")); xff != "" {
        parts := strings.Split(xff, ",")
        for i := range parts {
            parts[i] = strings.TrimSpace(parts[i])
        }
        chain = append(chain, strings.Join(parts, " -> ")+" (X-Forwarded-For)")
    }
    // always include RemoteAddr ip
    chain = append(chain, clientIPFromRemote(req.RemoteAddr)+" (RemoteAddr)")
    return chain
}

func localIPs() []string {
    var res []string
    ifaces, _ := net.Interfaces()
    for _, ifc := range ifaces {
        addrs, _ := ifc.Addrs()
        for _, a := range addrs {
            res = append(res, a.String())
        }
    }
    sort.Strings(res)
    return res
}

func dumpHeaders(h http.Header, includeCookies bool) string {
    keys := make([]string, 0, len(h))
    for k := range h {
        if !includeCookies && strings.EqualFold(k, "Cookie") {
            continue
        }
        keys = append(keys, k)
    }
    sort.Strings(keys)
    var b strings.Builder
    for _, k := range keys {
        for _, v := range h.Values(k) {
            b.WriteString(k)
            b.WriteString(": ")
            b.WriteString(v)
            b.WriteString("\n")
        }
    }
    return b.String()
}

func (m *DynamicLogger) syncLoop() {
	t := time.NewTicker(time.Duration(m.refreshSeconds) * time.Second)
	defer t.Stop()
	client := &http.Client{Timeout: 2 * time.Second}
	for {
		select {
		case <-t.C:
			req, _ := http.NewRequest(http.MethodGet, m.listURL, nil)
			for k, v := range m.extraHeaders {
				req.Header.Set(k, v)
			}
			resp, err := client.Do(req)
			if err != nil || resp == nil {
				continue
			}
			var payload struct {
				IPs       []string `json:"ips"`
				Countries []string `json:"countries"`
				Emails    []string `json:"emails"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&payload)
			_ = resp.Body.Close()

			m.sets.mu.Lock()
			m.sets.ips = toSet(payload.IPs, false)
			m.sets.cc = toSet(payload.Countries, true)
			m.sets.emails = toSet(payload.Emails, true)
			m.sets.mu.Unlock()
		case <-m.stopCh:
			return
		}
	}
}

func (m *DynamicLogger) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ip, _, _ := net.SplitHostPort(req.RemoteAddr)
	now := time.Now().UTC().Format(time.RFC3339Nano)

	if m.verbose {
		host, _ := os.Hostname()
		chain := clientChain(req)
		fmt.Printf(
			"[sec-logger] host=%s ip=%s method=%s path=%s proto=%s ua=%q xff=%q cfip=%q cfcountry=%q tls=%v\n",
			host,
			clientIPFromRemote(req.RemoteAddr),
			req.Method,
			req.URL.Path,
			req.Proto,
			req.Header.Get("User-Agent"),
			req.Header.Get("X-Forwarded-For"),
			req.Header.Get("CF-Connecting-IP"),
			req.Header.Get("CF-IPCountry"),
			req.TLS != nil,
		)
	}

	hostName, _ := os.Hostname()
	wj := whoamiLog{
	Event:      "request",
	TS:         now,
	Hostname:   hostName,
	RemoteAddr: req.RemoteAddr,
	ClientIP:   ip,
	ClientChain: clientChain(req),
	Method:     req.Method,
	Path:       req.URL.Path,
	Query:      req.URL.RawQuery,
	Proto:      req.Proto,
	Host:       req.Host,
	Decision:   "unknown",
	}
	if req.TLS != nil {
	wj.TLSProto = req.TLS.NegotiatedProtocol
	wj.TLSCipher = fmt.Sprintf("0x%x", req.TLS.CipherSuite)
	wj.TLSServer = req.TLS.ServerName
	}
	if m.dumpLocalIPs {
	wj.LocalIPs = localIPs()
	}
	if m.jsonLogHeaders {
	// clone headers, optionally strip Cookie
	wj.Headers = map[string][]string{}
	for k, vals := range req.Header {
		if !m.jsonLogCookies && strings.EqualFold(k, "Cookie") {
		continue
		}
		vv := make([]string, len(vals))
		copy(vv, vals)
		wj.Headers[k] = vv
	}
	}

	// local auto-block cache
	if _, blocked := m.blockList.Load(ip); blocked {
		fmt.Printf("[sec-logger] BLOCKED (cached) %s\n", ip)
		wj.Event = "blocked_cached"
		wj.Decision = "deny"
		wj.Reason = "cached_ttl"
		m.writeJSONL(wj)
		rw.WriteHeader(http.StatusForbidden)
		rw.Write([]byte("Access Denied"))
		return
	}
	// path filter
	if m.pathPrefix != "" && !strings.HasPrefix(req.URL.Path, m.pathPrefix) {
		m.next.ServeHTTP(rw, req)
		return
	}

	// 🔒 Dinamis deny (IP / Region / Email)
	if m.isDenied(ip, req) {
		fmt.Printf("[sec-logger] DENIED (ruleset) %s\n", ip)
		wj.Event = "denied"
		wj.Decision = "deny"
		wj.Reason = "ruleset"
		m.writeJSONL(wj)

		rw.WriteHeader(http.StatusForbidden)
		rw.Write([]byte("Access Denied"))
		return
	}

	// body handling (lightweight)
	var bodyStr string
	if m.maxBodyBytes > 0 {
		limited := io.LimitReader(req.Body, int64(m.maxBodyBytes))
		b, _ := io.ReadAll(limited)
		bodyStr = string(b)
	} else {
		bodyStr = ""
	}
	req.Body = io.NopCloser(bytes.NewBufferString(bodyStr))
	if m.jsonLogBody {
		wj.Body = bodyStr
	}
	// build payload
	payload := map[string]any{
		"ip":      ip,
		"method":  req.Method,
		"path":    req.URL.Path,
		"query":   req.URL.RawQuery,
		"host":    req.Host,
		"headers": req.Header,
		"body":    bodyStr,
		"ts":      time.Now().UTC().Format(time.RFC3339Nano),
	}

	// async report to API
	go func() {
		if m.apiEndpoint == "" {
			return
		}
		b, _ := json.Marshal(payload)
		httpReq, _ := http.NewRequest(http.MethodPost, m.apiEndpoint+"/log", bytes.NewReader(b))
		httpReq.Header.Set("Content-Type", "application/json")
		for k, v := range m.extraHeaders {
			httpReq.Header.Set(k, v)
		}
		client := &http.Client{Timeout: 2 * time.Second}
		if resp, err := client.Do(httpReq); err == nil && resp != nil {
			if resp.StatusCode == http.StatusForbidden {
				fmt.Printf("[sec-logger] BLOCKED by API %s\n", ip)
				// tulis JSON
				wjAPI := wj
				wjAPI.Event = "blocked_api"
				wjAPI.Decision = "deny"
				wjAPI.Reason = "api"
				m.writeJSONL(wjAPI)

				m.blockList.Store(ip, time.Now().Add(m.blockTTL))
				go m.expire(ip)
			}
			_ = resp.Body.Close()
		} else if err != nil {
			fmt.Printf("[sec-logger] API error: %v\n", err)
		}
	}()

	// mark allow for this path (note: jika nanti API memutuskan block, sudah ditulis "blocked_api" di atas)
	wj.Event = "allowed"
	wj.Decision = "allow"
	m.writeJSONL(wj)

	m.next.ServeHTTP(rw, req)
}

func (m *DynamicLogger) isDenied(ip string, req *http.Request) bool {
	m.sets.mu.RLock()
	defer m.sets.mu.RUnlock()

	// IP
	if _, ok := m.sets.ips[ip]; ok {
		return true
	}
	// Country (header from ForwardAuth or CF)
	cc := ""
	if m.countryHeader != "" {
		cc = strings.TrimSpace(req.Header.Get(m.countryHeader))
	}
	if cc == "" {
		// fallback CF-IPCountry if available
		cc = strings.TrimSpace(req.Header.Get("CF-IPCountry"))
	}
	if cc != "" {
		ccU := strings.ToUpper(cc)
		if _, ok := m.sets.cc[ccU]; ok {
			return true
		}
	}
	// Email
	for _, h := range m.emailHeaders {
		em := strings.TrimSpace(req.Header.Get(h))
		if em == "" {
			continue
		}
		// compare by domain
		if i := strings.LastIndex(em, "@"); i > 0 {
			d := strings.ToLower(em[i+1:])
			if _, ok := m.sets.emails[d]; ok {
				return true
			}
		}
	}
	return false
}

func (m *DynamicLogger) expire(ip string) {
	timer := time.NewTimer(m.blockTTL)
	<-timer.C
	m.blockList.Delete(ip)
}