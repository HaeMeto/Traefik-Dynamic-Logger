package traefik_dynamic_logger

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
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
}

func CreateConfig() *Config {
	return &Config{
		BlockTTL:       300,
		MaxBodyBytes:   64 * 1024,
		EmailHeaders:   []string{"X-Email", "X-Forwarded-Email"},
		CountryHeader:  "X-Sec-Country",
		RefreshSeconds: 60,
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

	// local auto-block cache
	if _, blocked := m.blockList.Load(ip); blocked {
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
				m.blockList.Store(ip, time.Now().Add(m.blockTTL))
				go m.expire(ip)
			}
			_ = resp.Body.Close()
		}
	}()

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
