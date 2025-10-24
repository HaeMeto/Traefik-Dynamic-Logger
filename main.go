package traefik_dynamic_logger

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type Config struct {
	APIEndpoint string `json:"apiEndpoint,omitempty"`
	BlockTTL    int    `json:"blockTTL,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		BlockTTL: 300, // default 5 menit
	}
}

type DynamicLogger struct {
	next        http.Handler
	apiEndpoint string
	blockTTL    time.Duration
	blockList   sync.Map
}

func New(_ any, next http.Handler, cfg *Config, _ string) (http.Handler, error) {
	return &DynamicLogger{
		next:        next,
		apiEndpoint: cfg.APIEndpoint,
		blockTTL:    time.Duration(cfg.BlockTTL) * time.Second,
	}, nil
}

func (m *DynamicLogger) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ip, _, _ := net.SplitHostPort(req.RemoteAddr)

	// Cek blocklist lokal
	if _, blocked := m.blockList.Load(ip); blocked {
		rw.WriteHeader(http.StatusForbidden)
		rw.Write([]byte("Access Denied"))
		return
	}

	// Baca dan restore body
	bodyBytes, _ := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Buat metadata
	data := map[string]any{
		"ip":      ip,
		"method":  req.Method,
		"path":    req.URL.Path,
		"headers": req.Header,
		"body":    string(bodyBytes),
		"time":    time.Now().Format(time.RFC3339),
	}

	// Kirim ke API eksternal secara async
	go func() {
		b, _ := json.Marshal(data)
		resp, err := http.Post(m.apiEndpoint+"/log", "application/json", bytes.NewReader(b))
		if err == nil && resp.StatusCode == 403 {
			// Jika API balas 403 → ban sementara
			m.blockList.Store(ip, time.Now().Add(m.blockTTL))
			go m.expireBlock(ip)
		}
	}()

	m.next.ServeHTTP(rw, req)
}

func (m *DynamicLogger) expireBlock(ip string) {
	time.Sleep(m.blockTTL)
	m.blockList.Delete(ip)
}
