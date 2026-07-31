// Package gateway provides the minimal Vuelta-owned stable HTTP hop used when
// an existing reverse proxy already targets a fixed Docker DNS name.
package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxConfigBytes = 16 << 10

var hostPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// Config contains routing metadata only. Credentials, arbitrary headers,
// paths, and transport-specific proxy configuration are deliberately absent.
type Config struct {
	Listen   string `json:"listen"`
	Upstream string `json:"upstream"`
}

// Load reads one bounded protected config file.
func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open gateway config: %w", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read gateway config: %w", err)
	}
	if len(data) > maxConfigBytes {
		return Config{}, errors.New("gateway config exceeds bounded size")
	}
	var config Config
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, errors.New("gateway config is invalid")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

// Validate restricts the gateway to one local container-network HTTP target.
func (c Config) Validate() error {
	listenHost, listenPort, err := net.SplitHostPort(c.Listen)
	if err != nil || (listenHost != "" && listenHost != "0.0.0.0") || !validPort(listenPort) {
		return errors.New("gateway listen must be 0.0.0.0:PORT or :PORT")
	}
	upstream, err := url.Parse(c.Upstream)
	if err != nil || upstream.Scheme != "http" || upstream.User != nil ||
		upstream.Path != "" || upstream.RawQuery != "" || upstream.Fragment != "" ||
		!hostPattern.MatchString(upstream.Hostname()) || !validPort(upstream.Port()) {
		return errors.New("gateway upstream must be one http://CONTAINER:PORT target")
	}
	return nil
}

// Handler atomically swaps the reverse proxy after a validated reload.
type Handler struct {
	mutex    sync.RWMutex
	upstream string
	proxy    *httputil.ReverseProxy
}

// NewHandler creates a validated routing handler.
func NewHandler(config Config) (*Handler, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	handler := &Handler{}
	if err := handler.Reload(config); err != nil {
		return nil, err
	}
	return handler, nil
}

// Reload swaps only after the complete candidate configuration is valid.
func (h *Handler) Reload(config Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	target, err := url.Parse(config.Upstream)
	if err != nil {
		return errors.New("gateway upstream is invalid")
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	proxy.ErrorHandler = func(response http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(response, "upstream unavailable", http.StatusBadGateway)
	}
	h.mutex.Lock()
	previous := h.proxy
	h.proxy = proxy
	h.upstream = config.Upstream
	h.mutex.Unlock()
	if previous != nil {
		if transport, ok := previous.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
	return nil
}

// Upstream returns the current safe target for health reporting.
func (h *Handler) Upstream() string {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.upstream
}

// ServeHTTP forwards requests without exposing config or upstream errors.
func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/__vuelta/health" {
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("ok\n"))
		return
	}
	h.mutex.RLock()
	proxy := h.proxy
	h.mutex.RUnlock()
	if proxy == nil {
		http.Error(response, "upstream unavailable", http.StatusServiceUnavailable)
		return
	}
	proxy.ServeHTTP(response, request)
}

func validPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port > 0 && port <= 65535
}
