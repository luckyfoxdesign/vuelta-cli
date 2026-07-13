// Command egress-proxy is the deliberately small, local forward proxy used
// by Vuelta update containers. It only permits configured registry hostnames;
// clients cannot connect to the public network directly because their Docker
// network is internal.
package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

const listenAddress = ":3128"

func main() {
	allow, err := parseAllowHosts(os.Getenv("VUELTA_EGRESS_ALLOW_HOSTS"))
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:              listenAddress,
		Handler:           proxy{allow: allow},
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("starting egress proxy on %s for %d allowlisted host(s)", listenAddress, len(allow))
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

type proxy struct {
	allow map[string]struct{}
}

func (p proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	p.forwardHTTP(w, r)
}

func (p proxy) connect(w http.ResponseWriter, r *http.Request) {
	host, port, err := splitTarget(r.Host, "443")
	if err != nil {
		http.Error(w, "invalid CONNECT target", http.StatusBadRequest)
		return
	}
	if !p.allowed(host) {
		http.Error(w, "target is not in the registry allowlist", http.StatusForbidden)
		return
	}

	dialer := net.Dialer{Timeout: 10 * time.Second}
	upstream, err := dialer.DialContext(r.Context(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		http.Error(w, "allowlisted target is unavailable", http.StatusBadGateway)
		return
	}
	defer closeConn("upstream connection", upstream)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "server does not support tunnelling", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer closeConn("client connection", client)
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	if buffered.Reader.Buffered() > 0 {
		if _, err := buffered.WriteTo(upstream); err != nil {
			logCopyError("buffered client data", err)
			return
		}
	}

	done := make(chan error, 1)
	var closeUpstream sync.Once
	closeUpstreamFn := func() {
		closeUpstream.Do(func() { closeConn("upstream connection", upstream) })
	}
	go func() {
		_, err := io.Copy(upstream, client)
		closeUpstreamFn()
		done <- err
	}()
	if _, err := io.Copy(client, upstream); err != nil {
		logCopyError("upstream response", err)
	}
	if err := <-done; err != nil {
		logCopyError("client request", err)
	}
}

func (p proxy) forwardHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL == nil || r.URL.Scheme != "http" {
		http.Error(w, "only HTTP proxy requests are supported", http.StatusBadRequest)
		return
	}
	host := r.URL.Hostname()
	if !p.allowed(host) {
		http.Error(w, "target is not in the registry allowlist", http.StatusForbidden)
		return
	}

	request := r.Clone(r.Context())
	request.RequestURI = ""
	request.Header.Del("Proxy-Connection")
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	defer transport.CloseIdleConnections()
	response, err := transport.RoundTrip(request)
	if err != nil {
		http.Error(w, "allowlisted target is unavailable", http.StatusBadGateway)
		return
	}
	copyHeader(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	if _, err := io.Copy(w, response.Body); err != nil {
		logCopyError("HTTP response", err)
	}
	if err := response.Body.Close(); err != nil {
		log.Printf("egress proxy: close HTTP response body: %v", err)
	}
}

func (p proxy) allowed(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || isIP(host) {
		return false
	}
	for domain := range p.allow {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func parseAllowHosts(raw string) (map[string]struct{}, error) {
	allow := make(map[string]struct{})
	for _, value := range strings.Split(raw, ",") {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
		if host == "" || strings.Contains(host, "/") || isIP(host) {
			return nil, fmt.Errorf("invalid VUELTA_EGRESS_ALLOW_HOSTS entry %q", value)
		}
		allow[host] = struct{}{}
	}
	if len(allow) == 0 {
		return nil, errors.New("VUELTA_EGRESS_ALLOW_HOSTS must contain at least one registry hostname")
	}
	return allow, nil
}

func isIP(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

func splitTarget(raw, defaultPort string) (string, string, error) {
	host, port, err := net.SplitHostPort(raw)
	if err == nil {
		return host, port, nil
	}
	if strings.Contains(raw, ":") {
		return "", "", err
	}
	return raw, defaultPort, nil
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func closeConn(label string, conn net.Conn) {
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("egress proxy: close %s: %v", label, err)
	}
}

func logCopyError(label string, err error) {
	if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		log.Printf("egress proxy: copy %s: %v", label, err)
	}
}
