// Command egress-proxy is the deliberately small, local forward proxy used
// by Vuelta update containers. It only permits configured registry endpoints;
// clients cannot connect to the public network directly because their Docker
// network is internal.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	listenAddress          = ":3128"
	maxConcurrentRequests  = 64
	maxResponseHeaderBytes = 1 << 20
)

var defaultTimeouts = proxyTimeouts{
	dial:           10 * time.Second,
	responseHeader: 30 * time.Second,
	request:        5 * time.Minute,
	tunnelIdle:     60 * time.Second,
	tunnelAbsolute: 10 * time.Minute,
}

func main() {
	allow, err := parseAllowRules(os.Getenv("VUELTA_EGRESS_ALLOW_RULES"))
	if err != nil {
		log.Fatal(err)
	}

	handler := newProxy(allow)
	server := &http.Server{
		Addr:              listenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       defaultTimeouts.request,
		WriteTimeout:      defaultTimeouts.request,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Printf("starting egress proxy on %s for %d allowlisted endpoint(s)", listenAddress, len(allow))
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

type endpoint struct {
	scheme string
	host   string
	port   string
}

type proxyTimeouts struct {
	dial           time.Duration
	responseHeader time.Duration
	request        time.Duration
	tunnelIdle     time.Duration
	tunnelAbsolute time.Duration
}

type ipResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

type proxy struct {
	allow    map[endpoint]struct{}
	resolver ipResolver
	dial     dialContextFunc
	timeouts proxyTimeouts
	slots    chan struct{}
}

func newProxy(allow map[endpoint]struct{}) *proxy {
	dialer := &net.Dialer{Timeout: defaultTimeouts.dial}
	return &proxy{
		allow:    allow,
		resolver: net.DefaultResolver,
		dial:     dialer.DialContext,
		timeouts: defaultTimeouts,
		slots:    make(chan struct{}, maxConcurrentRequests),
	}
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.acquire() {
		http.Error(w, "egress proxy concurrency limit reached", http.StatusServiceUnavailable)
		return
	}
	defer p.release()

	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	p.forwardHTTP(w, r)
}

func (p *proxy) acquire() bool {
	if p.slots == nil {
		return true
	}
	select {
	case p.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (p *proxy) release() {
	if p.slots != nil {
		<-p.slots
	}
}

func (p *proxy) connect(w http.ResponseWriter, r *http.Request) {
	host, port, err := parseTarget(r.Host)
	if err != nil {
		http.Error(w, "invalid CONNECT target", http.StatusBadRequest)
		return
	}
	if !p.allowed("https", host, port) {
		http.Error(w, "target is not in the registry allowlist", http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), p.timeouts.tunnelAbsolute)
	defer cancel()
	upstream, err := p.dialResolved(ctx, host, port)
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

	absoluteDeadline := time.Now().Add(p.timeouts.tunnelAbsolute)
	deadlines := tunnelDeadlines{
		connections: []net.Conn{client, upstream},
		idle:        p.timeouts.tunnelIdle,
		absolute:    absoluteDeadline,
	}
	deadlines.touch()
	clientConn := activityConn{Conn: client, activity: deadlines.touch}
	upstreamConn := activityConn{Conn: upstream, activity: deadlines.touch}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	if err := copyBufferedClientData(buffered, &upstreamConn); err != nil {
		logCopyError("buffered client data", err)
		return
	}

	type copyResult struct {
		label string
		err   error
	}
	results := make(chan copyResult, 2)
	done := make(chan struct{})
	var closeBoth sync.Once
	closeBothFn := func() {
		closeBoth.Do(func() {
			closeConn("client connection", client)
			closeConn("upstream connection", upstream)
		})
	}

	go func() {
		select {
		case <-ctx.Done():
			closeBothFn()
		case <-done:
		}
	}()
	go func() {
		_, copyErr := io.Copy(&upstreamConn, &clientConn)
		results <- copyResult{label: "client request", err: copyErr}
	}()
	go func() {
		_, copyErr := io.Copy(&clientConn, &upstreamConn)
		results <- copyResult{label: "upstream response", err: copyErr}
	}()

	first := <-results
	closeBothFn()
	second := <-results
	close(done)
	logCopyError(first.label, first.err)
	logCopyError(second.label, second.err)
}

func copyBufferedClientData(buffered *bufio.ReadWriter, upstream io.Writer) error {
	if buffered.Reader.Buffered() == 0 {
		return nil
	}
	pending := make([]byte, buffered.Reader.Buffered())
	if _, err := io.ReadFull(buffered.Reader, pending); err != nil {
		return err
	}
	_, err := upstream.Write(pending)
	return err
}

func (p *proxy) forwardHTTP(w http.ResponseWriter, r *http.Request) {
	target, err := httpTarget(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !p.allowed(target.scheme, target.host, target.port) {
		http.Error(w, "target is not in the registry allowlist", http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), p.timeouts.request)
	defer cancel()
	request := r.Clone(ctx)
	request.RequestURI = ""
	request.Close = true
	removeHopByHopHeaders(request.Header)

	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            p.dialAllowedTarget(target),
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      false,
		ResponseHeaderTimeout:  p.timeouts.responseHeader,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
	}
	defer transport.CloseIdleConnections()
	response, err := transport.RoundTrip(request)
	if err != nil {
		http.Error(w, "allowlisted target is unavailable", http.StatusBadGateway)
		return
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			log.Printf("egress proxy: close HTTP response body: %v", err)
		}
	}()
	removeHopByHopHeaders(response.Header)
	copyHeader(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	if _, err := io.Copy(w, response.Body); err != nil {
		logCopyError("HTTP response", err)
	}
}

func (p *proxy) dialAllowedTarget(target endpoint) dialContextFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := parseTarget(address)
		if err != nil || host != target.host || port != target.port {
			return nil, errors.New("transport attempted an unapproved destination")
		}
		return p.dialResolved(ctx, host, port)
	}
}

func (p *proxy) dialResolved(ctx context.Context, host, port string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeouts.dial)
	defer cancel()

	addresses, err := p.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve destination: %w", err)
	}
	addresses, err = validateResolvedAddresses(addresses)
	if err != nil {
		return nil, err
	}

	var dialErrors []error
	for _, address := range addresses {
		conn, dialErr := p.dial(ctx, "tcp", net.JoinHostPort(address.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		dialErrors = append(dialErrors, dialErr)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("dial resolved destination: %w", errors.Join(dialErrors...))
}

func validateResolvedAddresses(addresses []netip.Addr) ([]netip.Addr, error) {
	if len(addresses) == 0 {
		return nil, errors.New("destination resolved to no addresses")
	}

	validated := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if address.Zone() != "" || forbiddenAddress(address) {
			return nil, errors.New("destination resolved to a non-public address")
		}
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		validated = append(validated, address)
	}
	return validated, nil
}

func forbiddenAddress(address netip.Addr) bool {
	return !address.IsValid() || !address.IsGlobalUnicast() || address.IsLoopback() ||
		address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() ||
		address.IsMulticast() || address.IsUnspecified()
}

func (p *proxy) allowed(scheme, host, port string) bool {
	_, ok := p.allow[endpoint{scheme: scheme, host: host, port: port}]
	return ok
}

func parseAllowRules(raw string) (map[endpoint]struct{}, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("VUELTA_EGRESS_ALLOW_RULES must contain at least one registry endpoint")
	}

	allow := make(map[endpoint]struct{})
	for _, value := range strings.Split(raw, ",") {
		rule, err := parseAllowRule(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("invalid VUELTA_EGRESS_ALLOW_RULES entry %q: %w", value, err)
		}
		allow[rule] = struct{}{}
	}
	return allow, nil
}

func parseAllowRule(raw string) (endpoint, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return endpoint{}, err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return endpoint{}, errors.New("scheme must be http or https")
	}
	if parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return endpoint{}, errors.New("rule must contain only scheme, hostname, and port")
	}
	host, err := normalizeHostname(parsed.Hostname())
	if err != nil {
		return endpoint{}, err
	}
	port, err := normalizePort(parsed.Port())
	if err != nil {
		return endpoint{}, err
	}
	return endpoint{scheme: parsed.Scheme, host: host, port: port}, nil
}

func httpTarget(r *http.Request) (endpoint, error) {
	if r.URL == nil || r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.User != nil {
		return endpoint{}, errors.New("only absolute HTTP proxy requests are supported")
	}
	host, err := normalizeHostname(r.URL.Hostname())
	if err != nil {
		return endpoint{}, errors.New("invalid HTTP proxy target")
	}
	port := r.URL.Port()
	if port == "" {
		port = "80"
	}
	port, err = normalizePort(port)
	if err != nil {
		return endpoint{}, errors.New("invalid HTTP proxy target")
	}
	return endpoint{scheme: "http", host: host, port: port}, nil
}

func parseTarget(raw string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(raw)
	if err != nil {
		return "", "", err
	}
	host, err = normalizeHostname(host)
	if err != nil {
		return "", "", err
	}
	port, err = normalizePort(port)
	if err != nil {
		return "", "", err
	}
	return host, port, nil
}

func normalizeHostname(raw string) (string, error) {
	host := strings.TrimSuffix(strings.ToLower(raw), ".")
	if host == "" || len(host) > 253 || isIP(host) {
		return "", errors.New("hostname must be a non-IP DNS name")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("hostname contains an invalid DNS label")
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return "", errors.New("hostname contains an invalid DNS label")
			}
		}
	}
	return host, nil
}

func normalizePort(raw string) (string, error) {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("port must be an integer from 1 to 65535")
	}
	return strconv.Itoa(port), nil
}

func isIP(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

type tunnelDeadlines struct {
	connections []net.Conn
	idle        time.Duration
	absolute    time.Time
	mu          sync.Mutex
}

func (d *tunnelDeadlines) touch() {
	d.mu.Lock()
	defer d.mu.Unlock()
	deadline := time.Now().Add(d.idle)
	if deadline.After(d.absolute) {
		deadline = d.absolute
	}
	for _, conn := range d.connections {
		_ = conn.SetDeadline(deadline)
	}
}

type activityConn struct {
	net.Conn
	activity func()
}

func (c *activityConn) Read(buffer []byte) (int, error) {
	n, err := c.Conn.Read(buffer)
	if n > 0 {
		c.activity()
	}
	return n, err
}

func (c *activityConn) Write(buffer []byte) (int, error) {
	n, err := c.Conn.Write(buffer)
	if n > 0 {
		c.activity()
	}
	return n, err
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func removeHopByHopHeaders(header http.Header) {
	for _, name := range strings.Split(header.Get("Connection"), ",") {
		header.Del(strings.TrimSpace(name))
	}
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		header.Del(name)
	}
}

func closeConn(label string, conn net.Conn) {
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("egress proxy: close %s: %v", label, err)
	}
}

func logCopyError(label string, err error) {
	var networkError net.Error
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &networkError) && networkError.Timeout()) {
		return
	}
	log.Printf("egress proxy: copy %s: %v", label, err)
}
