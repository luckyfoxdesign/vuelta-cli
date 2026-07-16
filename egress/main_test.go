package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var publicTestAddress = netip.MustParseAddr("203.0.113.10")

type staticResolver struct {
	addresses []netip.Addr
	err       error
}

func (r staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.addresses, r.err
}

func TestParseAllowRulesMatchesExactSchemeHostAndPort(t *testing.T) {
	t.Parallel()
	allow, err := parseAllowRules("https://registry.npmjs.org:443, http://pypi.org:80")
	if err != nil {
		t.Fatalf("parseAllowRules: %v", err)
	}
	p := newProxy(allow)
	for _, target := range []endpoint{
		{scheme: "https", host: "registry.npmjs.org", port: "443"},
		{scheme: "http", host: "pypi.org", port: "80"},
	} {
		if !p.allowed(target.scheme, target.host, target.port) {
			t.Fatalf("expected %#v to be allowed", target)
		}
	}
	for _, target := range []endpoint{
		{scheme: "https", host: "cdn.registry.npmjs.org", port: "443"},
		{scheme: "https", host: "registry.npmjs.org", port: "444"},
		{scheme: "http", host: "registry.npmjs.org", port: "443"},
		{scheme: "https", host: "registry.npmjs.org.example", port: "443"},
	} {
		if p.allowed(target.scheme, target.host, target.port) {
			t.Fatalf("expected %#v to be denied", target)
		}
	}
}

func TestParseAllowRulesRejectsInvalidValues(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"",
		"https://registry.npmjs.org",
		"https://127.0.0.1:443",
		"https://registry.npmjs.org:0",
		"https://registry.npmjs.org:65536",
		"https://registry.npmjs.org:443/path",
		"ftp://registry.npmjs.org:21",
		"https://bad_label.example:443",
		"https://registry.npmjs.org:443,",
	} {
		if _, err := parseAllowRules(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}

func TestValidateResolvedAddressesRejectsNonPublicAndMixedAnswers(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		addresses []string
	}{
		{name: "loopback IPv4", addresses: []string{"127.0.0.1"}},
		{name: "loopback IPv6", addresses: []string{"::1"}},
		{name: "private IPv4", addresses: []string{"10.0.0.1"}},
		{name: "private IPv6", addresses: []string{"fd00::1"}},
		{name: "link local IPv4", addresses: []string{"169.254.1.1"}},
		{name: "link local IPv6", addresses: []string{"fe80::1"}},
		{name: "multicast IPv4", addresses: []string{"224.0.0.1"}},
		{name: "multicast IPv6", addresses: []string{"ff02::1"}},
		{name: "unspecified IPv4", addresses: []string{"0.0.0.0"}},
		{name: "unspecified IPv6", addresses: []string{"::"}},
		{name: "mixed public and private", addresses: []string{"203.0.113.10", "192.168.1.1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			addresses := make([]netip.Addr, 0, len(test.addresses))
			for _, raw := range test.addresses {
				addresses = append(addresses, netip.MustParseAddr(raw))
			}
			if _, err := validateResolvedAddresses(addresses); err == nil {
				t.Fatal("expected address set to be rejected")
			}
		})
	}
}

func TestForwardHTTPRejectsPrivateAnswerBeforeDial(t *testing.T) {
	t.Parallel()
	p := testProxy(t, "http://registry.test:80")
	p.resolver = staticResolver{addresses: []netip.Addr{
		publicTestAddress,
		netip.MustParseAddr("192.168.1.20"),
	}}
	var calls atomic.Int32
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("must not dial")
	}
	response := httptest.NewRecorder()
	p.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://registry.test/package", nil))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("response status = %d", response.Code)
	}
	if calls.Load() != 0 {
		t.Fatalf("dial called %d times", calls.Load())
	}
}

func TestDialResolvedUsesTheValidatedAddressAndDeadline(t *testing.T) {
	t.Parallel()
	p := testProxy(t, "https://registry.test:443")
	p.timeouts.dial = 30 * time.Millisecond
	called := make(chan string, 1)
	p.dial = func(ctx context.Context, _, address string) (net.Conn, error) {
		called <- address
		<-ctx.Done()
		return nil, ctx.Err()
	}
	started := time.Now()
	if _, err := p.dialResolved(context.Background(), "registry.test", "443"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dialResolved error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("dial deadline took %v", elapsed)
	}
	if address := <-called; address != "203.0.113.10:443" {
		t.Fatalf("dial address = %q", address)
	}
}

func TestForwardHTTPUsesExactAllowedEndpoint(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/package" {
			t.Errorf("upstream path = %q", r.URL.Path)
		}
		_, _ = io.WriteString(w, "registry response")
	}))
	defer upstream.Close()
	upstreamAddress := mustURLHost(t, upstream.URL)
	_, port, err := net.SplitHostPort(upstreamAddress)
	if err != nil {
		t.Fatal(err)
	}

	p := testProxy(t, "http://registry.test:"+port)
	p.dial = redirectDialer(upstreamAddress)

	request := httptest.NewRequest(http.MethodGet, "http://registry.test:"+port+"/package", nil)
	response := httptest.NewRecorder()
	p.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "registry response" {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}

	wrongPortRequest := httptest.NewRequest(http.MethodGet, "http://registry.test:81/package", nil)
	wrongPortResponse := httptest.NewRecorder()
	p.ServeHTTP(wrongPortResponse, wrongPortRequest)
	if wrongPortResponse.Code != http.StatusForbidden {
		t.Fatalf("wrong-port response = %d", wrongPortResponse.Code)
	}

	subdomainRequest := httptest.NewRequest(http.MethodGet, "http://cdn.registry.test:"+port+"/package", nil)
	subdomainResponse := httptest.NewRecorder()
	p.ServeHTTP(subdomainResponse, subdomainRequest)
	if subdomainResponse.Code != http.StatusForbidden {
		t.Fatalf("subdomain response = %d", subdomainResponse.Code)
	}
}

func TestForwardHTTPResponseHeaderDeadline(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer upstream.Close()
	upstreamAddress := mustURLHost(t, upstream.URL)
	_, port, err := net.SplitHostPort(upstreamAddress)
	if err != nil {
		t.Fatal(err)
	}

	p := testProxy(t, "http://registry.test:"+port)
	p.timeouts.responseHeader = 30 * time.Millisecond
	p.timeouts.request = time.Second
	p.dial = redirectDialer(upstreamAddress)
	request := httptest.NewRequest(http.MethodGet, "http://registry.test:"+port+"/slow", nil)
	response := httptest.NewRecorder()
	started := time.Now()
	p.ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("response status = %d", response.Code)
	}
	if elapsed := time.Since(started); elapsed > 300*time.Millisecond {
		t.Fatalf("response-header deadline took %v", elapsed)
	}
}

func TestProxyConcurrencyCapFailsClosed(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	upstreamAddress := mustURLHost(t, upstream.URL)
	_, port, err := net.SplitHostPort(upstreamAddress)
	if err != nil {
		t.Fatal(err)
	}

	p := testProxy(t, "http://registry.test:"+port)
	p.slots = make(chan struct{}, 1)
	p.dial = redirectDialer(upstreamAddress)
	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		p.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://registry.test:"+port, nil))
		firstDone <- response
	}()
	<-started

	second := httptest.NewRecorder()
	p.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "http://registry.test:"+port, nil))
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("second response status = %d", second.Code)
	}
	close(release)
	if first := <-firstDone; first.Code != http.StatusNoContent {
		t.Fatalf("first response status = %d", first.Code)
	}
}

func TestConnectRejectsUnexpectedPort(t *testing.T) {
	t.Parallel()
	p := testProxy(t, "https://registry.test:443")
	request := httptest.NewRequest(http.MethodConnect, "http://registry.test:444", nil)
	request.Host = "registry.test:444"
	response := httptest.NewRecorder()
	p.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("response status = %d", response.Code)
	}
}

func TestConnectIdleDeadlineClosesBothSides(t *testing.T) {
	t.Parallel()
	listener := mustListen(t)
	defer closeTestResource(t, listener)
	accepted := acceptOne(listener)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	p := testProxy(t, "https://registry.test:"+port)
	p.timeouts.tunnelIdle = 40 * time.Millisecond
	p.timeouts.tunnelAbsolute = time.Second
	p.dial = redirectDialer(listener.Addr().String())
	server := httptest.NewServer(p)
	defer server.Close()
	client := connectThroughProxy(t, server.URL, "registry.test:"+port)
	defer closeTestResource(t, client)
	upstream := <-accepted
	defer closeTestResource(t, upstream)

	if err := client.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = client.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected idle tunnel to close")
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		t.Fatalf("client deadline fired before proxy idle deadline: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 300*time.Millisecond {
		t.Fatalf("idle tunnel took %v to close", elapsed)
	}

	if err := upstream.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := upstream.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected upstream side to close")
	}
}

func TestConnectAbsoluteDeadlineSurvivesActivity(t *testing.T) {
	t.Parallel()
	listener := mustListen(t)
	defer closeTestResource(t, listener)
	accepted := acceptOne(listener)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	p := testProxy(t, "https://registry.test:"+port)
	p.timeouts.tunnelIdle = 80 * time.Millisecond
	p.timeouts.tunnelAbsolute = 120 * time.Millisecond
	p.dial = redirectDialer(listener.Addr().String())
	server := httptest.NewServer(p)
	defer server.Close()
	client := connectThroughProxy(t, server.URL, "registry.test:"+port)
	defer closeTestResource(t, client)
	upstream := <-accepted
	defer closeTestResource(t, upstream)
	go echo(upstream)

	started := time.Now()
	for {
		if err := client.SetDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write([]byte("x")); err != nil {
			break
		}
		if _, err := io.ReadFull(client, make([]byte, 1)); err != nil {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	elapsed := time.Since(started)
	if elapsed < 70*time.Millisecond || elapsed > 500*time.Millisecond {
		t.Fatalf("absolute tunnel lifetime = %v", elapsed)
	}
}

func TestConnectClientDisconnectCleansUp(t *testing.T) {
	t.Parallel()
	listener := mustListen(t)
	defer closeTestResource(t, listener)
	accepted := acceptOne(listener)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	p := testProxy(t, "https://registry.test:"+port)
	p.dial = redirectDialer(listener.Addr().String())
	handlerDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.ServeHTTP(w, r)
		close(handlerDone)
	}))
	defer server.Close()
	client := connectThroughProxy(t, server.URL, "registry.test:"+port)
	upstream := <-accepted
	defer closeTestResource(t, upstream)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("proxy handler did not exit after client disconnect")
	}
	if err := upstream.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := upstream.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected upstream connection to close after client disconnect")
	}
}

func testProxy(t *testing.T, rawRules string) *proxy {
	t.Helper()
	allow, err := parseAllowRules(rawRules)
	if err != nil {
		t.Fatalf("parseAllowRules: %v", err)
	}
	p := newProxy(allow)
	p.resolver = staticResolver{addresses: []netip.Addr{publicTestAddress}}
	p.timeouts = proxyTimeouts{
		dial:           200 * time.Millisecond,
		responseHeader: 200 * time.Millisecond,
		request:        2 * time.Second,
		tunnelIdle:     200 * time.Millisecond,
		tunnelAbsolute: 2 * time.Second,
	}
	return p
}

func redirectDialer(address string) dialContextFunc {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
}

func mustURLHost(t *testing.T, rawURL string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Host
}

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func acceptOne(listener net.Listener) <-chan net.Conn {
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	return accepted
}

func connectThroughProxy(t *testing.T, proxyURL, target string) net.Conn {
	t.Helper()
	client, err := net.Dial("tcp", mustURLHost(t, proxyURL))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		closeTestResource(t, client)
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		closeTestResource(t, client)
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	status, err := reader.ReadString('\n')
	if err != nil {
		closeTestResource(t, client)
		t.Fatal(err)
	}
	if !strings.Contains(status, " 200 ") {
		closeTestResource(t, client)
		t.Fatalf("CONNECT status = %q", strings.TrimSpace(status))
	}
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			closeTestResource(t, client)
			t.Fatal(readErr)
		}
		if line == "\r\n" {
			break
		}
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		closeTestResource(t, client)
		t.Fatal(err)
	}
	return client
}

func closeTestResource(t *testing.T, resource io.Closer) {
	t.Helper()
	if err := resource.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close test resource: %v", err)
	}
}

func echo(conn net.Conn) {
	buffer := make([]byte, 1)
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			if _, writeErr := conn.Write(buffer[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
