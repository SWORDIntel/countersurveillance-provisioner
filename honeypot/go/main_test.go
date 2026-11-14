package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestHTTPConnLimiterFull(t *testing.T) {
	// Fill httpConnLimiter
	for i := 0; i < 128; i++ {
		httpConnLimiter <- struct{}{}
	}
	defer func() {
		for i := 0; i < 128; i++ {
			<-httpConnLimiter
		}
	}()

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	rec := httptest.NewRecorder()
	handleHTTP(rec, req, 8080)

	res := rec.Result()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Expected status 503, got %d", res.StatusCode)
	}
	if res.Header.Get("Server") != RetroServer {
		t.Fatalf("Expected Server %s, got %s", RetroServer, res.Header.Get("Server"))
	}
	if res.Header.Get("Date") != RetroDate {
		t.Fatalf("Expected Date %s, got %s", RetroDate, res.Header.Get("Date"))
	}
	if res.Header.Get("Connection") != "close" {
		t.Fatalf("Expected Connection close, got %s", res.Header.Get("Connection"))
	}
	body, _ := io.ReadAll(res.Body)
	expectedBody := "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<html><head><title>503 Service Unavailable</title></head><body><h1>Service Temporarily Unavailable</h1></body></html>\r\n"
	if string(body) != expectedBody {
		t.Fatalf("Body mismatch:\nGot: %q\nWant: %q", string(body), expectedBody)
	}
}

func TestDecoupledLimiters(t *testing.T) {
	// Fill rawConnLimiter completely
	for i := 0; i < 128; i++ {
		rawConnLimiter <- struct{}{}
	}
	defer func() {
		for i := 0; i < 128; i++ {
			<-rawConnLimiter
		}
	}()

	// HTTP request must not be blocked or rejected as 503
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	rec := httptest.NewRecorder()
	handleHTTP(rec, req, 8080)

	res := rec.Result()
	if res.StatusCode == http.StatusServiceUnavailable {
		t.Fatalf("HTTP request rejected as 503 even though httpConnLimiter had capacity")
	}
}

func TestHandleRawTCPEOF(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	clientConn.Close() // Disconnect immediately

	start := time.Now()
	handleRawTCP(serverConn, 9445)
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Fatalf("handleRawTCP took %v on closed connection, expected immediate return < 1s", elapsed)
	}
}

func TestHandleRawTCPDrip(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		handleRawTCP(serverConn, 9445)
		close(done)
	}()

	// Send probe payload from client
	_, err := clientConn.Write([]byte("GET /probe HTTP/1.0\r\n\r\n"))
	if err != nil {
		t.Fatalf("Failed to write probe: %v", err)
	}

	// Read first drip byte
	buf := make([]byte, 1)
	_ = clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil || n != 1 || buf[0] != '\n' {
		t.Fatalf("Expected immediate drip newline byte, got %q, err: %v", buf[:n], err)
	}

	// Close client connection and verify server detects disconnect and exits before 15s
	clientConn.Close()
	select {
	case <-done:
		// Successfully exited early upon client disconnect
	case <-time.After(5 * time.Second):
		t.Fatalf("handleRawTCP failed to exit within 5s after client closed connection")
	}
}

func TestTelemetryWorkerChannel(t *testing.T) {
	initialLen := len(telemetryChan)
	dispatchTelemetry("127.0.0.1", 12345, 80, "tcp", "test-rule", []byte("probe"), nil)

	if len(telemetryChan) != initialLen+1 {
		t.Fatalf("Expected telemetryChan length to increment by 1, got %d", len(telemetryChan))
	}
	msg := <-telemetryChan
	if !strings.Contains(string(msg), "chronosink-go") {
		t.Fatalf("Telemetry missing expected process identifier: %s", string(msg))
	}
}

func TestResolvePortsFromEnv(t *testing.T) {
	t.Setenv("CHRONOSINK_HTTP_PORTS", "")
	t.Setenv("CHRONOSINK_DISABLE_PORT_80", "")
	t.Setenv("CHRONOSINK_ALLOW_PORT_80", "")
	os.Unsetenv("CHRONOSINK_HTTP_PORTS")
	os.Unsetenv("CHRONOSINK_DISABLE_PORT_80")
	os.Unsetenv("CHRONOSINK_ALLOW_PORT_80")

	hp, _ := resolvePortsFromEnv()
	if !reflect.DeepEqual(hp, []int{9080, 8080, 8443, 80}) {
		t.Fatalf("Expected default HTTP ports, got %v", hp)
	}

	t.Setenv("CHRONOSINK_DISABLE_PORT_80", "1")
	hp, _ = resolvePortsFromEnv()
	if !reflect.DeepEqual(hp, []int{9080, 8080, 8443}) {
		t.Fatalf("Expected port 80 filtered out, got %v", hp)
	}

	t.Setenv("CHRONOSINK_DISABLE_PORT_80", "0")
	t.Setenv("CHRONOSINK_HTTP_PORTS", "9080,8080,8443")
	hp, _ = resolvePortsFromEnv()
	if !reflect.DeepEqual(hp, []int{9080, 8080, 8443}) {
		t.Fatalf("Expected custom HTTP ports without 80, got %v", hp)
	}
}

func TestACMEChallengeServedFromWebroot(t *testing.T) {
	webroot := t.TempDir()
	chalDir := filepath.Join(webroot, ".well-known", "acme-challenge")
	if err := os.MkdirAll(chalDir, 0755); err != nil {
		t.Fatal(err)
	}
	token := "token-123_ABC"
	keyAuth := "token-123_ABC.thumbprint456"
	if err := os.WriteFile(filepath.Join(chalDir, token), []byte(keyAuth), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CHRONOSINK_ACME_WEBROOT", webroot)
	req := httptest.NewRequest("GET", "http://swordintelligence.airforce/.well-known/acme-challenge/"+token, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	start := time.Now()
	handleHTTP(rec, req, 80)

	if time.Since(start) > 200*time.Millisecond {
		t.Fatalf("ACME challenge unexpectedly incurred tarpit delay")
	}
	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for ACME challenge, got %d", res.StatusCode)
	}
	if res.Header.Get("Server") == RetroServer {
		t.Fatalf("ACME response should not include retro Apache Server header")
	}
	if res.Header.Get("Content-Encoding") != "" {
		t.Fatalf("ACME response should not be compressed, got %q", res.Header.Get("Content-Encoding"))
	}
	body, _ := io.ReadAll(res.Body)
	if string(body) != keyAuth {
		t.Fatalf("ACME body mismatch: got %q want %q", string(body), keyAuth)
	}
}

func TestACMEChallengeMissingAndTraversal(t *testing.T) {
	t.Setenv("CHRONOSINK_ACME_WEBROOT", t.TempDir())
	for _, path := range []string{
		"/.well-known/acme-challenge/nonexistent-token",
		"/.well-known/acme-challenge/../../etc/passwd",
		"/.well-known/acme-challenge/",
	} {
		req := httptest.NewRequest("GET", "http://example.com"+path, nil)
		rec := httptest.NewRecorder()
		handleHTTP(rec, req, 80)
		res := rec.Result()
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("Path %q: expected 404, got %d", path, res.StatusCode)
		}
		if res.Header.Get("Server") == RetroServer {
			t.Fatalf("Path %q: ACME 404 should not emit retro Apache headers", path)
		}
	}
}

func TestACMEChallengeProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/acme-challenge/proxy-tok" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "proxy-tok.key")
	}))
	defer backend.Close()

	t.Setenv("CHRONOSINK_ACME_WEBROOT", t.TempDir())
	t.Setenv("CHRONOSINK_ACME_PROXY", backend.URL)

	req := httptest.NewRequest("GET", "http://swordintelligence.airforce/.well-known/acme-challenge/proxy-tok", nil)
	rec := httptest.NewRecorder()
	handleHTTP(rec, req, 80)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 from ACME proxy, got %d", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	if string(body) != "proxy-tok.key" {
		t.Fatalf("Expected proxied ACME payload, got %q", string(body))
	}
}
