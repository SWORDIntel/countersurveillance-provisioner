package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
