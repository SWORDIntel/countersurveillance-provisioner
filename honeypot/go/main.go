package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	RetroServer   = "Apache/1.3.27 (Unix) mod_ssl/2.8.12 OpenSSL/0.9.6b"
	RetroDate     = "Fri, 24 Oct 2003 14:02:11 GMT"
	RetroModified = "Mon, 12 Apr 1999 08:30:00 GMT"

	DefaultLogPath     = "/var/log/chronosink/probes.jsonl"
	FallbackLogPath    = "/tmp/chronosink/probes.jsonl"
	QihseEventsFile    = "/opt/qihse-data/events/countersurveillance_alerts.jsonl"
	CitadelDefaultHost = "192.168.1.91"
	CitadelUDPPort     = 17872

	MaxConcurrentConnections = 256
	MaxProbePayloadBytes     = 4096
	ACMEChallengePrefix      = "/.well-known/acme-challenge/"
)

var (
	defaultHTTPPorts = []int{9080, 8080, 8443, 80}
	defaultRawPorts  = []int{9445, 23, 445, 5555, 8291}
	httpPorts        = append([]int(nil), defaultHTTPPorts...)
	rawPorts         = append([]int(nil), defaultRawPorts...)
	gzipBomb         []byte
	hostname        string
	deceptionMode   = "bounded" // "bounded" (default, harmless) or "bomb" (decompression bomb)
	httpConnLimiter = make(chan struct{}, 128)
	rawConnLimiter  = make(chan struct{}, 128)
	telemetryChan   = make(chan []byte, 1024)
)

// EvidenceRecord represents the standardized investigation-grade evidence schema
type EvidenceRecord struct {
	SchemaVersion   int                    `json:"schema_version"`
	EventID         string                 `json:"event_id"`
	SensorID        string                 `json:"sensor_id"`
	TimestampUTC    string                 `json:"timestamp_utc"`
	SourceIP        string                 `json:"source_ip"`
	SourcePort      int                    `json:"source_port"`
	DestinationPort int                    `json:"destination_port"`
	Protocol        string                 `json:"protocol"`
	Persona         string                 `json:"persona"`
	Action          string                 `json:"action"`
	Classification  string                 `json:"classification"`
	Confidence      float64                `json:"confidence"`
	PayloadSHA256   string                 `json:"payload_sha256"`
	RuleID          string                 `json:"rule_id"`
	ConnectionID    string                 `json:"connection_id"`
	Details         map[string]interface{} `json:"details,omitempty"`
}

type QihseAlert struct {
	Timestamp float64 `json:"timestamp"`
	ISOTime   string  `json:"iso_time"`
	Node      string  `json:"node"`
	EventType string  `json:"event_type"`
	Category  string  `json:"category"`
	Target    string  `json:"target"`
	Port      int     `json:"port"`
	Process   string  `json:"process"`
	PID       int     `json:"pid"`
	Count     int     `json:"count"`
	Action    string  `json:"action"`
}

type CitadelAlertMsg struct {
	Node   string `json:"node"`
	Target string `json:"target"`
	Port   int    `json:"port"`
	Comm   string `json:"comm"`
	PID    int    `json:"pid"`
}

func randomHex(bytesLen int) string {
	b := make([]byte, bytesLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func isTruthyEnv(key string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func isFalsyEnv(key string) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(v))
	return s == "0" || s == "false" || s == "no" || s == "off"
}

func parsePortsEnv(envKey string, defaults []int) []int {
	raw, ok := os.LookupEnv(envKey)
	if !ok {
		return append([]int(nil), defaults...)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.EqualFold(trimmed, "none") {
		return nil
	}
	seen := make(map[int]struct{})
	var ports []int
	for _, part := range strings.Split(trimmed, ",") {
		pStr := strings.TrimSpace(part)
		if pStr == "" {
			continue
		}
		p, err := strconv.Atoi(pStr)
		if err != nil || p < 1 || p > 65535 {
			continue
		}
		if _, dup := seen[p]; !dup {
			seen[p] = struct{}{}
			ports = append(ports, p)
		}
	}
	return ports
}

func filterPort(ports []int, exclude int) []int {
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p != exclude {
			out = append(out, p)
		}
	}
	return out
}

func resolvePortsFromEnv() ([]int, []int) {
	hp := parsePortsEnv("CHRONOSINK_HTTP_PORTS", defaultHTTPPorts)
	if isTruthyEnv("CHRONOSINK_DISABLE_PORT_80") || isFalsyEnv("CHRONOSINK_ALLOW_PORT_80") {
		hp = filterPort(hp, 80)
	}
	rp := parsePortsEnv("CHRONOSINK_RAW_PORTS", defaultRawPorts)
	return hp, rp
}

func init() {
	var err error
	hostname, err = os.Hostname()
	if err != nil {
		hostname = "unknown-node"
	}

	modeEnv := strings.ToLower(os.Getenv("DECEPTION_MODE"))
	if modeEnv == "bomb" || modeEnv == "gzip" {
		deceptionMode = "bomb"
	}

	httpPorts, rawPorts = resolvePortsFromEnv()

	// Pre-generate 100 MB of compressed null bytes (~100 KB on wire, 100 MB in memory)
	buf := new(bytes.Buffer)
	gz, _ := gzip.NewWriterLevel(buf, gzip.BestCompression)
	chunk := make([]byte, 1024*1024) // 1 MB
	for i := 0; i < 100; i++ {
		_, _ = gz.Write(chunk)
	}
	_ = gz.Close()
	gzipBomb = buf.Bytes()
}

func dispatchTelemetry(srcIP string, srcPort int, dstPort int, protocol string, ruleID string, rawPayload []byte, details map[string]interface{}) {
	now := time.Now().UTC()
	unixNow := float64(now.UnixNano()) / 1e9
	isoNow := now.Format(time.RFC3339)

	hash := sha256.Sum256(rawPayload)
	payloadHash := hex.EncodeToString(hash[:])
	connID := randomHex(8)
	eventID := randomHex(12)

	evidence := EvidenceRecord{
		SchemaVersion:   1,
		EventID:         eventID,
		SensorID:        hostname,
		TimestampUTC:    isoNow,
		SourceIP:        srcIP,
		SourcePort:      srcPort,
		DestinationPort: dstPort,
		Protocol:        protocol,
		Persona:         "apache-1.3.27-2003",
		Action:          "deceive",
		Classification:  "scanner-probe",
		Confidence:      0.90,
		PayloadSHA256:   payloadHash,
		RuleID:          ruleID,
		ConnectionID:    connID,
		Details:         details,
	}

	// 1. Local Structured JSONL log
	logPath := DefaultLogPath
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		logPath = FallbackLogPath
		_ = os.MkdirAll(filepath.Dir(logPath), 0755)
	}

	if b, err := json.Marshal(evidence); err == nil {
		if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			_, _ = f.Write(append(b, '\n'))
			_ = f.Close()
		}
	}

	// 2. Direct Append to QIHSE events file
	qEventsFile := os.Getenv("QIHSE_EVENTS_FILE")
	if qEventsFile == "" {
		qEventsFile = QihseEventsFile
	}

	qihseAlert := QihseAlert{
		Timestamp: unixNow,
		ISOTime:   isoNow,
		Node:      hostname,
		EventType: "countersurveillance.blocked",
		Category:  "SECURITY_SURVEILLANCE",
		Target:    srcIP,
		Port:      dstPort,
		Process:   "chronosink-go",
		PID:       os.Getpid(),
		Count:     1,
		Action:    "MITIGATED",
	}

	if alertBytes, err := json.Marshal(qihseAlert); err == nil {
		if f, err := os.OpenFile(qEventsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666); err == nil {
			_, _ = f.Write(append(alertBytes, '\n'))
			_ = f.Close()
		}
	}

	// 3. UDP Datagram to Citadel Shield (host:17872) via background worker
	citMsg := CitadelAlertMsg{
		Node:   hostname,
		Target: srcIP,
		Port:   dstPort,
		Comm:   "chronosink-go",
		PID:    os.Getpid(),
	}
	if b, err := json.Marshal(citMsg); err == nil {
		select {
		case telemetryChan <- b:
		default:
		}
	}
}

func isValidACMEToken(token string) bool {
	if token == "" || len(token) > 256 {
		return false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func appendSplitPaths(dirs []string, raw string, appendWellKnown bool) []string {
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ':' }) {
		p := filepath.Clean(strings.TrimSpace(part))
		if p == "" || p == "." {
			continue
		}
		if appendWellKnown {
			dirs = append(dirs, filepath.Join(p, ".well-known", "acme-challenge"))
		}
		dirs = append(dirs, p)
	}
	return dirs
}

func acmeChallengeDirs() []string {
	var dirs []string
	for _, key := range []string{"CHRONOSINK_ACME_DIR", "ACME_CHALLENGE_DIR"} {
		if v := os.Getenv(key); v != "" {
			dirs = appendSplitPaths(dirs, v, false)
		}
	}
	for _, key := range []string{"CHRONOSINK_ACME_WEBROOT", "ACME_WEBROOT"} {
		if v := os.Getenv(key); v != "" {
			dirs = appendSplitPaths(dirs, v, true)
		}
	}
	dirs = append(dirs,
		"/var/www/acme-challenge/.well-known/acme-challenge",
		"/var/www/html/.well-known/acme-challenge",
		"/var/www/letsencrypt/.well-known/acme-challenge",
		"/var/www/certbot/.well-known/acme-challenge",
		"/var/lib/letsencrypt/http_challenges",
		"/run/acme/.well-known/acme-challenge",
		"/run/acme",
	)
	return dirs
}

func readACMEChallenge(token string) ([]byte, bool) {
	for _, dir := range acmeChallengeDirs() {
		baseAbs, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		candidate := filepath.Join(baseAbs, token)
		candAbs, err := filepath.Abs(candidate)
		if err != nil || filepath.Dir(candAbs) != baseAbs {
			continue
		}
		info, err := os.Stat(candAbs)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
			continue
		}
		data, err := os.ReadFile(candAbs)
		if err == nil {
			return data, true
		}
	}
	return nil, false
}

func proxyACMEChallenge(w http.ResponseWriter, r *http.Request, proxyBase, token string) bool {
	base, err := url.Parse(strings.TrimSpace(proxyBase))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return false
	}
	target := base.ResolveReference(&url.URL{Path: ACMEChallengePrefix + token})
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), nil)
	if err != nil {
		return false
	}
	if r.Host != "" {
		req.Host = r.Host
	}
	client := &http.Client{
		Timeout: 4 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "close")
	w.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead {
		_, _ = io.Copy(w, io.LimitReader(resp.Body, 16384))
	}
	return true
}

func serveACMEChallenge(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, ACMEChallengePrefix) {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.Header().Set("Connection", "close")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}

	token := strings.TrimPrefix(r.URL.Path, ACMEChallengePrefix)
	if !isValidACMEToken(token) {
		w.Header().Set("Connection", "close")
		http.NotFound(w, r)
		return true
	}

	if data, ok := readACMEChallenge(token); ok {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(data)
		}
		return true
	}

	for _, key := range []string{"CHRONOSINK_ACME_PROXY", "ACME_PROXY_URL"} {
		if proxyBase := strings.TrimSpace(os.Getenv(key)); proxyBase != "" {
			if proxyACMEChallenge(w, r, proxyBase, token) {
				return true
			}
		}
	}

	w.Header().Set("Connection", "close")
	http.NotFound(w, r)
	return true
}

func handleHTTP(w http.ResponseWriter, r *http.Request, bindPort int) {
	if serveACMEChallenge(w, r) {
		return
	}
	// Concurrency bounding
	select {
	case httpConnLimiter <- struct{}{}:
		defer func() { <-httpConnLimiter }()
	default:
		// Saturated; drop connection to prevent denial of service with retro Apache 503
		w.Header().Set("Date", RetroDate)
		w.Header().Set("Server", RetroServer)
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<html><head><title>503 Service Unavailable</title></head><body><h1>Service Temporarily Unavailable</h1></body></html>\r\n")
		return
	}

	clientIP, portStr, _ := net.SplitHostPort(r.RemoteAddr)
	clientPort, _ := strconv.Atoi(portStr)

	// Bounded header reading
	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = v[0]
		}
	}

	// Bounded body snippet reading
	bodySnippet, _ := io.ReadAll(io.LimitReader(r.Body, MaxProbePayloadBytes))
	_ = r.Body.Close()

	details := map[string]interface{}{
		"method":          r.Method,
		"uri":             r.RequestURI,
		"user_agent":      r.UserAgent(),
		"host":            r.Host,
		"accept_encoding": headers["accept-encoding"],
	}

	dispatchTelemetry(clientIP, clientPort, bindPort, "tcp", "decoy-http", bodySnippet, details)

	// Artificial Temporal Jitter (300ms - 1500ms)
	time.Sleep(time.Duration(300+mrand.Intn(1200)) * time.Millisecond)

	// Retro Temporal Headers
	w.Header().Set("Date", RetroDate)
	w.Header().Set("Server", RetroServer)
	w.Header().Set("Last-Modified", RetroModified)
	w.Header().Set("Connection", "close")

	acceptEnc := headers["accept-encoding"]
	if deceptionMode == "bomb" && strings.Contains(acceptEnc, "gzip") {
		// Opt-in Decompression Bomb
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(gzipBomb)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzipBomb)
	} else {
		// Default: Bounded Harmless Deception Body
		body := "<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>Directory traversal rejected.</p></body></html>\r\n"
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, body)
	}
}

func handleRawTCP(conn net.Conn, bindPort int) {
	defer conn.Close()

	select {
	case rawConnLimiter <- struct{}{}:
		defer func() { <-rawConnLimiter }()
	default:
		return
	}

	clientIP, portStr, _ := net.SplitHostPort(conn.RemoteAddr().String())
	clientPort, _ := strconv.Atoi(portStr)

	// Bounded payload reading
	_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	buf := make([]byte, MaxProbePayloadBytes)
	n, err := conn.Read(buf)
	if n == 0 || err != nil {
		return // If client disconnected or sent FIN/RST, exit immediately; do NOT sleep 15s against empty sockets!
	}
	payload := buf[:n]

	details := map[string]interface{}{
		"bytes_received": n,
		"hex_preview":    hex.EncodeToString(payload[:min(n, 128)]),
	}

	dispatchTelemetry(clientIP, clientPort, bindPort, "tcp", "decoy-raw-tarpit", payload, details)

	// Tarpit socket: drip a single newline every 3 seconds up to 15s to keep client pinned
	for i := 0; i < 5; i++ {
		_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		if _, err := conn.Write([]byte("\n")); err != nil {
			return
		}
		time.Sleep(3 * time.Second)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	fmt.Printf("[*] Starting ChronoSink Go Deception Engine on node: %s (Mode: %s)\n", hostname, deceptionMode)
	fmt.Printf("[*] Concurrency Ceiling: %d connections | Max Payload Capture: %d bytes\n", MaxConcurrentConnections, MaxProbePayloadBytes)

	// Single persistent UDP connection to Citadel Shield worker
	citadelHost := os.Getenv("CITADEL_HOST")
	if citadelHost == "" {
		citadelHost = CitadelDefaultHost
	}
	citadelAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(citadelHost, strconv.Itoa(CitadelUDPPort)))
	var udpConn *net.UDPConn
	if err != nil {
		fmt.Printf("[-] Could not resolve Citadel UDP address %s:%d: %v\n", citadelHost, CitadelUDPPort, err)
	} else {
		udpConn, err = net.DialUDP("udp", nil, citadelAddr)
		if err != nil {
			fmt.Printf("[-] Could not connect to Citadel UDP %s:%d: %v\n", citadelHost, CitadelUDPPort, err)
		} else {
			fmt.Printf("[+] Citadel UDP telemetry active -> %s:%d\n", citadelHost, CitadelUDPPort)
		}
	}

	go func() {
		for data := range telemetryChan {
			if udpConn != nil {
				_ = udpConn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
				_, _ = udpConn.Write(data)
			}
		}
	}()

	var listeners []io.Closer

	// Start HTTP listeners
	for _, port := range httpPorts {
		p := port
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			handleHTTP(w, r, p)
		})
		srv := &http.Server{
			Addr:              fmt.Sprintf("0.0.0.0:%d", p),
			Handler:           mux,
			ReadHeaderTimeout: 3 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      8 * time.Second,
			MaxHeaderBytes:    8192,
		}

		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			fmt.Printf("[-] Could not bind HTTP port %d: %v\n", p, err)
			continue
		}
		listeners = append(listeners, ln)
		fmt.Printf("[+] HTTP Deception listener active on 0.0.0.0:%d\n", p)

		go func() {
			_ = srv.Serve(ln)
		}()
	}

	// Start Raw TCP listeners
	for _, port := range rawPorts {
		p := port
		ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", p))
		if err != nil {
			fmt.Printf("[-] Could not bind RAW port %d: %v\n", p, err)
			continue
		}
		listeners = append(listeners, ln)
		fmt.Printf("[+] Raw TCP Tarpit listener active on 0.0.0.0:%d\n", p)

		go func(listener net.Listener, bindPort int) {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				go handleRawTCP(conn, bindPort)
			}
		}(ln, p)
	}

	if len(listeners) == 0 {
		fmt.Fprintln(os.Stderr, "[!] No listeners could be bound. Exiting.")
		if udpConn != nil {
			_ = udpConn.Close()
		}
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n[*] Shutting down ChronoSink...")
	if udpConn != nil {
		_ = udpConn.Close()
	}
	for _, l := range listeners {
		_ = l.Close()
	}
	fmt.Println("[*] ChronoSink terminated cleanly.")
}
