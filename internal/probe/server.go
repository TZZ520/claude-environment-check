package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"claude-environment-check/internal/model"
	"github.com/gorilla/websocket"
	"github.com/miekg/dns"
	"github.com/oschwald/geoip2-golang"
)

type Config struct {
	Zone          string
	AnswerIPv4    net.IP
	TTL           time.Duration
	Secret        []byte
	GeoIPCityPath string
	GeoIPASNPath  string
}

type Server struct {
	cfg      Config
	mu       sync.RWMutex
	sessions map[string]*session
	geoCity  *geoip2.Reader
	geoASN   *geoip2.Reader
	limiter  map[string]*rateWindow
	upgrader websocket.Upgrader
}

type session struct {
	ID, HTTPIP, DNSIP string
	Created, Expires  time.Time
	TLS               model.TLSInfo
}

type rateWindow struct {
	start time.Time
	count int
}
type contextKey string

const fingerprintKey contextKey = "client-hello"

func New(cfg Config) (*Server, error) {
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	if len(cfg.Secret) < 32 {
		cfg.Secret = make([]byte, 32)
		if _, err := rand.Read(cfg.Secret); err != nil {
			return nil, err
		}
	}
	if cfg.AnswerIPv4 == nil {
		cfg.AnswerIPv4 = net.ParseIP("192.0.2.1")
	}
	cfg.Zone = dns.Fqdn(cfg.Zone)
	s := &Server{cfg: cfg, sessions: map[string]*session{}, limiter: map[string]*rateWindow{}, upgrader: websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }, ReadBufferSize: 1024, WriteBufferSize: 1024}}
	if cfg.GeoIPCityPath != "" {
		db, err := geoip2.Open(cfg.GeoIPCityPath)
		if err != nil {
			return nil, fmt.Errorf("open GeoIP City database: %w", err)
		}
		s.geoCity = db
	}
	if cfg.GeoIPASNPath != "" {
		db, err := geoip2.Open(cfg.GeoIPASNPath)
		if err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("open GeoIP ASN database: %w", err)
		}
		s.geoASN = db
	}
	go s.cleanupLoop()
	return s, nil
}

func (s *Server) Close() error {
	var first error
	if s.geoCity != nil {
		first = s.geoCity.Close()
	}
	if s.geoASN != nil {
		if err := s.geoASN.Close(); first == nil {
			first = err
		}
	}
	return first
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /v1/session", s.createSession)
	mux.HandleFunc("GET /v1/observe", s.observe)
	mux.HandleFunc("GET /v1/ws", s.webSocket)
	mux.HandleFunc("GET /v1/session/{token}/dns", s.dnsObservation)
	return s.securityHeaders(s.rateLimit(mux))
}

func (s *Server) ConnContext(ctx context.Context, conn net.Conn) context.Context {
	if tc, ok := conn.(*tls.Conn); ok {
		if sc, ok := tc.NetConn().(*sniffConn); ok {
			return context.WithValue(ctx, fingerprintKey, sc.fp)
		}
	}
	if sc, ok := conn.(*sniffConn); ok {
		return context.WithValue(ctx, fingerprintKey, sc.fp)
	}
	return ctx
}

func SniffListener(inner net.Listener) net.Listener { return &sniffListener{Listener: inner} }

type sniffListener struct{ net.Listener }

func (l *sniffListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return sniff(c), nil
}

type sniffConn struct {
	net.Conn
	r  io.Reader
	fp helloFingerprint
}

func (c *sniffConn) Read(p []byte) (int, error) { return c.r.Read(p) }

type helloFingerprint struct{ JA3, Hash string }

func sniff(conn net.Conn) net.Conn {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	header := make([]byte, 5)
	n, err := io.ReadFull(conn, header)
	if err != nil {
		_ = conn.SetReadDeadline(time.Time{})
		return &sniffConn{Conn: conn, r: io.MultiReader(bytes.NewReader(header[:n]), conn)}
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if header[0] != 22 || length <= 0 || length > 65535 {
		_ = conn.SetReadDeadline(time.Time{})
		return &sniffConn{Conn: conn, r: io.MultiReader(bytes.NewReader(header), conn)}
	}
	payload := make([]byte, length)
	n, err = io.ReadFull(conn, payload)
	all := append(header, payload[:n]...)
	_ = conn.SetReadDeadline(time.Time{})
	fp := helloFingerprint{}
	if err == nil {
		fp = parseJA3(payload)
	}
	return &sniffConn{Conn: conn, r: io.MultiReader(bytes.NewReader(all), conn), fp: fp}
}

func parseJA3(p []byte) helloFingerprint {
	if len(p) < 42 || p[0] != 1 {
		return helloFingerprint{}
	}
	version := binary.BigEndian.Uint16(p[4:6])
	pos := 38
	if pos >= len(p) {
		return helloFingerprint{}
	}
	sid := int(p[pos])
	pos += 1 + sid
	if pos+2 > len(p) {
		return helloFingerprint{}
	}
	cl := int(binary.BigEndian.Uint16(p[pos : pos+2]))
	pos += 2
	if pos+cl > len(p) || cl%2 != 0 {
		return helloFingerprint{}
	}
	var ciphers []uint16
	for i := 0; i < cl; i += 2 {
		v := binary.BigEndian.Uint16(p[pos+i : pos+i+2])
		if !grease(v) {
			ciphers = append(ciphers, v)
		}
	}
	pos += cl
	if pos >= len(p) {
		return helloFingerprint{}
	}
	comp := int(p[pos])
	pos += 1 + comp
	if pos+2 > len(p) {
		return helloFingerprint{}
	}
	el := int(binary.BigEndian.Uint16(p[pos : pos+2]))
	pos += 2
	if pos+el > len(p) {
		return helloFingerprint{}
	}
	var exts, groups []uint16
	var points []uint8
	end := pos + el
	for pos+4 <= end {
		typ := binary.BigEndian.Uint16(p[pos : pos+2])
		ln := int(binary.BigEndian.Uint16(p[pos+2 : pos+4]))
		pos += 4
		if pos+ln > end {
			break
		}
		data := p[pos : pos+ln]
		pos += ln
		if !grease(typ) {
			exts = append(exts, typ)
		}
		if typ == 10 && len(data) >= 2 {
			gl := int(binary.BigEndian.Uint16(data[:2]))
			for i := 2; i+1 < len(data) && i < 2+gl; i += 2 {
				v := binary.BigEndian.Uint16(data[i : i+2])
				if !grease(v) {
					groups = append(groups, v)
				}
			}
		}
		if typ == 11 && len(data) >= 1 {
			pl := int(data[0])
			for i := 1; i < len(data) && i <= pl; i++ {
				points = append(points, data[i])
			}
		}
	}
	ja3 := fmt.Sprintf("%d,%s,%s,%s,%s", version, join16(ciphers), join16(exts), join16(groups), join8(points))
	sum := md5.Sum([]byte(ja3)) // JA3 specifies MD5; not used for security.
	return helloFingerprint{JA3: ja3, Hash: hex.EncodeToString(sum[:])}
}
func grease(v uint16) bool { return v&0x0f0f == 0x0a0a }
func join16(v []uint16) string {
	a := make([]string, len(v))
	for i, n := range v {
		a[i] = strconv.Itoa(int(n))
	}
	return strings.Join(a, "-")
}
func join8(v []uint8) string {
	a := make([]string, len(v))
	for i, n := range v {
		a[i] = strconv.Itoa(int(n))
	}
	return strings.Join(a, "-")
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	idb := make([]byte, 16)
	_, _ = rand.Read(idb)
	id := base64.RawURLEncoding.EncodeToString(idb)
	token := id + "." + s.sign(id)
	now := time.Now()
	ss := &session{ID: id, Created: now, Expires: now.Add(s.cfg.TTL)}
	s.mu.Lock()
	s.sessions[id] = ss
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "expires_at": ss.Expires.UTC(), "dns_name": id + "." + s.cfg.Zone})
}

func (s *Server) observe(w http.ResponseWriter, r *http.Request) {
	ss, ok := s.authorize(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired session"})
		return
	}
	ip := remoteIP(r.RemoteAddr)
	fp, _ := r.Context().Value(fingerprintKey).(helloFingerprint)
	info := requestTLS(r, fp)
	s.mu.Lock()
	ss.HTTPIP = ip
	ss.TLS = info
	s.mu.Unlock()
	country, cc, asn, org := s.lookup(ip)
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "country": country, "countryCode": cc, "country_code": cc, "asn": asn, "organization": org, "tls": info, "http_version": r.Proto, "server_time": time.Now().UTC()})
}

func (s *Server) webSocket(w http.ResponseWriter, r *http.Request) {
	ss, ok := s.authorize(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired session"})
		return
	}
	c, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()
	ip := remoteIP(r.RemoteAddr)
	s.mu.Lock()
	ss.HTTPIP = ip
	s.mu.Unlock()
	_ = c.WriteJSON(map[string]any{"ip": ip, "session": ss.ID, "server_time": time.Now().UTC()})
}

func (s *Server) dnsObservation(w http.ResponseWriter, r *http.Request) {
	ss, ok := s.sessionForToken(r.PathValue("token"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "invalid or expired session"})
		return
	}
	s.mu.RLock()
	ip := ss.DNSIP
	s.mu.RUnlock()
	country, cc, asn, org := s.lookup(ip)
	writeJSON(w, http.StatusOK, map[string]any{"observed": ip != "", "resolver_ip": ip, "country": country, "country_code": cc, "asn": asn, "organization": org})
}

func (s *Server) DNSHandler() dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if len(r.Question) != 1 || s.cfg.Zone == "" {
			m.Rcode = dns.RcodeRefused
			_ = w.WriteMsg(m)
			return
		}
		q := r.Question[0]
		name := strings.ToLower(dns.Fqdn(q.Name))
		zone := strings.ToLower(s.cfg.Zone)
		if !strings.HasSuffix(name, "."+zone) {
			m.Rcode = dns.RcodeRefused
			_ = w.WriteMsg(m)
			return
		}
		id := strings.TrimSuffix(name, "."+zone)
		if strings.Contains(id, ".") {
			m.Rcode = dns.RcodeNameError
			_ = w.WriteMsg(m)
			return
		}
		s.mu.Lock()
		ss, ok := s.sessions[id]
		if ok && time.Now().Before(ss.Expires) {
			ss.DNSIP = remoteIP(w.RemoteAddr().String())
		}
		s.mu.Unlock()
		if !ok {
			m.Rcode = dns.RcodeNameError
			_ = w.WriteMsg(m)
			return
		}
		if q.Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: s.cfg.AnswerIPv4.To4()}}
		}
		_ = w.WriteMsg(m)
	})
}

func (s *Server) RunDNS(ctx context.Context, addr string) error {
	if s.cfg.Zone == "" {
		return errors.New("DNS zone is required")
	}
	udp := &dns.Server{Addr: addr, Net: "udp", Handler: s.DNSHandler(), UDPSize: 1232}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: s.DNSHandler()}
	errs := make(chan error, 2)
	go func() { errs <- udp.ListenAndServe() }()
	go func() { errs <- tcp.ListenAndServe() }()
	select {
	case <-ctx.Done():
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
		return nil
	case err := <-errs:
		return err
	}
}

func (s *Server) authorize(r *http.Request) (*session, bool) {
	token := r.URL.Query().Get("session")
	if token == "" {
		token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	return s.sessionForToken(token)
}
func (s *Server) sessionForToken(token string) (*session, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || !hmac.Equal([]byte(parts[1]), []byte(s.sign(parts[0]))) {
		return nil, false
	}
	s.mu.RLock()
	ss, ok := s.sessions[parts[0]]
	s.mu.RUnlock()
	return ss, ok && time.Now().Before(ss.Expires)
}
func (s *Server) sign(id string) string {
	h := hmac.New(sha256.New, s.cfg.Secret)
	_, _ = h.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (s *Server) lookup(raw string) (country, cc, asn, org string) {
	if (s.geoCity == nil && s.geoASN == nil) || raw == "" {
		return
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return
	}
	if s.geoCity != nil {
		rec, err := s.geoCity.City(ip)
		if err == nil {
			country = rec.Country.Names["en"]
			cc = rec.Country.IsoCode
		}
	}
	if s.geoASN != nil {
		ar, err := s.geoASN.ASN(ip)
		if err == nil {
			asn = fmt.Sprintf("AS%d", ar.AutonomousSystemNumber)
			org = ar.AutonomousSystemOrganization
		}
	}
	return
}
func requestTLS(r *http.Request, fp helloFingerprint) model.TLSInfo {
	info := model.TLSInfo{JA3: fp.JA3, JA3Hash: fp.Hash}
	if r.TLS != nil {
		info.Version = tlsVersion(r.TLS.Version)
		info.Cipher = tls.CipherSuiteName(r.TLS.CipherSuite)
		info.ALPN = r.TLS.NegotiatedProtocol
	}
	return info
}
func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return fmt.Sprintf("0x%x", v)
}
func remoteIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	return strings.Trim(addr, "[]")
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": model.ToolVersion, "sessions": s.sessionCount()})
}
func (s *Server) sessionCount() int { s.mu.RLock(); defer s.mu.RUnlock(); return len(s.sessions) }
func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for now := range ticker.C {
		s.mu.Lock()
		for id, ss := range s.sessions {
			if now.After(ss.Expires) {
				delete(s.sessions, id)
			}
		}
		for ip, rw := range s.limiter {
			if now.Sub(rw.start) > 2*time.Minute {
				delete(s.limiter, ip)
			}
		}
		s.mu.Unlock()
	}
}

func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := remoteIP(r.RemoteAddr)
		now := time.Now()
		s.mu.Lock()
		rw := s.limiter[ip]
		if rw == nil || now.Sub(rw.start) >= time.Minute {
			rw = &rateWindow{start: now}
			s.limiter[ip] = rw
		}
		rw.count++
		allowed := rw.count <= 60
		s.mu.Unlock()
		if !allowed {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "600")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

var _ = bufio.ErrInvalidUnreadByte
