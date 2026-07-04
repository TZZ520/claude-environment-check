package probe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionAndObserve(t *testing.T) {
	s, err := New(Config{Zone: "dns.test.", TTL: time.Minute, Secret: []byte("01234567890123456789012345678901")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/v1/session", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&created)
	_ = resp.Body.Close()
	if created.Token == "" {
		t.Fatal("missing token")
	}
	resp, err = http.Get(ts.URL + "/v1/observe?session=" + created.Token)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestInvalidSessionRejected(t *testing.T) {
	s, _ := New(Config{Secret: []byte("01234567890123456789012345678901")})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/v1/observe?session=bad.token", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rr.Code)
	}
}

func TestJA3ParserRejectsGarbage(t *testing.T) {
	if fp := parseJA3([]byte("not tls")); fp.Hash != "" {
		t.Fatal("unexpected fingerprint")
	}
}

func TestCORSPreflight(t *testing.T) {
	s, err := New(Config{Zone: "dns.test.", TTL: time.Minute, Secret: []byte("01234567890123456789012345678901")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/v1/observe", nil)
	req.Header.Set("Origin", "https://example.test")
	req.Header.Set("Access-Control-Request-Method", "GET")
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("got %d", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("missing CORS allow origin")
	}
	if rr.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Fatalf("missing CORS methods")
	}
}
