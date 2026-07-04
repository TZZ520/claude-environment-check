package rules

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"version":"v1","updated_at":"2026-01-01T00:00:00Z","unofficial":true,"official_sources":["https://example.com"]}`)
	sig := ed25519.Sign(priv, data)
	m, err := Verify(data, base64.StdEncoding.EncodeToString(sig), base64.StdEncoding.EncodeToString(pub))
	if err != nil || m.Version != "v1" {
		t.Fatalf("verify: %v %#v", err, m)
	}
}

func TestRejectTampering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := []byte(`{"version":"v1","official_sources":["https://example.com"]}`)
	sig := ed25519.Sign(priv, data)
	data[12] = '2'
	if _, err := Verify(data, base64.StdEncoding.EncodeToString(sig), base64.StdEncoding.EncodeToString(pub)); err == nil {
		t.Fatal("tampered manifest accepted")
	}
}
