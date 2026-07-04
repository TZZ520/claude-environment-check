package rules

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
)

type Manifest struct {
	Version              string         `json:"version"`
	UpdatedAt            string         `json:"updated_at"`
	Unofficial           bool           `json:"unofficial"`
	OfficialSources      []string       `json:"official_sources"`
	CompatibilityWeights map[string]int `json:"compatibility_weights"`
	RegionRiskWeights    map[string]int `json:"region_risk_weights"`
	Notes                string         `json:"notes"`
}

func Parse(data []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return m, err
	}
	if m.Version == "" || len(m.OfficialSources) == 0 {
		return m, errors.New("rules manifest is missing required fields")
	}
	return m, nil
}

func Verify(data []byte, signatureBase64, publicKeyBase64 string) (Manifest, error) {
	pub, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return Manifest{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return Manifest{}, err
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
		return Manifest{}, errors.New("rules signature verification failed")
	}
	return Parse(data)
}
