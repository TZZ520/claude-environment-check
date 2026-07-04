package redact

import (
	"strings"
	"testing"
)

func TestProxyCredentialsRemoved(t *testing.T) {
	got := Proxy("http://alice:secret@127.0.0.1:7890/path?q=1")
	if strings.Contains(got, "alice") || strings.Contains(got, "secret") || strings.Contains(got, "q=1") {
		t.Fatalf("not redacted: %s", got)
	}
}
func TestSecretsRemovedFromText(t *testing.T) {
	got := Text("Authorization: Bearer abc x-api-key=secret sk-ant-api03-example123")
	for _, v := range []string{"Bearer abc", "=secret", "sk-ant-api03-example123"} {
		if strings.Contains(got, v) {
			t.Fatalf("secret remained: %s", got)
		}
	}
}
