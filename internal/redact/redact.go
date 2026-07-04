package redact

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(sk-ant-[a-z0-9_-]{8,})`),
	regexp.MustCompile(`(?i)(authorization|x-api-key|proxy-authorization)\s*[:=]\s*[^\s,;]+`),
}

func Proxy(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "<configured>"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func Text(s string) string {
	for _, re := range secretPatterns {
		s = re.ReplaceAllStringFunc(s, func(v string) string {
			if strings.Contains(strings.ToLower(v), "authorization") || strings.Contains(strings.ToLower(v), "api-key") {
				return "<redacted-header>"
			}
			return "<redacted-secret>"
		})
	}
	return s
}

func JSON(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return []byte(Text(string(b))), nil
}
