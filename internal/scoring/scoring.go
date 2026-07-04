package scoring

import (
	"strings"

	"claude-environment-check/internal/model"
)

func Apply(r *model.Report) {
	total, known, earned := 0, 0, 0.0
	for _, c := range r.Checks {
		total += c.Weight
		if c.Status == model.Unknown {
			continue
		}
		known += c.Weight
		switch c.Status {
		case model.Pass:
			earned += float64(c.Weight)
		case model.Warn:
			earned += float64(c.Weight) * .55
		}
	}
	if known > 0 {
		r.CompatibilityScore = clamp(int(earned/float64(known)*100 + .5))
	}
	if total > 0 {
		r.Coverage = clamp(known * 100 / total)
	}

	risk := 0
	var direct, effective *model.Route
	for i := range r.Routes {
		route := &r.Routes[i]
		if route.Name == "direct" {
			direct = route
		}
		if route.Name == "environment" || (effective == nil && route.Name == "direct") {
			effective = route
		}
	}
	if effective != nil && effective.CountryCode == "CN" {
		risk += 55
		r.Evidence = append(r.Evidence, model.Evidence{Kind: "observed", Message: "Effective egress geolocates to Mainland China", Impact: 55, Confidence: "high", CheckID: "route.environment"})
	}
	if direct != nil && effective != nil && direct.CountryCode == "CN" && effective.CountryCode != "" && effective.CountryCode != "CN" && direct.PublicIP != effective.PublicIP {
		risk += 25
		r.Evidence = append(r.Evidence, model.Evidence{Kind: "inference", Message: "Direct egress is in Mainland China while the routed egress differs", Impact: 25, Confidence: "medium", CheckID: "route.consistency"})
	}
	for _, c := range r.Checks {
		if c.ID == "anthropic.access" && c.Status == model.Fail {
			msg := strings.ToLower(c.Summary)
			if strings.Contains(msg, "451") || strings.Contains(msg, "region") || strings.Contains(msg, "country") {
				risk += 30
				r.Evidence = append(r.Evidence, model.Evidence{Kind: "observed", Message: "Anthropic endpoint returned an explicit region-related denial", Impact: 30, Confidence: "high", CheckID: c.ID})
			}
		}
		if c.ID == "system.readiness" {
			if signals := evidenceStringSlice(c.Evidence, "mainland_device_signals"); len(signals) > 0 {
				risk += 45
				r.Evidence = append(r.Evidence, model.Evidence{Kind: "observed", Message: "Device-side signals match Mainland China target-risk profile", Impact: 45, Confidence: "high", CheckID: c.ID})
				if r.CompatibilityScore > 59 {
					r.CompatibilityScore = 59
				}
			}
		}
		if c.ID == "egress.ip_type" && c.Status == model.Fail {
			risk += 20
			r.Evidence = append(r.Evidence, model.Evidence{Kind: "inference", Message: "Current egress IP is not confirmed as residential/static", Impact: 20, Confidence: "medium", CheckID: c.ID})
		}
	}

	tz := strings.ToLower(r.Platform.Timezone)
	if strings.Contains(tz, "asia/shanghai") || strings.Contains(tz, "china standard") || strings.Contains(tz, "中国标准") || r.Platform.UTCOffset == "+08:00" {
		risk += 15
		r.Evidence = append(r.Evidence, model.Evidence{Kind: "inference", Message: "System timezone or UTC offset matches Mainland China common setting", Impact: 15, Confidence: "medium", CheckID: "system.timezone"})
	}
	loc := strings.ToLower(strings.Join(append([]string{r.Platform.Locale, r.Platform.SystemLocale}, r.Platform.UserLanguages...), " "))
	if containsMainlandLocale(loc) {
		risk += 20
		r.Evidence = append(r.Evidence, model.Evidence{Kind: "inference", Message: "System language or region contains a Mainland Chinese marker", Impact: 20, Confidence: "high", CheckID: "system.locale"})
	}
	if strings.Contains(strings.ToLower(r.Platform.CodePage), "936") {
		risk += 10
		r.Evidence = append(r.Evidence, model.Evidence{Kind: "inference", Message: "System code page is 936 for Simplified Chinese/GBK", Impact: 10, Confidence: "medium", CheckID: "system.code_page"})
	}

	r.RegionExposureScore = clamp(risk)
	if r.CompatibilityScore < 70 {
		r.Recommendations = append(r.Recommendations, "Review failed endpoint, DNS, certificate, proxy, and device-region checks before using Claude Code.")
	}
	if r.RegionExposureScore >= 35 {
		r.Recommendations = append(r.Recommendations, "Review Anthropic's supported-location policy and use only organization-approved network configurations.")
	}
}

func evidenceStringSlice(e map[string]any, key string) []string {
	if e == nil {
		return nil
	}
	switch v := e[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func containsMainlandLocale(s string) bool {
	markers := []string{"zh-cn", "zh_cn", "zh-hans-cn", "zh_hans_cn", "zh-hans", "zh_hans", "simplified", "chs"}
	for _, marker := range markers {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func clamp(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
