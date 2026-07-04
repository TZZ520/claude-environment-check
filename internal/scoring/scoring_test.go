package scoring

import (
	"claude-environment-check/internal/model"
	"testing"
)

func TestUnknownLowersCoverageNotScore(t *testing.T) {
	r := model.Report{Checks: []model.Check{{Status: model.Pass, Weight: 40}, {Status: model.Unknown, Weight: 60}}}
	Apply(&r)
	if r.CompatibilityScore != 100 || r.Coverage != 40 {
		t.Fatalf("got score=%d coverage=%d", r.CompatibilityScore, r.Coverage)
	}
}

func TestRegionSignals(t *testing.T) {
	r := model.Report{Platform: model.Platform{Timezone: "Asia/Shanghai"}, Routes: []model.Route{{Name: "direct", PublicIP: "1", CountryCode: "CN"}, {Name: "environment", PublicIP: "2", CountryCode: "US"}}}
	Apply(&r)
	if r.RegionExposureScore != 40 {
		t.Fatalf("got %d", r.RegionExposureScore)
	}
}

func TestMainlandDeviceSignalsCapCompatibility(t *testing.T) {
	r := model.Report{
		Platform: model.Platform{UTCOffset: "+08:00", SystemLocale: "zh-CN", CodePage: "Active code page: 936"},
		Checks: []model.Check{
			{ID: "system.readiness", Status: model.Fail, Weight: 15, Evidence: map[string]any{"mainland_device_signals": []string{"zh-CN", "+08:00", "936"}}},
			{ID: "anthropic.access", Status: model.Pass, Weight: 40},
			{ID: "tls.integrity", Status: model.Pass, Weight: 20},
		},
	}
	Apply(&r)
	if r.CompatibilityScore > 59 {
		t.Fatalf("compatibility was not capped: %d", r.CompatibilityScore)
	}
	if r.RegionExposureScore < 90 {
		t.Fatalf("risk too low for Mainland device signals: %d", r.RegionExposureScore)
	}
}
