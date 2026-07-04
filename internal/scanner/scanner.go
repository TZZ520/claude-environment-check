package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"claude-environment-check/internal/model"
	"claude-environment-check/internal/redact"
	"claude-environment-check/internal/scoring"
	"github.com/gorilla/websocket"
)

type Scanner struct{ now func() time.Time }

type localeProfile struct {
	Culture       string   `json:"culture"`
	UICulture     string   `json:"ui_culture"`
	SystemLocale  string   `json:"system_locale"`
	UserLanguages []string `json:"user_languages"`
	Decimal       string   `json:"decimal"`
	List          string   `json:"list"`
	Date          string   `json:"date"`
	Time          string   `json:"time"`
	CodePage      string   `json:"code_page"`
}

func New() *Scanner { return &Scanner{now: time.Now} }

func (s *Scanner) Scan(ctx context.Context, opts model.ScanOptions) model.Report {
	started := s.now()
	if opts.TimeoutSeconds <= 0 {
		opts.TimeoutSeconds = 8
	}
	if opts.Profile == "" {
		opts.Profile = "all"
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(opts.TimeoutSeconds*3)*time.Second)
	defer cancel()
	r := model.Report{
		SchemaVersion: model.SchemaVersion, ToolVersion: model.ToolVersion, RulesVersion: model.RulesVersion,
		GeneratedAt: started.UTC(), Platform: collectPlatform(),
		Routes: []model.Route{}, Checks: []model.Check{}, Evidence: []model.Evidence{}, Recommendations: []string{},
		PrivacyRedactions: []string{"proxy credentials", "Authorization", "x-api-key", "API keys and tokens"},
		Metadata:          map[string]any{"unofficial": true, "disclaimer": "Heuristic diagnostics; not Anthropic's private detection logic."},
	}

	type routeResult struct {
		route    model.Route
		endpoint model.Check
		tlsCheck model.Check
		wsCheck  model.Check
	}
	routes := routeSpecs(opts.Profile)
	results := make(chan routeResult, len(routes))
	var wg sync.WaitGroup
	for _, spec := range routes {
		wg.Add(1)
		go func(spec routeSpec) {
			defer wg.Done()
			client := makeClient(spec, time.Duration(opts.TimeoutSeconds)*time.Second)
			route := inspectRoute(ctx, client, spec, opts)
			endpoint, tlsCheck := inspectAnthropic(ctx, client, route.Name)
			wsCheck := inspectWebSocket(ctx, spec, time.Duration(opts.TimeoutSeconds)*time.Second)
			if v, ok := wsCheck.Evidence["observed_ip"].(string); ok {
				route.WebSocketIP = v
			}
			route.WebSocket = wsCheck.Status
			results <- routeResult{route, endpoint, tlsCheck, wsCheck}
		}(spec)
	}
	wg.Wait()
	close(results)
	var endpointChecks, tlsChecks, wsChecks []model.Check
	for rr := range results {
		r.Routes = append(r.Routes, rr.route)
		endpointChecks = append(endpointChecks, rr.endpoint)
		tlsChecks = append(tlsChecks, rr.tlsCheck)
		wsChecks = append(wsChecks, rr.wsCheck)
	}
	sort.Slice(r.Routes, func(i, j int) bool { return r.Routes[i].Name < r.Routes[j].Name })
	r.Checks = append(r.Checks, systemCheck(r.Platform))
	r.Checks = append(r.Checks, egressIPTypeCheck(r.Routes))
	r.Checks = append(r.Checks, collapse("anthropic.access", "network", "Anthropic API accessibility", 25, endpointChecks))
	r.Checks = append(r.Checks, collapse("tls.integrity", "tls", "TLS negotiation and certificate", 15, tlsChecks))
	r.Checks = append(r.Checks, routeConsistency(r.Routes))
	r.Checks = append(r.Checks, inspectDNS(ctx, time.Duration(opts.TimeoutSeconds)*time.Second))
	r.Checks = append(r.Checks, collapse("websocket.access", "websocket", "WebSocket connectivity", 10, wsChecks))
	if opts.Authenticated {
		r.Checks = append(r.Checks, authenticatedCheck(ctx, opts, time.Duration(opts.TimeoutSeconds)*time.Second))
	}
	if opts.RunDoctor {
		r.Checks = append(r.Checks, doctorCheck(ctx))
	}
	scoring.Apply(&r)
	r.DurationMS = time.Since(started).Milliseconds()
	return r
}

type routeSpec struct {
	name     string
	proxyURL *url.URL
}

func routeSpecs(profile string) []routeSpec {
	direct := routeSpec{name: "direct"}
	if profile == "direct" {
		return []routeSpec{direct}
	}
	raw := firstEnv("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy")
	var p *url.URL
	if raw != "" {
		p, _ = url.Parse(raw)
	}
	env := routeSpec{name: "environment", proxyURL: p}
	if profile == "system-proxy" {
		return []routeSpec{env}
	}
	return []routeSpec{direct, env}
}

func makeClient(spec routeSpec, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: timeout, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true,
	}
	if spec.proxyURL != nil {
		tr.Proxy = http.ProxyURL(spec.proxyURL)
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

func inspectRoute(ctx context.Context, client *http.Client, spec routeSpec, opts model.ScanOptions) model.Route {
	start := time.Now()
	r := model.Route{Name: spec.name, WebSocket: model.Unknown}
	if spec.proxyURL != nil {
		r.Proxy = redact.Proxy(spec.proxyURL.String())
		r.ProxyDiagnostics = proxyDiagnostics(spec.proxyURL)
	}
	if opts.ProbeURL != "" {
		if obs, err := probeObserve(ctx, client, opts.ProbeURL); err == nil {
			r.PublicIP = obs.IP
			r.Country = obs.Country
			r.CountryCode = obs.CountryCode
			r.ASN = obs.ASN
			r.Organization = obs.Organization
			r.Source = "self-hosted-probe"
			r.TLS = obs.TLS
		}
	}
	if r.PublicIP == "" && opts.PublicFallback {
		if obs := observePublicIP(ctx, client); obs.IP != "" {
			r.PublicIP = obs.IP
			r.Source = obs.Source
			if len(obs.Attempts) > 0 {
				r.Error = "public IP methods: " + strings.Join(obs.Attempts, "; ")
			}
			applyPublicGeo(ctx, client, &r)
		} else if len(obs.Attempts) > 0 {
			r.Error = "Public egress observation unavailable: " + redact.Text(strings.Join(obs.Attempts, "; "))
		}
	}
	if r.PublicIP == "" {
		if r.Error == "" {
			r.Error = "Public egress observation unavailable"
		}
	}
	r.LatencyMS = time.Since(start).Milliseconds()
	return r
}

type publicIPObservation struct {
	IP       string
	Source   string
	Attempts []string
}

func observePublicIP(ctx context.Context, client *http.Client) publicIPObservation {
	services := []struct {
		name string
		url  string
		json bool
	}{
		{"api64.ipify.org", "https://api64.ipify.org?format=json", true},
		{"checkip.amazonaws.com", "https://checkip.amazonaws.com", false},
		{"icanhazip.com", "https://icanhazip.com", false},
		{"ifconfig.me", "https://ifconfig.me/ip", false},
	}
	obs := publicIPObservation{}
	for _, svc := range services {
		ip, err := fetchPublicIP(ctx, client, svc.url, svc.json)
		if err != nil {
			obs.Attempts = append(obs.Attempts, svc.name+" failed: "+redact.Text(err.Error()))
			continue
		}
		obs.Attempts = append(obs.Attempts, svc.name+" observed "+ip)
		if obs.IP == "" {
			obs.IP = ip
			obs.Source = svc.name
		}
	}
	return obs
}

func fetchPublicIP(ctx context.Context, client *http.Client, endpoint string, isJSON bool) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("User-Agent", "claude-environment-check/"+model.ToolVersion)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if isJSON {
		var v struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&v); err != nil {
			return "", err
		}
		if net.ParseIP(strings.TrimSpace(v.IP)) == nil {
			return "", errors.New("invalid IP in response")
		}
		return strings.TrimSpace(v.IP), nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return "", errors.New("invalid IP in response")
	}
	return ip, nil
}

type probeObservation struct {
	IP, Country, CountryCode, ASN, Organization string
	TLS                                         model.TLSInfo
}

func probeObserve(ctx context.Context, client *http.Client, base string) (probeObservation, error) {
	base = strings.TrimRight(base, "/")
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/session", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return probeObservation{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return probeObservation{}, fmt.Errorf("probe session: HTTP %d", resp.StatusCode)
	}
	var session struct {
		Token string `json:"token"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&session) != nil || session.Token == "" {
		return probeObservation{}, errors.New("invalid probe session")
	}
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/observe?session="+url.QueryEscape(session.Token), nil)
	resp, err = client.Do(req)
	if err != nil {
		return probeObservation{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return probeObservation{}, fmt.Errorf("probe observe: HTTP %d", resp.StatusCode)
	}
	var out struct {
		IP, Country, CountryCode, ASN, Organization string
		TLS                                         model.TLSInfo `json:"tls"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&out); err != nil {
		return probeObservation{}, err
	}
	return probeObservation{out.IP, out.Country, out.CountryCode, out.ASN, out.Organization, out.TLS}, nil
}

func applyPublicGeo(ctx context.Context, client *http.Client, r *model.Route) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipwho.is/"+url.PathEscape(r.PublicIP), nil)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var v struct {
		Success     bool   `json:"success"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		Connection  struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 131072)).Decode(&v) == nil && v.Success {
		r.Country = v.Country
		r.CountryCode = v.CountryCode
		r.ASN = fmt.Sprint(v.Connection.ASN)
		r.Organization = v.Connection.Org
		if r.Organization == "" {
			r.Organization = v.Connection.ISP
		}
	}
}

func inspectAnthropic(ctx context.Context, client *http.Client, route string) (model.Check, model.Check) {
	start := time.Now()
	c := model.Check{ID: "anthropic.access." + route, Category: "network", Title: "Anthropic API via " + route, Weight: 25, Observed: true, Source: "api.anthropic.com"}
	type endpoint struct {
		name   string
		method string
		url    string
	}
	endpoints := []endpoint{
		{"root", http.MethodGet, "https://api.anthropic.com/"},
		{"models-no-key", http.MethodGet, "https://api.anthropic.com/v1/models"},
	}
	attempts := map[string]any{}
	var tlsState *tls.ConnectionState
	pass, warn, fail := 0, 0, 0
	regionDenied := false
	var summaries []string
	for _, ep := range endpoints {
		req, _ := http.NewRequestWithContext(ctx, ep.method, ep.url, nil)
		req.Header.Set("User-Agent", "claude-environment-check/"+model.ToolVersion)
		if strings.Contains(ep.url, "/v1/") {
			req.Header.Set("anthropic-version", "2023-06-01")
		}
		resp, err := client.Do(req)
		if err != nil {
			fail++
			msg := redact.Text(err.Error())
			attempts[ep.name] = map[string]any{"error": msg}
			summaries = append(summaries, ep.name+": "+msg)
			continue
		}
		if resp.TLS != nil && tlsState == nil {
			copyState := *resp.TLS
			tlsState = &copyState
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		_ = resp.Body.Close()
		bodyText := strings.ToLower(string(body))
		status := resp.StatusCode
		attempts[ep.name] = map[string]any{"status": status}
		summaries = append(summaries, fmt.Sprintf("%s HTTP %d", ep.name, status))
		switch {
		case status == 451:
			fail++
			regionDenied = true
		case status == 403 && containsRegion(bodyText):
			fail++
			regionDenied = true
		case status == 403:
			warn++
		case status >= 200 && status < 500:
			pass++
		default:
			fail++
		}
	}
	c.Evidence = map[string]any{"route": route, "attempts": attempts}
	c.DurationMS = time.Since(start).Milliseconds()
	switch {
	case pass > 0 && fail == 0 && warn == 0:
		c.Status = model.Pass
	case pass > 0 || warn > 0:
		c.Status = model.Warn
	case fail > 0:
		c.Status = model.Fail
	default:
		c.Status = model.Unknown
	}
	if regionDenied {
		c.Summary = "Anthropic endpoint returned explicit region/country denial: " + strings.Join(summaries, "; ")
	} else if fail > 0 && pass == 0 && warn == 0 {
		c.Summary = "All Anthropic endpoint methods failed: " + strings.Join(summaries, "; ")
	} else {
		c.Summary = fmt.Sprintf("Anthropic endpoint methods: %d OK, %d limited, %d failed", pass, warn, fail)
	}
	tc := model.Check{ID: "tls.integrity." + route, Category: "tls", Title: "TLS via " + route, Weight: 15, Observed: true, Source: "api.anthropic.com"}
	if tlsState == nil {
		tc.Status = model.Unknown
		tc.Summary = "No TLS state available"
	} else {
		info := tlsInfo(tlsState)
		tc.Status = model.Pass
		tc.Summary = info.Version + " / " + info.Cipher
		tc.Evidence = map[string]any{"tls": info}
	}
	return c, tc
}

func tlsInfo(cs *tls.ConnectionState) model.TLSInfo {
	info := model.TLSInfo{Version: tlsVersion(cs.Version), Cipher: tls.CipherSuiteName(cs.CipherSuite), ALPN: cs.NegotiatedProtocol}
	if len(cs.PeerCertificates) > 0 {
		cert := cs.PeerCertificates[0]
		info.Issuer = cert.Issuer.String()
		info.Subject = cert.Subject.String()
		info.DNSNames = cert.DNSNames
		h := sha256.Sum256(cert.Raw)
		info.Fingerprint = hex.EncodeToString(h[:])
	}
	return info
}

func inspectWebSocket(ctx context.Context, spec routeSpec, timeout time.Duration) model.Check {
	start := time.Now()
	d := websocket.Dialer{HandshakeTimeout: timeout, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if spec.proxyURL != nil {
		d.Proxy = http.ProxyURL(spec.proxyURL)
	}
	endpoints := []string{
		"wss://ws.postman-echo.com/raw",
		"wss://echo.websocket.events/",
	}
	attempts := map[string]any{}
	success := 0
	for _, endpoint := range endpoints {
		conn, resp, err := d.DialContext(ctx, endpoint, nil)
		item := map[string]any{}
		if resp != nil {
			item["status"] = resp.StatusCode
		}
		if err != nil {
			item["error"] = redact.Text(err.Error())
			attempts[endpoint] = item
			continue
		}
		_ = conn.Close()
		item["ok"] = true
		attempts[endpoint] = item
		success++
	}
	c := model.Check{ID: "websocket.access." + spec.name, Category: "websocket", Title: "WebSocket via " + spec.name, Weight: 10, Observed: true, Source: "ws.postman-echo.com + echo.websocket.events", DurationMS: time.Since(start).Milliseconds(), Evidence: map[string]any{"attempts": attempts}}
	if success > 0 {
		c.Status = model.Pass
		c.Summary = fmt.Sprintf("WebSocket handshake succeeded on %d/%d method(s)", success, len(endpoints))
		return c
	}
	c.Status = model.Unknown
	c.Summary = "All WebSocket handshake methods failed"
	return c
}

func inspectDNS(ctx context.Context, timeout time.Duration) model.Check {
	start := time.Now()
	c := model.Check{ID: "dns.consistency", Category: "dns", Title: "DNS resolution consistency", Weight: 15, Observed: true}
	system, err := net.DefaultResolver.LookupHost(ctx, "api.anthropic.com")
	client := &http.Client{Timeout: timeout}
	resolverURLs := map[string]string{
		"cloudflare": "https://cloudflare-dns.com/dns-query?name=api.anthropic.com&type=A",
		"google":     "https://dns.google/resolve?name=api.anthropic.com&type=A",
		"quad9":      "https://dns.quad9.net/dns-query?name=api.anthropic.com&type=A",
	}
	dohAttempts := map[string]any{}
	var doh []string
	for name, endpoint := range resolverURLs {
		answers, e := queryDoHJSON(ctx, client, endpoint)
		if e != nil {
			dohAttempts[name] = map[string]any{"error": redact.Text(e.Error())}
			continue
		}
		dohAttempts[name] = answers
		doh = append(doh, answers...)
	}
	doh = uniqueStrings(doh)
	c.DurationMS = time.Since(start).Milliseconds()
	c.Evidence = map[string]any{"system": system, "doh": doh, "doh_attempts": dohAttempts}
	c.Source = "system resolver + Cloudflare/Google/Quad9 DoH"
	if err != nil {
		c.Status = model.Fail
		c.Summary = "System DNS failed: " + redact.Text(err.Error())
	} else if len(doh) == 0 {
		c.Status = model.Warn
		c.Summary = "System DNS works; DoH comparison unavailable"
	} else {
		c.Status = model.Pass
		c.Summary = fmt.Sprintf("System DNS and %d independent DoH answer(s) resolve the endpoint", len(doh))
	}
	return c
}

func queryDoHJSON(ctx context.Context, client *http.Client, endpoint string) ([]string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", "claude-environment-check/"+model.ToolVersion)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var v struct {
		Status int `json:"Status"`
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 131072)).Decode(&v); err != nil {
		return nil, err
	}
	var out []string
	for _, a := range v.Answer {
		if a.Type == 1 || a.Type == 28 {
			if net.ParseIP(a.Data) != nil {
				out = append(out, a.Data)
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no A/AAAA answers")
	}
	return out, nil
}

func routeConsistency(routes []model.Route) model.Check {
	c := model.Check{ID: "route.consistency", Category: "proxy", Title: "Route and proxy consistency", Weight: 20, Observed: true, Evidence: map[string]any{}}
	if len(routes) == 0 {
		c.Status = model.Unknown
		c.Summary = "No route observations"
		return c
	}
	for _, r := range routes {
		ev := map[string]any{"ip": r.PublicIP, "country": r.CountryCode, "proxy": r.Proxy, "source": r.Source}
		if r.Error != "" {
			ev["note"] = r.Error
		}
		if r.Proxy != "" {
			ev["proxy_checks"] = r.ProxyDiagnostics
		}
		c.Evidence[r.Name] = ev
	}
	if len(routes) == 1 {
		if routes[0].PublicIP != "" {
			c.Status = model.Pass
			c.Summary = "Selected route produced an observable egress"
		} else {
			c.Status = model.Warn
			c.Summary = "Selected route exists, but public egress could not be confirmed"
		}
		return c
	}
	if routes[0].PublicIP == "" || routes[1].PublicIP == "" {
		if routes[0].PublicIP != "" || routes[1].PublicIP != "" {
			c.Status = model.Warn
			c.Summary = "Only part of the route egresses could be observed"
		} else {
			c.Status = model.Unknown
			c.Summary = "No route egress could be observed"
		}
	} else {
		c.Status = model.Pass
		c.Summary = "Direct and environment routes were both observed"
		if routes[0].PublicIP != routes[1].PublicIP {
			c.Status = model.Warn
			c.Summary = "Direct and environment routes use different egress IPs"
		}
	}
	return c
}

func egressIPTypeCheck(routes []model.Route) model.Check {
	c := model.Check{ID: "egress.ip_type", Category: "proxy", Title: "Egress IP type", Weight: 10, Observed: true, Evidence: map[string]any{"rule": "Only residential/static-leaning ISP exits pass; datacenter/VPN/shared/unknown exits are treated as threat."}}
	r := effectiveRoute(routes)
	if r == nil || r.PublicIP == "" {
		c.Status = model.Fail
		c.Summary = "Threat: current egress IP type could not be confirmed as residential/static"
		c.Evidence["verdict"] = "threat"
		c.Evidence["reason"] = "No observable public egress IP"
		c.Remediation = "Use only organization-approved network configurations and verify the public exit type with a trusted IP intelligence source."
		return c
	}
	verdict, reasons := classifyEgressIP(*r)
	c.Evidence["selected_route"] = r.Name
	c.Evidence["public_ip"] = r.PublicIP
	c.Evidence["country"] = r.CountryCode
	c.Evidence["asn"] = r.ASN
	c.Evidence["organization"] = r.Organization
	c.Evidence["source"] = r.Source
	c.Evidence["verdict"] = verdict
	c.Evidence["reasons"] = reasons
	c.Evidence["static_ip_note"] = "Static assignment cannot be proven reliably without a commercial IP intelligence database; this tool reports a conservative heuristic."
	if verdict == "residential_static_like" {
		c.Status = model.Pass
		c.Summary = "Residential/static-leaning ISP egress detected"
	} else {
		c.Status = model.Fail
		c.Summary = "Threat: current egress looks public/shared/datacenter/VPN or cannot be confirmed as residential/static"
		c.Remediation = "Use only organization-approved network configurations and verify the public exit type with a trusted IP intelligence source."
	}
	return c
}

func effectiveRoute(routes []model.Route) *model.Route {
	for i := range routes {
		if routes[i].Name == "environment" && routes[i].PublicIP != "" {
			return &routes[i]
		}
	}
	for i := range routes {
		if routes[i].Name == "direct" && routes[i].PublicIP != "" {
			return &routes[i]
		}
	}
	if len(routes) > 0 {
		return &routes[0]
	}
	return nil
}

func classifyEgressIP(r model.Route) (string, []string) {
	text := strings.ToLower(strings.Join([]string{r.ASN, r.Organization, r.Source}, " "))
	var reasons []string
	if r.CountryCode == "" || strings.TrimSpace(r.Organization+r.ASN) == "" {
		return "threat", []string{"ASN/organization data is missing, so residential/static type cannot be confirmed"}
	}
	if containsAny(text, datacenterIPMarkers()) {
		return "threat", []string{"ASN/organization contains datacenter, cloud, hosting, VPN, proxy, CDN, or colocation markers"}
	}
	if containsAny(text, residentialISPMarkers()) {
		reasons = append(reasons, "ASN/organization looks like a consumer ISP or telecom access network")
		if r.Proxy != "" {
			reasons = append(reasons, "traffic is routed through a configured proxy; static assignment is not independently proven")
		}
		return "residential_static_like", reasons
	}
	return "threat", []string{"ASN/organization is not a recognized residential ISP marker; treating unknown/shared/public exits as threat"}
}

func containsAny(s string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func datacenterIPMarkers() []string {
	return []string{
		"amazon", "aws", "google cloud", "microsoft", "azure", "cloudflare", "akamai", "fastly", "oracle", "digitalocean", "linode", "akamai connected cloud",
		"vultr", "choopa", "ovh", "hetzner", "leaseweb", "m247", "datacamp", "datacenter", "data center", "colo", "colocation", "hosting", "host", "server",
		"vpn", "proxy", "tor", "cdn", "alibaba", "aliyun", "tencent", "huawei cloud", "baidu cloud", "ucloud", "cloud", "rackspace", "contabo", "ionos",
	}
}

func residentialISPMarkers() []string {
	return []string{
		"comcast", "xfinity", "charter", "spectrum", "cox", "verizon", "fios", "at&t", "att internet", "frontier", "centurylink", "lumen",
		"t-mobile", "tmobile", "starlink", "hughes", "viasat", "bt ", "british telecom", "deutsche telekom", "telekom", "orange", "vodafone",
		"telefonica", "movistar", "proximus", "ziggo", "kpn", "telia", "telenor", "swisscom", "bell", "rogers", "telus", "shaw",
		"telstra", "optus", "spark", "ntt", "kddi", "softbank", "docomo", "sk broadband", "korea telecom", "kt ", "lg uplus", "singtel",
		"starhub", "chunghwa", "hinet", "pccw", "hkbn", "telecom", "communications", "broadband", "fiber", "fibre", "cable", "isp",
	}
}

func proxyDiagnostics(u *url.URL) map[string]any {
	out := map[string]any{"configured": u != nil}
	if u == nil {
		return out
	}
	host := proxyHost(u)
	out["scheme"] = strings.ToLower(u.Scheme)
	out["host"] = host
	conn, err := net.DialTimeout("tcp", host, 2500*time.Millisecond)
	if err != nil {
		out["tcp_reachable"] = false
		out["tcp_error"] = redact.Text(err.Error())
		return out
	}
	out["tcp_reachable"] = true
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2500 * time.Millisecond))
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		out["connect_method"] = "http-connect"
		_, _ = fmt.Fprintf(conn, "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\nUser-Agent: claude-environment-check/%s\r\n", model.ToolVersion)
		if u.User != nil {
			user := u.User.Username()
			pass, _ := u.User.Password()
			token := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
			_, _ = fmt.Fprintf(conn, "Proxy-Authorization: Basic %s\r\n", token)
			out["auth_supplied"] = true
		}
		_, _ = fmt.Fprint(conn, "\r\n")
		buf := make([]byte, 256)
		n, e := conn.Read(buf)
		if e != nil {
			out["connect_error"] = redact.Text(e.Error())
		} else {
			line := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
			out["connect_response"] = strings.TrimSpace(line)
			out["connect_ok"] = strings.Contains(line, " 200 ")
		}
	case "socks5", "socks5h":
		out["connect_method"] = "socks5"
		ok, note := socks5Connect(conn, u, "api.anthropic.com", 443)
		out["connect_ok"] = ok
		if note != "" {
			out["connect_response"] = note
		}
	default:
		out["connect_method"] = "unsupported-proxy-scheme"
	}
	return out
}

func proxyHost(u *url.URL) string {
	host := u.Host
	if !strings.Contains(host, ":") {
		switch strings.ToLower(u.Scheme) {
		case "http", "https":
			host += ":8080"
		case "socks5", "socks5h":
			host += ":1080"
		}
	}
	return host
}

func socks5Connect(conn net.Conn, u *url.URL, target string, port int) (bool, string) {
	methods := []byte{0x00}
	if u.User != nil {
		methods = append(methods, 0x02)
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return false, redact.Text(err.Error())
	}
	buf := make([]byte, 260)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return false, redact.Text(err.Error())
	}
	if buf[0] != 0x05 {
		return false, "not a SOCKS5 proxy"
	}
	if buf[1] == 0xff {
		return false, "SOCKS5 server rejected available authentication methods"
	}
	if buf[1] == 0x02 {
		user := u.User.Username()
		pass, _ := u.User.Password()
		if len(user) > 255 || len(pass) > 255 {
			return false, "SOCKS5 username/password is too long"
		}
		pkt := []byte{0x01, byte(len(user))}
		pkt = append(pkt, []byte(user)...)
		pkt = append(pkt, byte(len(pass)))
		pkt = append(pkt, []byte(pass)...)
		if _, err := conn.Write(pkt); err != nil {
			return false, redact.Text(err.Error())
		}
		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			return false, redact.Text(err.Error())
		}
		if buf[1] != 0x00 {
			return false, "SOCKS5 authentication failed"
		}
	}
	if len(target) > 255 {
		return false, "target hostname too long"
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(target))}
	req = append(req, []byte(target)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return false, redact.Text(err.Error())
	}
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return false, redact.Text(err.Error())
	}
	if buf[1] != 0x00 {
		return false, fmt.Sprintf("SOCKS5 connect reply 0x%02x", buf[1])
	}
	var skip int
	switch buf[3] {
	case 0x01:
		skip = 4 + 2
	case 0x03:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return false, redact.Text(err.Error())
		}
		skip = int(buf[0]) + 2
	case 0x04:
		skip = 16 + 2
	default:
		return false, "SOCKS5 returned unknown address type"
	}
	if _, err := io.ReadFull(conn, buf[:skip]); err != nil {
		return false, redact.Text(err.Error())
	}
	return true, "SOCKS5 CONNECT to api.anthropic.com:443 succeeded"
}

func systemCheck(p model.Platform) model.Check {
	mainlandSignals := mainlandDeviceSignals(p)
	targetSignals := targetDeviceSignals(p)
	c := model.Check{ID: "system.readiness", Category: "system", Title: "Device target-environment match", Weight: 15, Observed: true, Evidence: map[string]any{"os": p.OS, "arch": p.Architecture, "timezone": p.Timezone, "utc_offset": p.UTCOffset, "locale": p.Locale, "system_locale": p.SystemLocale, "user_languages": p.UserLanguages, "format_settings": p.FormatSettings, "code_page": p.CodePage, "claude_version": p.ClaudeVersion, "dns_servers": p.DNSServers, "proxy_env_names": mapKeys(p.ProxyEnv), "target_profile": "US or non-Mainland-like device environment", "mainland_device_signals": mainlandSignals, "target_like_device_signals": targetSignals}}
	if p.OS != "windows" && p.OS != "darwin" && p.OS != "linux" {
		c.Status = model.Fail
		c.Summary = "Unsupported operating system"
	} else if len(mainlandSignals) > 0 {
		c.Status = model.Fail
		c.Summary = fmt.Sprintf("Device-side signals match Mainland China (%d signal(s)); target profile not met", len(mainlandSignals))
		c.Remediation = "Review Anthropic's supported-location policy and keep device region, timezone, language, DNS, and proxy configuration consistent with your permitted environment."
	} else if p.ClaudePath == "" {
		c.Status = model.Warn
		c.Summary = "Target-like device signals; Claude Code executable was not found"
		c.Remediation = "Install Claude Code using Anthropic's official instructions."
	} else {
		c.Status = model.Pass
		c.Summary = "Target-like device signals and Claude Code executable found"
	}
	return c
}

func mainlandDeviceSignals(p model.Platform) []string {
	var out []string
	localeText := strings.ToLower(strings.Join(append([]string{p.Locale, p.SystemLocale}, p.UserLanguages...), " "))
	if containsMainlandLocale(localeText) {
		out = append(out, "language/region setting contains zh-CN or Simplified Chinese mainland marker")
	}
	tz := strings.ToLower(strings.TrimSpace(p.Timezone))
	if strings.Contains(tz, "asia/shanghai") || strings.Contains(tz, "china standard") || strings.Contains(tz, "中国标准") || p.UTCOffset == "+08:00" {
		out = append(out, "timezone or UTC offset matches Mainland China common setting")
	}
	if strings.Contains(strings.ToLower(p.CodePage), "936") {
		out = append(out, "system code page is 936 (Simplified Chinese/GBK)")
	}
	for _, dns := range p.DNSServers {
		if isMainlandPublicDNS(dns) {
			out = append(out, "DNS server uses a known Mainland China public resolver: "+dns)
		}
	}
	return uniqueStrings(out)
}

func targetDeviceSignals(p model.Platform) []string {
	var out []string
	localeText := strings.ToLower(strings.Join(append([]string{p.Locale, p.SystemLocale}, p.UserLanguages...), " "))
	if strings.Contains(localeText, "en-us") {
		out = append(out, "language/region includes en-US")
	}
	tz := strings.ToLower(strings.TrimSpace(p.Timezone))
	if strings.Contains(tz, "america/") || strings.Contains(tz, "pacific standard") || strings.Contains(tz, "eastern standard") || strings.Contains(tz, "central standard") || strings.Contains(tz, "mountain standard") {
		out = append(out, "timezone name matches a US timezone")
	}
	switch p.UTCOffset {
	case "-04:00", "-05:00", "-06:00", "-07:00", "-08:00", "-09:00", "-10:00":
		out = append(out, "UTC offset is compatible with common US timezones")
	}
	if strings.Contains(strings.ToLower(p.CodePage), "437") || strings.Contains(strings.ToLower(p.CodePage), "65001") {
		out = append(out, "code page is common for English/UTF-8 environments")
	}
	return uniqueStrings(out)
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

func isMainlandPublicDNS(s string) bool {
	host := strings.Trim(strings.ToLower(s), "[] ")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	known := map[string]bool{
		"114.114.114.114": true,
		"114.114.115.115": true,
		"223.5.5.5":       true,
		"223.6.6.6":       true,
		"119.29.29.29":    true,
		"180.76.76.76":    true,
		"1.2.4.8":         true,
		"210.2.4.8":       true,
	}
	return known[host]
}

func authenticatedCheck(ctx context.Context, opts model.ScanOptions, timeout time.Duration) model.Check {
	c := model.Check{ID: "anthropic.authenticated", Category: "network", Title: "Optional authenticated API check", Weight: 0, Observed: true, Source: "api.anthropic.com"}
	key := opts.APIKey
	if key == "" {
		key = os.Getenv("ANTHROPIC_API_KEY")
	}
	if key == "" {
		c.Status = model.Unknown
		c.Summary = "No API key supplied"
		return c
	}
	client := &http.Client{Timeout: timeout}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.anthropic.com/v1/models", nil)
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := client.Do(req)
	if err != nil {
		c.Status = model.Fail
		c.Summary = redact.Text(err.Error())
		return c
	}
	var models struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if resp.StatusCode/100 == 2 {
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&models)
		c.Status = model.Pass
		c.Summary = "API key accepted by the models endpoint"
	} else {
		c.Status = model.Fail
		c.Summary = fmt.Sprintf("Authenticated endpoint returned HTTP %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if opts.ModelRequest && c.Status == model.Pass {
		if len(models.Data) == 0 {
			c.Status = model.Unknown
			c.Summary = "Authentication succeeded, but no model was available for the confirmed request"
		} else {
			payload, _ := json.Marshal(map[string]any{"model": models.Data[0].ID, "max_tokens": 1, "messages": []map[string]string{{"role": "user", "content": "Reply OK"}}})
			req, _ = http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(payload))
			req.Header.Set("x-api-key", key)
			req.Header.Set("anthropic-version", "2023-06-01")
			req.Header.Set("content-type", "application/json")
			modelResp, e := client.Do(req)
			if e != nil {
				c.Status = model.Fail
				c.Summary = "Confirmed model request failed: " + redact.Text(e.Error())
			} else {
				status := modelResp.StatusCode
				_, _ = io.Copy(io.Discard, io.LimitReader(modelResp.Body, 4096))
				_ = modelResp.Body.Close()
				if status/100 == 2 {
					c.Status = model.Pass
					c.Summary = "Authentication and confirmed one-token model request succeeded"
				} else if status == 429 {
					c.Status = model.Warn
					c.Summary = "Authentication succeeded; model request was rate limited"
				} else {
					c.Status = model.Fail
					c.Summary = fmt.Sprintf("Confirmed model request returned HTTP %d", status)
				}
			}
		}
	}
	key = ""
	return c
}

func doctorCheck(ctx context.Context) model.Check {
	c := model.Check{ID: "claude.doctor", Category: "system", Title: "Claude doctor", Weight: 0, Observed: true}
	p, err := exec.LookPath("claude")
	if err != nil {
		c.Status = model.Unknown
		c.Summary = "Claude executable not found"
		return c
	}
	cmd := exec.CommandContext(ctx, p, "doctor")
	hideCommand(cmd)
	out, err := cmd.CombinedOutput()
	summary := redact.Text(string(out))
	if len(summary) > 1000 {
		summary = summary[:1000]
	}
	c.Evidence = map[string]any{"output": summary}
	if err != nil {
		c.Status = model.Warn
		c.Summary = "claude doctor returned an error"
	} else {
		c.Status = model.Pass
		c.Summary = "claude doctor completed"
	}
	return c
}

func collapse(id, category, title string, weight int, items []model.Check) model.Check {
	c := model.Check{ID: id, Category: category, Title: title, Weight: weight, Observed: false, Evidence: map[string]any{}}
	if len(items) == 0 {
		c.Status = model.Unknown
		c.Summary = "No checks were run"
		return c
	}
	c.Observed = true
	pass, warn, fail, unknown := 0, 0, 0, 0
	for _, item := range items {
		c.Evidence[item.ID] = map[string]any{"status": item.Status, "summary": item.Summary, "evidence": item.Evidence}
		switch item.Status {
		case model.Pass:
			pass++
		case model.Warn:
			warn++
		case model.Fail:
			fail++
		default:
			unknown++
		}
	}
	switch {
	case pass > 0 && warn == 0 && fail == 0:
		if unknown > 0 {
			c.Status = model.Warn
		} else {
			c.Status = model.Pass
		}
	case pass > 0 || warn > 0:
		c.Status = model.Warn
	case fail > 0:
		c.Status = model.Fail
	default:
		c.Status = model.Unknown
	}
	c.Summary = fmt.Sprintf("%d route check(s): %d normal, %d need attention, %d failed, %d unknown", len(items), pass, warn, fail, unknown)
	return c
}

func collectPlatform() model.Platform {
	host, _ := os.Hostname()
	p := model.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH, Hostname: host, ProxyEnv: map[string]string{}}
	now := time.Now()
	p.Timezone = now.Location().String()
	_, off := now.Zone()
	p.UTCOffset = fmt.Sprintf("%+03d:%02d", off/3600, (off%3600)/60)
	p.Locale = firstEnv("LC_ALL", "LC_CTYPE", "LANG", "LANGUAGE")
	lp := systemLocaleProfile()
	if p.Locale == "" {
		p.Locale = firstNonEmpty(lp.Culture, lp.UICulture)
	}
	p.SystemLocale = firstNonEmpty(lp.SystemLocale, lp.UICulture, lp.Culture)
	p.UserLanguages = uniqueStrings(lp.UserLanguages)
	p.FormatSettings = compactMap(map[string]string{"decimal": lp.Decimal, "list": lp.List, "date": lp.Date, "time": lp.Time})
	p.CodePage = lp.CodePage
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY"} {
		if v := os.Getenv(k); v != "" {
			if strings.Contains(k, "PROXY") && k != "NO_PROXY" {
				v = redact.Proxy(v)
			}
			p.ProxyEnv[k] = v
		}
	}
	p.DNSServers = systemDNSServers()
	p.SystemProxy = systemProxy()
	if path, err := exec.LookPath("claude"); err == nil {
		p.ClaudePath = path
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, path, "--version")
		hideCommand(cmd)
		if out, e := cmd.CombinedOutput(); e == nil {
			p.ClaudeVersion = strings.TrimSpace(redact.Text(string(out)))
		}
	}
	return p
}

func systemLocaleProfile() localeProfile {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	switch runtime.GOOS {
	case "windows":
		script := "$ErrorActionPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); $c=Get-Culture; $ui=Get-UICulture; $sys=Get-WinSystemLocale; $langs=@(); try{$langs=@((Get-WinUserLanguageList).LanguageTag)}catch{}; $cp=((cmd /c chcp) -join ' '); [pscustomobject]@{culture=$c.Name; ui_culture=$ui.Name; system_locale=$sys.Name; user_languages=$langs; decimal=$c.NumberFormat.NumberDecimalSeparator; list=$c.TextInfo.ListSeparator; date=$c.DateTimeFormat.ShortDatePattern; time=$c.DateTimeFormat.ShortTimePattern; code_page=$cp} | ConvertTo-Json -Compress"
		cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", script)
		hideCommand(cmd)
		out, err := cmd.Output()
		if err != nil {
			return localeProfile{}
		}
		var lp localeProfile
		if json.Unmarshal(out, &lp) == nil {
			lp.CodePage = strings.TrimSpace(redact.Text(lp.CodePage))
			return lp
		}
	case "darwin":
		cmd := exec.CommandContext(ctx, "defaults", "read", "-g", "AppleLanguages")
		hideCommand(cmd)
		if out, err := cmd.Output(); err == nil {
			return localeProfile{UserLanguages: parseLocaleWords(string(out))}
		}
	default:
		cmd := exec.CommandContext(ctx, "locale")
		hideCommand(cmd)
		if out, err := cmd.Output(); err == nil {
			return parseLocaleOutput(string(out))
		}
	}
	return localeProfile{}
}

func systemDNSServers() []string {
	var cmd *exec.Cmd
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", "(Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses) -join ','")
	case "darwin":
		cmd = exec.CommandContext(ctx, "scutil", "--dns")
	default:
		b, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return nil
		}
		return parseIPs(string(b))
	}
	hideCommand(cmd)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parseIPs(string(out))
}

func systemProxy() string {
	var cmd *exec.Cmd
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", "$ErrorActionPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); $v=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; [pscustomobject]@{proxy_enabled=[bool]$v.ProxyEnable; proxy_server=$v.ProxyServer; pac=$v.AutoConfigURL} | ConvertTo-Json -Compress")
	case "darwin":
		cmd = exec.CommandContext(ctx, "scutil", "--proxy")
	default:
		return ""
	}
	hideCommand(cmd)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(out))
	if len(s) > 600 {
		s = s[:600]
	}
	return redact.Text(s)
}

func parseIPs(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == ',' || r == ';' }) {
		f = strings.Trim(f, "[]()\"")
		if net.ParseIP(strings.Split(f, "%")[0]) != nil && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}
func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func compactMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		if strings.TrimSpace(v) != "" {
			out[k] = strings.TrimSpace(v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mapKeys(in map[string]string) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func parseLocaleWords(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == ',' || r == ';' || r == '(' || r == ')' || r == '"' || r == '\''
	}) {
		f = strings.TrimSpace(f)
		if len(f) >= 2 && (strings.Contains(f, "-") || strings.Contains(f, "_")) {
			out = append(out, f)
		}
	}
	return uniqueStrings(out)
}

func parseLocaleOutput(s string) localeProfile {
	lp := localeProfile{}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), "\"")
		switch k {
		case "LANG":
			lp.Culture = v
		case "LC_ALL", "LC_CTYPE":
			if lp.SystemLocale == "" {
				lp.SystemLocale = v
			}
		}
	}
	if lp.Culture != "" {
		lp.UserLanguages = []string{lp.Culture}
	}
	return lp
}
func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
func containsRegion(s string) bool {
	return strings.Contains(s, "region") || strings.Contains(s, "country") || strings.Contains(s, "territory") || strings.Contains(s, "not available")
}
func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	}
	return fmt.Sprintf("0x%x", v)
}

var _ = x509.Certificate{}
