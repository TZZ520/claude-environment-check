package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"claude-environment-check/internal/model"
	"claude-environment-check/internal/redact"
	"claude-environment-check/internal/scanner"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		scan(os.Args[2:])
	case "serve-ui":
		serveUI(os.Args[2:])
	case "version":
		fmt.Printf("claude-env-check %s (schema %s, rules %s)\n", model.ToolVersion, model.SchemaVersion, model.RulesVersion)
	default:
		usage()
		os.Exit(2)
	}
}

func scan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	profile := fs.String("profile", "all", "direct|system-proxy|all")
	probe := fs.String("probe", "", "self-hosted probe base URL")
	timeout := fs.Int("timeout", 8, "per-check timeout seconds")
	jsonPath := fs.String("json", "", "write redacted JSON report")
	authenticated := fs.Bool("authenticated", false, "use ANTHROPIC_API_KEY for an optional authentication check")
	doctor := fs.Bool("doctor", false, "run claude doctor with explicit consent")
	noFallback := fs.Bool("no-public-fallback", false, "disable public IP/DoH fallback services")
	_ = fs.Parse(args)
	r := scanner.New().Scan(context.Background(), model.ScanOptions{Profile: *profile, ProbeURL: *probe, TimeoutSeconds: *timeout, PublicFallback: !*noFallback, Authenticated: *authenticated, RunDoctor: *doctor})
	fmt.Printf("\nClaude Environment Check (Unofficial)\nCompatibility: %d%%  Region exposure: %d%%  Coverage: %d%%\n\n", r.CompatibilityScore, r.RegionExposureScore, r.Coverage)
	for _, c := range r.Checks {
		fmt.Printf("%-7s %-24s %s\n", c.Status, c.Title, c.Summary)
	}
	if *jsonPath != "" {
		b, err := redact.JSON(r)
		if err != nil {
			fatal(err)
		}
		if err = os.WriteFile(*jsonPath, b, 0600); err != nil {
			fatal(err)
		}
		abs, _ := filepath.Abs(*jsonPath)
		fmt.Println("\nJSON:", abs)
	}
}

func serveUI(args []string) {
	fs := flag.NewFlagSet("serve-ui", flag.ExitOnError)
	addr := fs.String("listen", "127.0.0.1:0", "local listen address")
	_ = fs.Parse(args)
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fatal(err)
	}
	url := "http://" + ln.Addr().String()
	fmt.Println("Local UI:", url)
	openBrowser(url)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<!doctype html><meta charset=utf-8><title>Claude Environment Check</title><style>body{font:16px system-ui;max-width:760px;margin:10vh auto;padding:24px;background:#0b1020;color:#eef}button{padding:12px 18px}</style><h1>Claude Environment Check</h1><p>Use the desktop application for the full interactive UI, or run <code>claude-env-check scan --json report.json</code>.</p>")
	})
	server := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	fatal(server.Serve(ln))
}

func openBrowser(u string) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		c = exec.Command("open", u)
	default:
		c = exec.Command("xdg-open", u)
	}
	_ = c.Start()
}
func usage() { fmt.Fprintln(os.Stderr, "usage: claude-env-check <scan|serve-ui|version> [options]") }
func fatal(err error) {
	if err == http.ErrServerClosed {
		return
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

var _ = json.Valid
