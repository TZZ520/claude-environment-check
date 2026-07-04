package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"strings"

	"claude-environment-check/internal/model"
	"claude-environment-check/internal/redact"
	"claude-environment-check/internal/scanner"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type App struct {
	ctx     context.Context
	scanner *scanner.Scanner
}

func NewApp() *App                         { return &App{scanner: scanner.New()} }
func (a *App) startup(ctx context.Context) { a.ctx = ctx; appendStartupLog("wails-startup") }
func (a *App) LogFrontendError(message string) {
	appendStartupLog("frontend-error: " + redact.Text(message))
}
func (a *App) Version() map[string]string {
	return map[string]string{"tool": model.ToolVersion, "schema": model.SchemaVersion, "rules": model.RulesVersion}
}
func (a *App) Scan(opts model.ScanOptions) model.Report { return a.scanner.Scan(a.ctx, opts) }

func (a *App) ExportJSON(report model.Report) (string, error) {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{Title: "导出脱敏 JSON 报告", DefaultFilename: "claude-environment-report.json", Filters: []runtime.FileFilter{{DisplayName: "JSON 报告", Pattern: "*.json"}}})
	if err != nil || path == "" {
		return path, err
	}
	b, err := redact.JSON(report)
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, b, 0600)
}

func (a *App) ExportHTML(report model.Report) (string, error) {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{Title: "导出网页报告", DefaultFilename: "claude-environment-report.html", Filters: []runtime.FileFilter{{DisplayName: "网页报告", Pattern: "*.html"}}})
	if err != nil || path == "" {
		return path, err
	}
	b, _ := json.MarshalIndent(report, "", "  ")
	doc := "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Claude 环境检查报告</title><style>body{font:15px system-ui;max-width:980px;margin:auto;padding:40px;background:#0b1020;color:#e7ecf7}h1{font-size:28px}.scores{display:flex;gap:20px}.card{background:#131b31;border:1px solid #293655;border-radius:16px;padding:20px;flex:1}.score{font-size:42px;font-weight:750}pre{white-space:pre-wrap;word-break:break-word;background:#080d19;padding:18px;border-radius:12px}p{color:#aab4ca}</style></head><body><h1>Claude 环境检查 <small>非官方工具</small></h1><div class=\"scores\"><div class=\"card\"><div>顺利使用可能性</div><div class=\"score\">" +
		fmt.Sprint(report.CompatibilityScore) + "%</div></div><div class=\"card\"><div>大陆环境暴露可能性</div><div class=\"score\">" +
		fmt.Sprint(report.RegionExposureScore) + "%</div></div><div class=\"card\"><div>本次检测完整度</div><div class=\"score\">" +
		fmt.Sprint(report.Coverage) + "%</div></div></div><h2>脱敏后的原始报告</h2><pre>" +
		html.EscapeString(redact.Text(string(b))) + "</pre><p>本报告由非官方诊断工具生成，只根据可观察现象做解释性评分，不代表 Anthropic 内部规则。</p></body></html>"
	return path, os.WriteFile(path, []byte(doc), 0600)
}
func (a *App) OpenURL(raw string) error {
	if !strings.HasPrefix(raw, "https://") {
		return fmt.Errorf("only HTTPS links are allowed")
	}
	runtime.BrowserOpenURL(a.ctx, raw)
	return nil
}
