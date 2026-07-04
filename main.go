package main

import (
	"context"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	winoptions "github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	defer func() {
		if recovered := recover(); recovered != nil {
			message := fmt.Sprintf("panic: %v\n\n%s", recovered, debug.Stack())
			path := writeStartupError(message)
			showFatalError("Claude Environment Check", fmt.Sprintf("应用启动失败。\n日志：%s\n\n%v", path, recovered))
		}
	}()
	appendStartupLog("process-start")
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.TempDir()
	}
	webviewData := filepath.Join(base, "ClaudeEnvironmentCheck", "WebView2")
	_ = os.MkdirAll(webviewData, 0700)
	app := NewApp()
	err = wails.Run(&options.App{
		Title:            "Claude Environment Check (Unofficial)",
		Width:            1240,
		Height:           820,
		MinWidth:         940,
		MinHeight:        680,
		AssetServer:      &assetserver.Options{Assets: assets},
		BackgroundColour: &options.RGBA{R: 8, G: 13, B: 25, A: 1},
		OnStartup:        app.startup,
		OnDomReady:       func(context.Context) { appendStartupLog("dom-ready") },
		Windows: &winoptions.Options{
			WebviewUserDataPath:  webviewData,
			WebviewGpuIsDisabled: os.Getenv("CEC_ENABLE_GPU") != "1",
			Theme:                winoptions.SystemDefault,
		},
		Bind: []interface{}{app},
	})
	if err != nil {
		path := writeStartupError(err.Error())
		showFatalError("Claude Environment Check", fmt.Sprintf("应用无法启动。\n日志：%s\n\n%s", path, err.Error()))
	}
}

func appendStartupLog(message string) {
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "ClaudeEnvironmentCheck")
	_ = os.MkdirAll(dir, 0700)
	f, err := os.OpenFile(filepath.Join(dir, "startup.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err == nil {
		_, _ = fmt.Fprintf(f, "[%s] %s\n", time.Now().Format(time.RFC3339), message)
		_ = f.Close()
	}
}

func writeStartupError(message string) string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "ClaudeEnvironmentCheck")
	_ = os.MkdirAll(dir, 0700)
	path := filepath.Join(dir, "startup.log")
	entry := fmt.Sprintf("[%s] version=0.1.0\n%s\n\n", time.Now().Format(time.RFC3339), message)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err == nil {
		_, _ = f.WriteString(entry)
		_ = f.Close()
	}
	return path
}
