$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Push-Location (Join-Path $Root 'frontend')
npm ci
npm run build
Pop-Location
Push-Location $Root
go test ./...
New-Item -ItemType Directory -Force 'build/bin' | Out-Null
go build -trimpath -tags 'desktop,production' -ldflags '-s -w -H windowsgui' -o 'build/bin/ClaudeEnvironmentCheck.exe' .
go build -trimpath -ldflags '-s -w' -o 'build/bin/claude-env-check.exe' ./cmd/claude-env-check
go build -trimpath -ldflags '-s -w' -o 'build/bin/probe-server.exe' ./cmd/probe-server
Pop-Location

