#!/bin/bash
# Cross-compile XCloak agent for Windows (amd64)
# Run from xcloak-agent/ directory

set -e

echo "Building XCloak Agent for Windows..."

GOOS=windows GOARCH=amd64 go build \
  -ldflags="-s -w -X main.Version=1.0.0" \
  -o dist/xcloak-agent.exe \
  ./cmd/agent/main.go 2>/dev/null || \
GOOS=windows GOARCH=amd64 go build \
  -ldflags="-s -w" \
  -o dist/xcloak-agent.exe \
  .

echo "Built: dist/xcloak-agent.exe"
echo ""
echo "Windows deployment:"
echo "  1. Copy xcloak-agent.exe to target Windows machine"
echo "  2. Set SERVER_URL environment variable:"
echo "     setx SERVER_URL http://YOUR_SERVER:8080"
echo "  3. Run as Administrator:"
echo "     xcloak-agent.exe"
echo ""
echo "To install as a Windows Service:"
echo "  sc create XCloakAgent binPath= \"C:\\path\\xcloak-agent.exe\" start= auto"
echo "  sc start XCloakAgent"
