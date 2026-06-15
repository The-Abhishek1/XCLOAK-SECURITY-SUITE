#!/bin/bash
# Run this to see the REAL compile error
cd ~/Projects/XCLOAK-SECURITY-SUITE/xcloak-ngfw/backend
echo "=== Running go build to find the error ==="
go build ./... 2>&1
echo "=== Exit code: $? ==="
