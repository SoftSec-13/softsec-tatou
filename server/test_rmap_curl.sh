#!/bin/bash
# Quick RMAP endpoint testing with curl

SERVER_URL="${1:-http://localhost:5000}"
echo "Testing RMAP endpoints on: $SERVER_URL"

echo ""
echo "1. Testing /rmap-initiate with valid payload..."
curl -X POST "$SERVER_URL/rmap-initiate" \
  -H "Content-Type: application/json" \
  -d '{"payload": "bW9ja19lbmNyeXB0ZWRfbWVzc2FnZV8x"}' \ # pragma: allowlist secret
  -w "\nHTTP Status: %{http_code}\n\n"

echo "2. Testing /rmap-initiate with missing payload..."
curl -X POST "$SERVER_URL/rmap-initiate" \
  -H "Content-Type: application/json" \
  -d '{}' \
  -w "\nHTTP Status: %{http_code}\n\n"

echo "3. Testing /rmap-get-link with valid payload..."
curl -X POST "$SERVER_URL/rmap-get-link" \
  -H "Content-Type: application/json" \
  -d '{"payload": "bW9ja19lbmNyeXB0ZWRfbWVzc2FnZV8y"}' \
  -w "\nHTTP Status: %{http_code}\n\n"

echo "4. Testing /rmap-get-link with missing payload..."
curl -X POST "$SERVER_URL/rmap-get-link" \
  -H "Content-Type: application/json" \
  -d '{}' \
  -w "\nHTTP Status: %{http_code}\n\n"

echo "Testing complete!"
