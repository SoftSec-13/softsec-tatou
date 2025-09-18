#!/bin/bash
# Quick RMAP endpoint testing with curl

SERVER_URL="${1:-http://localhost:5000}"
echo "Testing RMAP endpoints on: $SERVER_URL"

echo ""
echo "1. Testing /rmap-initiate with valid payload..."
# Create a proper JSON payload: {"nonceClient": 123456789, "identity": "Group13"}
# Base64 encoded: eyJub25jZUNsaWVudCI6IDEyMzQ1Njc4OSwgImlkZW50aXR5IjogIkdyb3VwMTMifQ==
curl -X POST "$SERVER_URL/rmap-initiate" \
  -H "Content-Type: application/json" \
  -d '{"payload": "eyJub25jZUNsaWVudCI6IDEyMzQ1Njc4OSwgImlkZW50aXR5IjogIkdyb3VwMTMifQ=="}' \
  -w "\nHTTP Status: %{http_code}\n\n"

echo "2. Testing /rmap-initiate with missing payload..."
curl -X POST "$SERVER_URL/rmap-initiate" \
  -H "Content-Type: application/json" \
  -d '{}' \
  -w "\nHTTP Status: %{http_code}\n\n"

echo "3. Testing /rmap-get-link with valid payload (will fail - wrong nonce)..."
# Create a proper JSON payload: {"nonceServer": 987654321}
# Base64 encoded: eyJub25jZVNlcnZlciI6IDk4NzY1NDMyMX0=
curl -X POST "$SERVER_URL/rmap-get-link" \
  -H "Content-Type: application/json" \
  -d '{"payload": "eyJub25jZVNlcnZlciI6IDk4NzY1NDMyMX0="}' \
  -w "\nHTTP Status: %{http_code}\n\n"

echo "4. Testing /rmap-get-link with missing payload..."
curl -X POST "$SERVER_URL/rmap-get-link" \
  -H "Content-Type: application/json" \
  -d '{}' \
  -w "\nHTTP Status: %{http_code}\n\n"

echo "5. Testing /rmap-initiate with invalid base64..."
curl -X POST "$SERVER_URL/rmap-initiate" \
  -H "Content-Type: application/json" \
  -d '{"payload": "invalid_base64!"}' \
  -w "\nHTTP Status: %{http_code}\n\n"

echo "Testing complete!"
echo ""
echo "NOTE: For a complete working test that handles the two-step protocol,"
echo "run: python3 /tmp/test_rmap_complete.py"