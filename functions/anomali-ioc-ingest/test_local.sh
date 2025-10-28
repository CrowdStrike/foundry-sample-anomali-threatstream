#!/bin/bash

# Simple test script to test local file functionality
echo "🔄 Testing local file mode for IOC ingest function..."

# Make sure we have a test directory
mkdir -p test_output/search-all

# Function to make a simple API call
make_simple_test_call() {
    echo "📞 Making simple test call to local function..."

    response=$(curl -s -X POST http://localhost:8081 \
        -H "Content-Type: application/json" \
        -d '{
            "method": "POST",
            "url": "/ingest",
            "body": {
                "repository": "search-all",
                "status": "active",
                "limit": 10
            }
        }')

    echo "📋 Response:"
    echo "$response" | python -m json.tool 2>/dev/null || echo "$response"
    echo ""
}

# Make the test call
make_simple_test_call

echo "📁 Checking test_output directory for local files..."
ls -la test_output/search-all/ 2>/dev/null || echo "No test_output directory found yet"

echo "🏁 Test complete!"