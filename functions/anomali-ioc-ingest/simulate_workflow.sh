#!/bin/bash

# Simulate workflow calling the IOC ingest function
echo "🔄 Simulating Foundry Workflow calling IOC ingest function..."

# Function to make API call and extract next token
make_api_call() {
    local next_token="$1"
    local iteration="$2"

    echo "=== Iteration $iteration ==="

    if [ -z "$next_token" ]; then
        echo "📞 Making INITIAL call (no next token)"
        body='{"repository": "search-all", "status": "active", "limit": 1000}'
    else
        echo "📞 Making PAGINATION call with next token: $next_token"
        body="{\"repository\": \"search-all\", \"status\": \"active\", \"limit\": 1000, \"next\": \"$next_token\"}"
    fi

    # Make the API call
    response=$(curl -s -X POST http://localhost:8081 -H "Content-Type: application/json" -d "{
        \"method\": \"POST\",
        \"url\": \"/ingest\",
        \"body\": $body
    }")

    echo "📋 Response:"
    echo "$response" | python -m json.tool 2>/dev/null || echo "$response"

    # Extract next token for next iteration
    next_token=$(echo "$response" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    if 'body' in data and 'next' in data['body']:
        next_val = data['body']['next']
        if next_val != '0' and next_val is not None:
            print(next_val)
except:
    pass
" 2>/dev/null)

    echo "🔗 Next token for workflow: '$next_token'"
    echo ""

    # Return next token
    echo "$next_token"
}

# Start workflow simulation
echo "🚀 Starting workflow simulation..."
next_token=""
iteration=1

# Continue until we get next="0" or empty next token
while true; do
    if [ $iteration -gt 10 ]; then
        echo "⚠️  Stopping after 10 iterations for safety"
        break
    fi

    next_token=$(make_api_call "$next_token" $iteration)

    if [ -z "$next_token" ] || [ "$next_token" == "0" ]; then
        echo "✅ Workflow complete - next token is empty or '0'"
        break
    fi

    iteration=$((iteration + 1))
    echo "⏳ Waiting 2 seconds before next iteration..."
    sleep 2
done

echo "🏁 Workflow simulation complete!"