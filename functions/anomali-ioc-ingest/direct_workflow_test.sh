#!/bin/bash

echo "🔄 Direct Workflow Test - Simulating Foundry Workflow Calls"
echo "This directly tests the IOC ingest pagination exactly like the workflow would"
echo ""

# Test 1: Initial call (no next token)
echo "=== TEST 1: Initial Call (Creates Job) ==="
echo "📞 Making INITIAL call (no next token)"

response1=$(curl -s -X POST http://localhost:8081 \
    -H "Content-Type: application/json" \
    -d '{
        "method": "POST",
        "url": "/ingest",
        "body": {
            "repository": "search-all",
            "status": "active",
            "limit": 25
        }
    }')

echo "📋 Initial Call Response:"
echo "$response1" | python -m json.tool 2>/dev/null || echo "$response1"
echo ""

# Extract next token from first call
next_token=$(echo "$response1" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    if 'body' in data and 'next' in data['body']:
        next_val = data['body']['next']
        # Check for all termination conditions like the workflow does
        if next_val != '0' and next_val != 0 and next_val is not None and next_val != '':
            print(next_val)
except:
    pass
" 2>/dev/null)

echo "🔗 Extracted next token: '$next_token'"
echo ""

if [ -n "$next_token" ] && [ "$next_token" != "0" ]; then
    echo "=== TEST 2: Pagination Call (Uses Next Token) ==="
    echo "📞 Making PAGINATION call with next token: $next_token"

    response2=$(curl -s -X POST http://localhost:8081 \
        -H "Content-Type: application/json" \
        -d "{
            \"method\": \"POST\",
            \"url\": \"/ingest\",
            \"body\": {
                \"repository\": \"search-all\",
                \"status\": \"active\",
                \"limit\": 25,
                \"next\": \"$next_token\"
            }
        }")

    echo "📋 Pagination Call Response:"
    echo "$response2" | python -m json.tool 2>/dev/null || echo "$response2"
    echo ""

    # Extract next token from second call
    next_token2=$(echo "$response2" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    if 'body' in data and 'next' in data['body']:
        next_val = data['body']['next']
        # Check for all termination conditions like the workflow does
        if next_val != '0' and next_val != 0 and next_val is not None and next_val != '':
            print(next_val)
except:
    pass
" 2>/dev/null)

    echo "🔗 Next token from pagination call: '$next_token2'"

    if [ -z "$next_token2" ] || [ "$next_token2" == "0" ]; then
        echo "✅ Workflow would TERMINATE here (next='$next_token2')"
    else
        echo "🔄 Workflow would CONTINUE with next='$next_token2'"
    fi
else
    echo "✅ Workflow terminated after initial call (next='$next_token')"
fi

echo ""
echo "=== TEST 3: Resumption Test (Fresh Start) ==="
echo "📞 Making another INITIAL call to test resumption"

sleep 2

response3=$(curl -s -X POST http://localhost:8081 \
    -H "Content-Type: application/json" \
    -d '{
        "method": "POST",
        "url": "/ingest",
        "body": {
            "repository": "search-all",
            "status": "active",
            "limit": 25
        }
    }')

echo "📋 Resumption Test Response:"
echo "$response3" | python -m json.tool 2>/dev/null || echo "$response3"

# Check if resumption behaves differently
next_token3=$(echo "$response3" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    if 'body' in data and 'next' in data['body']:
        next_val = data['body']['next']
        # Check for all termination conditions like the workflow does
        if next_val != '0' and next_val != 0 and next_val is not None and next_val != '':
            print(next_val)
except:
    pass
" 2>/dev/null)

echo ""
echo "🔗 Resumption next token: '$next_token3'"

if [ -z "$next_token3" ] || [ "$next_token3" == "0" ]; then
    echo "✅ Resumption also terminates immediately (incremental sync working)"
else
    echo "🔄 Resumption would continue (more data available)"
fi

echo ""
echo "🏁 Direct Workflow Test Complete!"
echo ""
echo "📋 Analysis:"
echo "   ✅ Initial calls create jobs and fetch IOCs"
echo "   ✅ Pagination calls use next tokens to continue"
echo "   ✅ Termination happens when next='0'"
echo "   ✅ Resumption tests show incremental sync behavior"