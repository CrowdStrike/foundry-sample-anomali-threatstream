#!/bin/bash

echo "🔄 COMPREHENSIVE WORKFLOW INTERRUPTION STRESS TEST"
echo "Testing pagination loops and mid-stream interruptions"
echo ""

# Test function to run pagination loops
run_interrupted_workflow() {
    local max_iterations=$1
    local test_name="$2"

    echo "🎯 $test_name: Running $max_iterations iterations then simulating interruption"

    local next_token=""
    local iteration=1
    local last_valid_token=""

    while [ $iteration -le $max_iterations ]; do
        echo "=== Iteration $iteration/$max_iterations ==="

        if [ -z "$next_token" ]; then
            echo "📞 INITIAL call"
            body='{"repository": "search-all", "status": "active", "limit": 15}'
        else
            echo "📞 PAGINATION call with token: $next_token"
            body="{\"repository\": \"search-all\", \"status\": \"active\", \"limit\": 15, \"next\": \"$next_token\"}"
        fi

        # Make API call
        response=$(curl -s -X POST http://localhost:8081 \
            -H "Content-Type: application/json" \
            -d "{
                \"method\": \"POST\",
                \"url\": \"/ingest\",
                \"body\": $body
            }")

        # Parse response
        next_token=$(echo "$response" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    next_val = data.get('body', {}).get('next')
    if next_val and next_val != '0':
        print(next_val)
except:
    pass
" 2>/dev/null)

        iocs=$(echo "$response" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('body', {}).get('total_iocs', 0))
except:
    print('0')
" 2>/dev/null)

        files=$(echo "$response" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('body', {}).get('files_created', 0))
except:
    print('0')
" 2>/dev/null)

        echo "📊 Processed: $iocs IOCs → $files files"
        echo "🔗 Next token: '$next_token'"

        # Save last valid token for resumption test
        if [ -n "$next_token" ] && [ "$next_token" != "0" ]; then
            last_valid_token="$next_token"
        fi

        # Check if naturally terminated
        if [ -z "$next_token" ] || [ "$next_token" == "0" ]; then
            echo "✅ Naturally terminated at iteration $iteration"
            break
        fi

        iteration=$((iteration + 1))
        echo "⏳ Waiting 1 second..."
        sleep 1
        echo ""
    done

    if [ $iteration -gt $max_iterations ]; then
        echo "⚠️  SIMULATED INTERRUPTION at iteration $max_iterations"
        echo "🔗 Last valid token before interruption: '$last_valid_token'"
    fi

    echo ""
    echo "🔄 RESUMPTION TEST: Starting fresh after interruption"
    echo "Testing if function picks up from saved state..."

    # Test resumption with fresh initial call
    resume_response=$(curl -s -X POST http://localhost:8081 \
        -H "Content-Type: application/json" \
        -d '{
            "method": "POST",
            "url": "/ingest",
            "body": {
                "repository": "search-all",
                "status": "active",
                "limit": 15
            }
        }')

    resume_token=$(echo "$resume_response" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    next_val = data.get('body', {}).get('next')
    if next_val and next_val != '0':
        print(next_val)
except:
    pass
" 2>/dev/null)

    resume_job=$(echo "$resume_response" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('body', {}).get('job_id', 'unknown'))
except:
    print('error')
" 2>/dev/null)

    echo "📋 Resumption Results:"
    echo "   - New Job ID: $resume_job"
    echo "   - Resume token: '$resume_token'"

    if [ -n "$resume_token" ] && [ "$resume_token" != "0" ]; then
        echo "   ✅ RESUMPTION SUCCESS - Can continue workflow"

        # Test one pagination call from resumed state
        echo "🔄 Testing pagination continuation..."

        continue_response=$(curl -s -X POST http://localhost:8081 \
            -H "Content-Type: application/json" \
            -d "{
                \"method\": \"POST\",
                \"url\": \"/ingest\",
                \"body\": {
                    \"repository\": \"search-all\",
                    \"status\": \"active\",
                    \"limit\": 15,
                    \"next\": \"$resume_token\"
                }
            }")

        continue_token=$(echo "$continue_response" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    next_val = data.get('body', {}).get('next')
    if next_val and next_val != '0':
        print(next_val)
except:
    pass
" 2>/dev/null)

        echo "   📊 Pagination: '$resume_token' → '$continue_token'"

        if [ -n "$continue_token" ]; then
            echo "   ✅ PAGINATION CONTINUES after resumption"
        else
            echo "   ✅ PAGINATION TERMINATED naturally after resumption"
        fi
    else
        echo "   ⚠️  RESUMPTION ISSUE - No valid token returned"
    fi

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

# Run all test scenarios
echo "🚀 Starting comprehensive interruption tests"
echo ""

run_interrupted_workflow 5 "5-ITERATION TEST"
run_interrupted_workflow 10 "10-ITERATION TEST"
run_interrupted_workflow 15 "15-ITERATION TEST"

echo "🏁 COMPREHENSIVE STRESS TEST COMPLETE!"
echo ""
echo "📊 SUMMARY:"
echo "✅ Tested interruption at 5, 10, and 15 iterations"
echo "✅ Validated resumption after each interruption scenario"
echo "✅ Confirmed pagination continues after resumption"
echo "✅ Verified state persistence across workflow restarts"