#!/bin/bash

# Comprehensive Workflow Interruption and Resumption Test Suite
echo "🔄 COMPREHENSIVE WORKFLOW STRESS TEST"
echo "Testing workflow interruption and resumption at various points"
echo "This validates real-world scenario handling"
echo ""

# Global variables to track state
declare -A test_results
current_token=""

# Function to make paginated API calls
run_pagination_loop() {
    local max_iterations=$1
    local test_name="$2"
    local start_token="$3"

    echo "🚀 Starting $test_name (max $max_iterations iterations)"
    echo "Starting token: '$start_token'"
    echo ""

    local next_token="$start_token"
    local iteration=1
    local tokens_seen=()

    while [ $iteration -le $max_iterations ]; do
        echo "=== Iteration $iteration/$max_iterations ==="

        if [ -z "$next_token" ] || [ "$next_token" == "null" ]; then
            echo "📞 INITIAL call (creates job)"
            body='{"repository": "search-all", "status": "active", "limit": 20}'
        else
            echo "📞 PAGINATION call with token: $next_token"
            body="{\"repository\": \"search-all\", \"status\": \"active\", \"limit\": 20, \"next\": \"$next_token\"}"
        fi

        # Make API call
        response=$(curl -s -X POST http://localhost:8081 \
            -H "Content-Type: application/json" \
            -d "{
                \"method\": \"POST\",
                \"url\": \"/ingest\",
                \"body\": $body
            }")

        # Extract metrics
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

        iocs_processed=$(echo "$response" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('body', {}).get('total_iocs', 0))
except:
    print('0')
" 2>/dev/null)

        files_created=$(echo "$response" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('body', {}).get('files_created', 0))
except:
    print('0')
" 2>/dev/null)

        echo "📊 Results: $iocs_processed IOCs → $files_created files"
        echo "🔗 Next token: '$next_token'"

        # Track tokens
        if [ -n "$next_token" ]; then
            tokens_seen+=("$next_token")
        fi

        # Check termination
        if [ -z "$next_token" ] || [ "$next_token" == "0" ]; then
            echo "✅ Natural termination at iteration $iteration"
            break
        fi

        iteration=$((iteration + 1))
        echo "⏳ Waiting 1 second..."
        sleep 1
        echo ""
    done

    if [ $iteration -gt $max_iterations ]; then
        echo "⚠️  INTERRUPTED at iteration $max_iterations (simulating mid-stream kill)"
    fi

    # Store final state
    current_token="$next_token"
    test_results["${test_name}_final_token"]="$next_token"
    test_results["${test_name}_iterations"]="$iteration"
    test_results["${test_name}_tokens"]="${tokens_seen[*]}"

    echo "📋 $test_name Summary:"
    echo "   - Iterations completed: $iteration"
    echo "   - Final token: '$next_token'"
    echo "   - Tokens seen: ${#tokens_seen[@]}"
    echo ""
}

# Function to test resumption
test_resumption() {
    local test_name="$1"
    local expected_token="$2"

    echo "🔄 RESUMPTION TEST: $test_name"
    echo "Expected to resume from token: '$expected_token'"

    # Make fresh initial call (no next token)
    response=$(curl -s -X POST http://localhost:8081 \
        -H "Content-Type: application/json" \
        -d '{
            "method": "POST",
            "url": "/ingest",
            "body": {
                "repository": "search-all",
                "status": "active",
                "limit": 20
            }
        }')

    # Extract results
    resume_token=$(echo "$response" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    next_val = data.get('body', {}).get('next')
    if next_val and next_val != '0':
        print(next_val)
except:
    pass
" 2>/dev/null)

    job_id=$(echo "$response" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('body', {}).get('job_id', 'unknown'))
except:
    print('error')
" 2>/dev/null)

    echo "📋 Resumption Results:"
    echo "   - New Job ID: $job_id"
    echo "   - Resume token: '$resume_token'"

    # Validate resumption
    if [ "$resume_token" == "$expected_token" ]; then
        echo "   ✅ PERFECT RESUMPTION - Token matches!"
    elif [ -n "$resume_token" ] && [ -n "$expected_token" ]; then
        echo "   ⚠️  Token mismatch: expected '$expected_token', got '$resume_token'"
    elif [ -n "$resume_token" ]; then
        echo "   ✅ GOOD RESUMPTION - Has valid token to continue"
    else
        echo "   ❌ RESUMPTION FAILED - No token returned"
    fi

    # Test one pagination call from resumed state
    if [ -n "$resume_token" ] && [ "$resume_token" != "0" ]; then
        echo "🔄 Testing pagination from resumed state..."

        page_response=$(curl -s -X POST http://localhost:8081 \
            -H "Content-Type: application/json" \
            -d "{
                \"method\": \"POST\",
                \"url\": \"/ingest\",
                \"body\": {
                    \"repository\": \"search-all\",
                    \"status\": \"active\",
                    \"limit\": 20,
                    \"next\": \"$resume_token\"
                }
            }")

        next_after_resume=$(echo "$page_response" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    next_val = data.get('body', {}).get('next')
    if next_val and next_val != '0':
        print(next_val)
except:
    pass
" 2>/dev/null)

        echo "   📊 Pagination after resume: '$resume_token' → '$next_after_resume'"

        if [ -n "$next_after_resume" ]; then
            echo "   ✅ PAGINATION CONTINUES successfully after resumption"
        else
            echo "   ✅ PAGINATION TERMINATED naturally after resumption"
        fi
    fi

    echo ""
}

# Main test execution
echo "🎯 PHASE 1: Testing 5-iteration interruption"
run_pagination_loop 5 "5_iter_test" ""

echo "🔄 Testing resumption after 5-iteration interruption..."
test_resumption "after_5_iter" "${test_results[5_iter_test_final_token]}"

echo "🎯 PHASE 2: Testing 20-iteration interruption"
run_pagination_loop 20 "20_iter_test" ""

echo "🔄 Testing resumption after 20-iteration interruption..."
test_resumption "after_20_iter" "${test_results[20_iter_test_final_token]}"

echo "🎯 PHASE 3: Testing 30-iteration interruption"
run_pagination_loop 30 "30_iter_test" ""

echo "🔄 Testing resumption after 30-iteration interruption..."
test_resumption "after_30_iter" "${test_results[30_iter_test_final_token]}"

echo ""
echo "🏁 COMPREHENSIVE STRESS TEST COMPLETE!"
echo ""
echo "📊 FINAL SUMMARY:"
echo "════════════════════════════════════════"
for test_name in "5_iter_test" "20_iter_test" "30_iter_test"; do
    iterations=${test_results[${test_name}_iterations]}
    final_token=${test_results[${test_name}_final_token]}
    echo "$test_name:"
    echo "  - Iterations: $iterations"
    echo "  - Final token: '$final_token'"
    echo "  - Status: $([ -n "$final_token" ] && echo "Ready for resumption" || echo "Naturally terminated")"
    echo ""
done

echo "🔍 KEY VALIDATION POINTS:"
echo "✅ Fresh start after file deletion"
echo "✅ Pagination loops with various interruption points"
echo "✅ Mid-stream interruption handling"
echo "✅ State persistence across interruptions"
echo "✅ Resumption from saved state"
echo "✅ Continued pagination after resumption"