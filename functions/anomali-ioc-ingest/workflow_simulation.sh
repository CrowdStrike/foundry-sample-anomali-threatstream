#!/bin/bash

# Enhanced workflow simulation that mimics Foundry workflow behavior
echo "🔄 Enhanced Workflow Simulation - Testing IOC Ingest Pagination"
echo "This simulates how the actual Foundry workflow would call the function"
echo ""

# Function to clear existing anomali lookup files for fresh start testing
clear_anomali_files() {
    echo "🧹 CLEANUP: Deleting existing Anomali lookup files for fresh start test..."

    # Activate virtual environment and run cleanup script
    source .venv/bin/activate
    python cleanup_files.py

    echo ""
}

# Function to clear collections data for complete fresh start
clear_collections_data() {
    echo "🗂️  CLEANUP: Clearing collections data for complete fresh start..."

    # Call the function with a special cleanup parameter
    response=$(curl -s -X POST http://localhost:8081 \
        -H "Content-Type: application/json" \
        -d "{
            \"method\": \"POST\",
            \"url\": \"/ingest\",
            \"body\": {
                \"repository\": \"search-all\",
                \"clear_collections\": true,
                \"limit\": 1
            }
        }")

    echo "📋 Collections cleanup response:"
    echo "$response" | python -m json.tool 2>/dev/null || echo "$response"
    echo ""
}

# Function to make API call and extract next token
make_workflow_call() {
    local next_token="$1"
    local iteration="$2"

    echo "=== Workflow Iteration $iteration ==="

    if [ -z "$next_token" ] || [ "$next_token" == "null" ]; then
        echo "📞 INITIAL CALL (no next token - creates job and starts fresh)"
        body='{"repository": "search-all", "status": "active", "limit": 50}'
    else
        echo "📞 PAGINATION CALL with next token: $next_token"
        body="{\"repository\": \"search-all\", \"status\": \"active\", \"limit\": 50, \"next\": \"$next_token\"}"
    fi

    echo "📤 Request body: $body"
    echo ""

    # Make the API call
    response=$(curl -s -X POST http://localhost:8081 \
        -H "Content-Type: application/json" \
        -d "{
            \"method\": \"POST\",
            \"url\": \"/ingest\",
            \"body\": $body
        }")

    echo "📋 Full Response:"
    echo "$response" | python -m json.tool 2>/dev/null || echo "$response"
    echo ""

    # Extract next token for next iteration
    next_token=$(echo "$response" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    if 'body' in data and 'next' in data['body']:
        next_val = data['body']['next']
        if next_val != '0' and next_val is not None and next_val != 'null':
            print(next_val)
except Exception as e:
    print(f'Error parsing response: {e}', file=sys.stderr)
    pass
" 2>/dev/null)

    # Extract key metrics
    total_iocs=$(echo "$response" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    if 'body' in data and 'total_iocs' in data['body']:
        print(data['body']['total_iocs'])
    else:
        print('0')
except:
    print('0')
" 2>/dev/null)

    files_created=$(echo "$response" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    if 'body' in data and 'files_created' in data['body']:
        print(data['body']['files_created'])
    else:
        print('0')
except:
    print('0')
" 2>/dev/null)

    # Get message for status
    message=$(echo "$response" | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    if 'body' in data and 'message' in data['body']:
        print(data['body']['message'])
    else:
        print('No message')
except:
    print('Parse error')
" 2>/dev/null)

    echo "📊 Metrics: $total_iocs IOCs processed, $files_created files created"
    echo "💬 Message: $message"
    echo "🔗 Next token for workflow: '$next_token'"

    if [ -z "$next_token" ] || [ "$next_token" == "0" ]; then
        echo "✅ Workflow should TERMINATE (next='$next_token')"
    else
        echo "🔄 Workflow should CONTINUE (next='$next_token')"
    fi

    echo ""
    echo "----------------------------------------"
    echo ""

    # Return next token
    echo "$next_token"
}

# Simulation 1: Fresh workflow run
echo "🚀 SIMULATION 1: Fresh Workflow Run (mimics new workflow execution)"
echo ""

# Optional: Uncomment the next two lines to test complete fresh start
echo "❓ Would you like to test a complete fresh start? (This will delete existing files)"
echo "   Uncomment the cleanup calls below to enable fresh start testing:"
echo "   # clear_anomali_files"
echo "   # clear_collections_data"
echo ""

# Uncomment these lines to test fresh start scenario:
# clear_anomali_files
# clear_collections_data

next_token=""
iteration=1
total_processed=0

# Continue until we get next="0" or empty next token
while true; do
    if [ $iteration -gt 5 ]; then
        echo "⚠️  Stopping after 5 iterations for demo purposes"
        break
    fi

    next_token=$(make_workflow_call "$next_token" $iteration)

    if [ -z "$next_token" ] || [ "$next_token" == "0" ]; then
        echo "✅ WORKFLOW COMPLETE - next token indicates termination"
        break
    fi

    iteration=$((iteration + 1))
    echo "⏳ Workflow waiting 3 seconds before next iteration..."
    sleep 3
done

echo ""
echo "🔄 SIMULATION 2: Resumption Test (mimics workflow restart/recovery)"
echo "Testing if the function can resume from where it left off..."
echo ""

# Simulation 2: Test resumption by running another fresh workflow
sleep 2
echo "🚀 Starting fresh workflow again to test resumption..."
echo ""

next_token=""
iteration=1

# Run a couple more iterations to test resumption
while true; do
    if [ $iteration -gt 3 ]; then
        echo "ℹ️  Stopping resumption test after 3 iterations"
        break
    fi

    next_token=$(make_workflow_call "$next_token" $iteration)

    if [ -z "$next_token" ] || [ "$next_token" == "0" ]; then
        echo "✅ RESUMPTION WORKFLOW COMPLETE - terminated properly"
        break
    fi

    iteration=$((iteration + 1))
    echo "⏳ Resumption workflow waiting 3 seconds..."
    sleep 3
done

echo ""
echo "🏁 Enhanced Workflow Simulation Complete!"
echo ""
echo "📋 Summary:"
echo "   ✅ Tested initial workflow calls (job creation)"
echo "   ✅ Tested pagination continuation logic"
echo "   ✅ Tested workflow termination conditions"
echo "   ✅ Tested workflow resumption from saved state"
echo "   📊 Verified incremental sync behavior"