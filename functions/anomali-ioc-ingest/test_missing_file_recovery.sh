#!/bin/bash

echo "🔄 Missing File Recovery Test"
echo "This test verifies the function can detect and recover from missing lookup files"
echo ""

echo "=== STEP 1: Baseline State Check ==="
echo "📞 Making call to check current files..."

response1=$(curl -s -X POST http://localhost:8081 \
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

echo "📋 Baseline Response:"
echo "$response1" | python -c "
import json, sys
data = json.load(sys.stdin)
upload_results = data.get('body', {}).get('upload_results', [])
print('Current lookup files created:')
for result in upload_results:
    print(f'  ✅ {result.get(\"file\")} - {result.get(\"status\")}')
print(f'Total files: {len(upload_results)}')
print('Job ID:', data.get('body', {}).get('job_id'))
print('Next token:', data.get('body', {}).get('next'))
print('Message:', data.get('body', {}).get('message'))
"

echo ""
echo "🗑️  Now manually delete 'anomali_threatstream_domain.csv' from NGSIEM"
echo "⏳ Then press Enter to continue testing..."
read -p ""

echo ""
echo "=== STEP 2: Recovery Test After File Deletion ==="
echo "📞 Making fresh call to test missing file recovery..."

response2=$(curl -s -X POST http://localhost:8081 \
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

echo "📋 Recovery Response:"
echo "$response2" | python -c "
import json, sys
data = json.load(sys.stdin)
upload_results = data.get('body', {}).get('upload_results', [])
print('Files recreated after deletion:')
for result in upload_results:
    print(f'  ✅ {result.get(\"file\")} - {result.get(\"status\")}')
print(f'Total files: {len(upload_results)}')
print('Job ID:', data.get('body', {}).get('job_id'))
print('Next token:', data.get('body', {}).get('next'))
print('Files with new data:', data.get('body', {}).get('process_stats', {}).get('files_with_new_data'))
print('Message:', data.get('body', {}).get('message'))
"

echo ""
echo "🔍 Analysis:"
echo "✅ Expected behavior after deleting anomali_threatstream_domain.csv:"
echo "   1. Function detects missing file during download phase"
echo "   2. Clears update_id for that file type to force fresh start"
echo "   3. Recreates the missing file with current data"
echo "   4. Updates collections with new state"
echo "   5. Returns valid next token to continue pagination"

echo ""
echo "🏁 Missing File Recovery Test Complete!"