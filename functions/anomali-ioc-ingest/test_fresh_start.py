#!/usr/bin/env python3
"""Test fresh start with corrected duplicate detection logic"""

import json
import requests

def test_fresh_start():
    print("=== FRESH START TEST (Corrected Duplicate Logic) ===")

    # Make initial call to fresh system
    response = requests.post("http://localhost:8081", json={
        "method": "POST",
        "url": "/ingest",
        "body": {
            "repository": "search-all",
            "status": "active",
            "limit": 30
        }
    })

    if response.status_code != 200:
        print(f"❌ Request failed: {response.status_code} - {response.text}")
        return

    data = response.json()

    print(f"Total IOCs processed: {data.get('body', {}).get('total_iocs', 0)}")
    print(f"Files created: {data.get('body', {}).get('files_created', 0)}")

    # Show upload results
    upload_results = data.get('body', {}).get('upload_results', [])
    print(f"New files uploaded: {len(upload_results)}")
    for result in upload_results:
        print(f"  ✅ {result.get('file', 'unknown')}: {result.get('status', 'unknown')}")

    # Show process stats
    process_stats = data.get('body', {}).get('process_stats', {})
    print(f"\nProcess statistics:")
    print(f"  - Total new IOCs: {process_stats.get('total_new_iocs', 0)}")
    print(f"  - Files with new data: {process_stats.get('files_with_new_data', 0)}")
    print(f"  - Duplicates removed: {process_stats.get('total_duplicates_removed', 0)}")

    next_token = data.get('body', {}).get('next', '0')
    print(f"\nNext token for pagination: {next_token}")

    job_id = data.get('body', {}).get('job_id', 'unknown')
    print(f"Job ID: {job_id}")

    # Save next token for pagination test
    if next_token and next_token != '0':
        with open('/tmp/next_token.txt', 'w') as f:
            f.write(next_token)
        print(f"\n🔄 More data available - saved token for pagination test")
        return next_token
    else:
        print(f"\n✅ No more data available - fresh start complete")
        return None

if __name__ == "__main__":
    test_fresh_start()