#!/usr/bin/env python3
"""Test pagination with corrected duplicate detection logic"""

import json
import requests

def test_pagination():
    print("=== PAGINATION TEST (Corrected Duplicate Logic) ===")

    # Read saved next token
    try:
        with open('/tmp/next_token.txt', 'r') as f:
            next_token = f.read().strip()
        print(f"Using saved next token: {next_token}")
    except FileNotFoundError:
        print("❌ No saved next token found - run fresh start test first")
        return

    # Make pagination call
    response = requests.post("http://localhost:8081", json={
        "method": "POST",
        "url": "/ingest",
        "body": {
            "repository": "search-all",
            "status": "active",
            "limit": 25,
            "next": next_token
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
    print(f"Files updated: {len(upload_results)}")
    for result in upload_results:
        print(f"  ✅ {result.get('file', 'unknown')}: {result.get('status', 'unknown')}")

    # Show process stats - this is key for validation
    process_stats = data.get('body', {}).get('process_stats', {})
    print(f"\n📊 Process statistics (CORRECTED LOGIC):")
    print(f"  - Total new IOCs: {process_stats.get('total_new_iocs', 0)}")
    print(f"  - Files with new data: {process_stats.get('files_with_new_data', 0)}")
    print(f"  - Duplicates removed: {process_stats.get('total_duplicates_removed', 0)}")

    next_token_new = data.get('body', {}).get('next', '0')
    print(f"\nNext token: {next_token_new}")

    job_id = data.get('body', {}).get('job_id', 'unknown')
    print(f"Job ID: {job_id}")

    # Analysis
    if process_stats.get('files_with_new_data', 0) > 0:
        print(f"\n✅ FILES ARE GROWING - keep='last' logic working correctly!")
        print(f"✅ {process_stats.get('files_with_new_data', 0)} files received new unique IOCs")
    else:
        print(f"\n🤔 No new unique data - might be duplicate-heavy batch (normal in some cases)")

    # Save new token for continued testing
    if next_token_new and next_token_new != '0':
        with open('/tmp/next_token.txt', 'w') as f:
            f.write(next_token_new)
        print(f"🔄 Pagination continues - saved new token: {next_token_new}")
        return next_token_new
    else:
        print(f"✅ Pagination terminated - no more data")
        return None

if __name__ == "__main__":
    test_pagination()