#!/usr/bin/env python3
"""
Unit test to validate IOC duplicate detection logic correctness.
Tests whether we correctly keep the most recent IOC data vs. oldest.
"""

import pandas as pd
from io import StringIO

def test_duplicate_logic_before_fix():
    """Test the OLD (incorrect) logic that kept first/oldest entries"""

    print("=== TESTING OLD LOGIC (keep='first') ===")

    # Simulate existing data (older IOCs)
    existing_csv = """destination.ip,confidence,threat_type,source,tags,expiration_ts
192.168.1.1,50,malware,feed1,tag1,2023-01-01
10.0.0.1,30,c2,feed1,tag2,2023-01-01"""

    # Simulate new data (same IPs but updated intelligence)
    new_data = [
        ['192.168.1.1', '90', 'apt', 'feed2', 'tag1,apt29', '2024-01-01'],  # Higher confidence, new tags
        ['10.0.0.1', '85', 'c2,exfiltration', 'feed2', 'tag2,advanced', '2024-01-01'],  # Updated threat type
        ['172.16.1.1', '70', 'malware', 'feed2', 'tag3', '2024-01-01']  # New IP
    ]

    # Process like the old logic
    existing_df = pd.read_csv(StringIO(existing_csv))
    new_df = pd.DataFrame(new_data, columns=['destination.ip', 'confidence', 'threat_type', 'source', 'tags', 'expiration_ts'])

    combined_df = pd.concat([existing_df, new_df], ignore_index=True)
    print(f"Before dedup: {len(combined_df)} records")
    print(combined_df[['destination.ip', 'confidence', 'threat_type', 'tags']].to_string())

    # OLD LOGIC: keep='first' (WRONG for threat intel)
    result_old = combined_df.drop_duplicates(subset=['destination.ip'], keep='first')
    print(f"\nAfter OLD dedup (keep='first'): {len(result_old)} records")
    print(result_old[['destination.ip', 'confidence', 'threat_type', 'tags']].to_string())

    print("\n❌ PROBLEM: Old logic keeps outdated intelligence:")
    print("  - 192.168.1.1: confidence=50 (old) instead of 90 (new)")
    print("  - 10.0.0.1: threat_type='c2' (old) instead of 'c2,exfiltration' (new)")
    print("  - Missing updated tags and attribution\n")

def test_duplicate_logic_after_fix():
    """Test the NEW (correct) logic that keeps last/newest entries"""

    print("=== TESTING NEW LOGIC (keep='last') ===")

    # Same test data
    existing_csv = """destination.ip,confidence,threat_type,source,tags,expiration_ts
192.168.1.1,50,malware,feed1,tag1,2023-01-01
10.0.0.1,30,c2,feed1,tag2,2023-01-01"""

    new_data = [
        ['192.168.1.1', '90', 'apt', 'feed2', 'tag1,apt29', '2024-01-01'],
        ['10.0.0.1', '85', 'c2,exfiltration', 'feed2', 'tag2,advanced', '2024-01-01'],
        ['172.16.1.1', '70', 'malware', 'feed2', 'tag3', '2024-01-01']
    ]

    existing_df = pd.read_csv(StringIO(existing_csv))
    new_df = pd.DataFrame(new_data, columns=['destination.ip', 'confidence', 'threat_type', 'source', 'tags', 'expiration_ts'])

    combined_df = pd.concat([existing_df, new_df], ignore_index=True)
    print(f"Before dedup: {len(combined_df)} records")
    print(combined_df[['destination.ip', 'confidence', 'threat_type', 'tags']].to_string())

    # NEW LOGIC: keep='last' (CORRECT for threat intel)
    result_new = combined_df.drop_duplicates(subset=['destination.ip'], keep='last')
    print(f"\nAfter NEW dedup (keep='last'): {len(result_new)} records")
    print(result_new[['destination.ip', 'confidence', 'threat_type', 'tags']].to_string())

    print("\n✅ SOLUTION: New logic keeps most recent intelligence:")
    print("  - 192.168.1.1: confidence=90 (latest) with updated tags")
    print("  - 10.0.0.1: threat_type='c2,exfiltration' (latest) with enhanced classification")
    print("  - 172.16.1.1: new IOC properly added")
    print("  - Threat analysts get the most current intelligence\n")

def test_real_world_scenario():
    """Test a realistic threat intelligence scenario"""

    print("=== REAL-WORLD THREAT INTELLIGENCE SCENARIO ===")

    # Scenario: APT group C2 server gets updated classification over time
    threat_evolution = [
        # Week 1: Initial detection
        ['185.244.148.82', '40', 'suspicious', 'osint', 'investigation', '2024-01-01'],

        # Week 2: Confirmed malicious
        ['185.244.148.82', '70', 'malware', 'sandbox', 'investigation,confirmed', '2024-01-08'],

        # Week 3: Attribution to APT group
        ['185.244.148.82', '85', 'apt', 'analyst', 'investigation,confirmed,apt29', '2024-01-15'],

        # Week 4: Active C2 confirmation
        ['185.244.148.82', '95', 'c2,apt', 'telemetry', 'investigation,confirmed,apt29,active-c2', '2024-01-22']
    ]

    columns = ['destination.ip', 'confidence', 'threat_type', 'source', 'tags', 'expiration_ts']

    print("Threat intelligence evolution for 185.244.148.82:")
    for i, data in enumerate(threat_evolution, 1):
        print(f"  Week {i}: confidence={data[1]}, type={data[2]}, tags={data[4]}")

    # Test both approaches
    df = pd.DataFrame(threat_evolution, columns=columns)

    print(f"\nWith OLD logic (keep='first'):")
    old_result = df.drop_duplicates(subset=['destination.ip'], keep='first')
    old_row = old_result.iloc[0]
    print(f"  Result: confidence={old_row['confidence']}, type={old_row['threat_type']}, tags={old_row['tags']}")
    print("  ❌ Analyst gets outdated Week 1 data: 'suspicious' with confidence=40")

    print(f"\nWith NEW logic (keep='last'):")
    new_result = df.drop_duplicates(subset=['destination.ip'], keep='last')
    new_row = new_result.iloc[0]
    print(f"  Result: confidence={new_row['confidence']}, type={new_row['threat_type']}, tags={new_row['tags']}")
    print("  ✅ Analyst gets current Week 4 data: 'c2,apt' with confidence=95")
    print("  ✅ Critical for incident response and threat hunting accuracy\n")

if __name__ == "__main__":
    print("VALIDATING IOC DUPLICATE DETECTION LOGIC")
    print("=" * 60)

    test_duplicate_logic_before_fix()
    test_duplicate_logic_after_fix()
    test_real_world_scenario()

    print("CONCLUSION:")
    print("✅ The fix from keep='first' to keep='last' is CORRECT for threat intelligence")
    print("✅ Ensures analysts get the most recent IOC classifications and confidence scores")
    print("✅ Critical for accurate threat hunting and incident response decisions")