# Testing Framework for Anomali IOC Ingestion

This directory contains a comprehensive testing framework for validating the Anomali ThreatStream IOC ingestion function, with particular focus on the intelligent threat intelligence deduplication feature.

## Test Files Overview

### Unit Tests

#### `test_duplicate_logic.py`
Validates the core deduplication logic that preserves most recent threat intelligence.

**Usage:**
```bash
source .venv/bin/activate
python test_duplicate_logic.py
```

**What it tests:**
- Demonstrates difference between old logic (keep='first') vs new logic (keep='last')
- Shows real-world IOC evolution scenarios
- Validates STIX 2.1 compliant temporal precedence

#### `test_fresh_start.py`
Tests initial function behavior when no existing lookup files are present.

**Usage:**
```bash
source .venv/bin/activate
python test_fresh_start.py
```

**Requirements:**
- Function server running on localhost:8081
- No existing Anomali lookup files in NGSIEM

#### `test_pagination.py`
Validates file growth behavior during pagination calls.

**Usage:**
```bash
source .venv/bin/activate
python test_pagination.py
```

**Requirements:**
- Function server running on localhost:8081
- `/tmp/next_token.txt` file with valid pagination token

### Integration Tests

#### `direct_workflow_test.sh`
Simulates exact Foundry workflow behavior for end-to-end validation.

**Usage:**
```bash
chmod +x direct_workflow_test.sh
./direct_workflow_test.sh
```

**What it tests:**
- Initial call behavior (job creation)
- Pagination call behavior (token usage)
- Proper workflow termination conditions

#### `comprehensive_stress_test.sh`
Tests interruption and resumption scenarios at various iteration counts.

**Usage:**
```bash
chmod +x comprehensive_stress_test.sh
./comprehensive_stress_test.sh
```

**What it tests:**
- Mid-stream workflow interruptions
- State persistence across interruptions
- Resumption from saved state
- Multiple iteration scenarios (5, 20, 30 iterations)

#### `interruption_stress_test.sh`
Advanced workflow interruption testing with detailed analysis.

**Usage:**
```bash
chmod +x interruption_stress_test.sh
./interruption_stress_test.sh
```

**What it tests:**
- Comprehensive interruption scenarios
- Fresh start recovery behavior
- Token-based resumption validation

## Running the Complete Test Suite

### Prerequisites
1. **Virtual Environment**: Activate the Python virtual environment
2. **Environment Variables**: Set up required credentials (see main.py for details)
3. **Function Server**: Start the function server on localhost:8081
4. **Clean State**: Ensure no existing Anomali lookup files for fresh testing

### Test Sequence
```bash
# 1. Start with unit tests (no server required)
source .venv/bin/activate
python test_duplicate_logic.py

# 2. Start function server (in separate terminal)
# Set environment variables first, then:
# python main.py

# 3. Run integration tests
python test_fresh_start.py
python test_pagination.py
./direct_workflow_test.sh

# 4. Run stress tests
./comprehensive_stress_test.sh
./interruption_stress_test.sh
```

## Key Validation Points

### ✅ Expected Behaviors
- **Fresh Start**: Creates new lookup files for all IOC types
- **File Growth**: Files consistently grow with new unique IOCs during pagination
- **Deduplication**: Preserves most recent threat intelligence (higher confidence, current classifications)
- **Pagination**: Proper next token management and workflow termination
- **Interruption Recovery**: Successful resumption after mid-stream interruptions

### ❌ Problematic Behaviors
- Files not growing during pagination (indicates deduplication issues)
- Inconsistent next token behavior
- Failed resumption after interruptions
- Loss of updated threat intelligence data

## Environment Setup

### Required Environment Variables
```bash
export APP_ID=your_app_id
export FALCON_CLIENT_ID=your_client_id
export FALCON_CLIENT_SECRET=your_client_secret
export CS_CLOUD=us-2  # or your appropriate cloud
```

### Virtual Environment
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Threat Intelligence Testing Notes

### IOC Evolution Scenarios
The tests validate handling of IOC intelligence that evolves over time:

1. **Initial Detection**: Low confidence, generic classification
2. **Analysis Phase**: Medium confidence, specific threat type
3. **Attribution Phase**: High confidence, APT group association
4. **Active Threat**: Highest confidence, active C2 classification

### STIX 2.1 Compliance
The deduplication logic implements temporal precedence as specified in STIX 2.1:
- Most recent intelligence takes precedence
- Confidence scores reflect current analysis
- Threat classifications represent latest understanding
- Tags include complete attribution chain

## Troubleshooting

### Common Issues
1. **403 Errors**: Check APP_ID and client credentials
2. **Empty Responses**: Verify CS_CLOUD environment setting
3. **Test Failures**: Ensure clean state (no existing lookup files)
4. **Pagination Issues**: Check function server logs for errors

### Debug Mode
Enable debug logging by setting log level in main.py or using function debugging features.

## Contributing

When adding new tests:
1. Follow existing naming conventions
2. Include comprehensive docstrings
3. Add validation for both success and failure scenarios
4. Update this README with new test descriptions

## Historical Context

This testing framework was developed to validate the intelligent threat intelligence deduplication feature that ensures security analysts receive the most current IOC data rather than outdated intelligence. The comprehensive test suite prevents regression and validates the STIX 2.1 compliant approach to temporal precedence in threat intelligence handling.