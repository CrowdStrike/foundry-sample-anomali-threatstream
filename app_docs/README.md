# Anomali ThreatStream Next-Gen SIEM Connector

Provides automated threat intelligence ingestion from Anomali ThreatStream APIs into Falcon Next-Gen SIEM lookup files.

## Prerequisites

- **Subscriptions**: Falcon Foundry and Falcon Next-Gen SIEM
- **Access**: App Developer or Falcon Administrator role
- **Credentials**: Anomali ThreatStream API key

## Setup

### 1. Install App and Configure API
1. **Foundry > App catalog** → Search "Anomali ThreatStream Next-Gen SIEM Connector"
2. Click **Install** and enter your Anomali ThreatStream API credentials when prompted:
   - **API URL**: Your ThreatStream API endpoint (e.g., `https://api.threatstream.com`)
   - **API Key**: Your credentials in format `email:key`
3. Wait for installation to complete

### 2. Test Integration
1. **Fusion SOAR > Workflows** → Find `Anomali Threat Intelligence Ingest` workflow
2. Click **Execute** to trigger manual IOC ingestion
3. Monitor workflow execution logs and wait for completion
4. Verify data appears in **Next-Gen SIEM > Lookup files**:
   - Search for "anomali" to find uploaded lookup files
   - Look for files: `anomali_threatstream_ip.csv`, `anomali_threatstream_domain.csv`, `anomali_threatstream_url.csv`, `anomali_threatstream_email.csv`, `anomali_threatstream_hash_md5.csv` (and potentially SHA1/SHA256 variants)

## Usage

**Automated**: Hourly workflow `Anomali Threat Intelligence Ingest` runs in **Fusion SOAR > Workflows**

**Manual**: Execute function directly with optional parameters:
- `repository`: Target repository (default: "search-all")
- `status`: IOC status filter (default: "active")
- `feed_id`: Comma-separated Anomali feed IDs to filter ingestion (e.g., "0368,1390")
- `type`: IOC type filter for selective ingestion (options: "ip", "domain", "url", "email", "hash", "md5", "sha1", "sha256")
- `limit`: Number of records per API call (default: 1000, max: 1000)
- `confidence_gt`: Filter IOCs with confidence score greater than specified value (0-100)
- `confidence_gte`: Filter IOCs with confidence score greater than or equal to specified value (0-100)
- `confidence_lt`: Filter IOCs with confidence score less than specified value (0-100)
- `confidence_lte`: Filter IOCs with confidence score less than or equal to specified value (0-100)
- `fail_fast_enabled`: Enable early file size estimation to fail fast if projected size exceeds 200 MB limit (default: false)

### Filtering by Feed ID

To ingest IOCs from specific Anomali ThreatStream feeds, you can configure the `feed_id` parameter in the workflow using either the Falcon console or by editing the YAML directly.

#### Option 1: Edit Workflow via Foundry UI (Recommended)

1. **Navigate to App Manager**: Go to **Foundry > App manager**
2. **Open App Builder**: Find your app, click the three-dot menu, and select **Edit app**
3. **Access Logic Section**: In the left sidebar, click the **Logic** icon (lightbulb)
4. **Edit Workflow**: Click on **Anomali Threat Intelligence Ingest** workflow
5. **Configure First Action**:
   - Click on the **Anomali Ingest** action card
   - Update the `feed_id` field with your comma-separated feed IDs (e.g., `1234,2356`)
6. **Configure Loop Action**:
   - Click on the **Anomali Ingest - 2** action card
   - Add the same `feed_id` value 
   - Ensure this matches the first action's `feed_id` for consistent filtering
7. **Save Changes**: Click **Save and exit** in the top right

**Important**: Both `Anomali Ingest` and `Anomali Ingest - 2` actions must use the same `feed_id` value to ensure consistent filtering throughout pagination.

#### Option 2: Edit Workflow YAML Directly

Edit the workflow file `workflows/Anomali_Threat_Intelligence_Ingest.yml`:

```yaml
actions:
    AnomaliIngest:
        properties:
            feed_id: "0368,1390"  # Add your Anomali feed IDs
            limit: 1000
            repository: search-all
            status: active
```

Also update the loop action with the same `feed_id`:

```yaml
loops:
    Loop:
        actions:
            AnomaliIngest2:
                properties:
                    feed_id: "0368,1390"  # Must match AnomaliIngest feed_id
                    limit: 1000
                    next: ${data['WorkflowCustomVariable.next']}
                    repository: search-all
                    status: active
```

After editing the YAML, redeploy the app using `foundry apps deploy`.

**Finding Feed IDs**: Log into the [Anomali ThreatStream platform](https://ui.threatstream.com) and navigate to **Manage > Feeds** in the left sidebar to view your available feeds and their IDs.

### Filtering by Confidence Score

To ingest only IOCs that meet specific confidence thresholds, you can configure confidence filtering parameters in the workflow. Confidence scores in Anomali ThreatStream range from 0 to 100, where higher values indicate greater certainty that the indicator is malicious.

Available confidence parameters:
- `confidence_gt`: Filter IOCs with confidence score **greater than** specified value
- `confidence_gte`: Filter IOCs with confidence score **greater than or equal to** specified value
- `confidence_lt`: Filter IOCs with confidence score **less than** specified value
- `confidence_lte`: Filter IOCs with confidence score **less than or equal to** specified value

#### Option 1: Edit Workflow via Foundry UI (Recommended)

1. **Navigate to App Manager**: Go to **Foundry > App manager**
2. **Open App Builder**: Find your app, click the three-dot menu, and select **Edit app**
3. **Access Logic Section**: In the left sidebar, click the **Logic** icon (lightbulb)
4. **Edit Workflow**: Click on **Anomali Threat Intelligence Ingest** workflow
5. **Configure First Action**:
   - Click on the **Anomali Ingest** action card
   - Add a confidence filter field (e.g., `confidence_gte: 70` for high-confidence IOCs only)
6. **Configure Loop Action**:
   - Click on the **Anomali Ingest - 2** action card
   - Add the same confidence filter value
   - Ensure this matches the first action for consistent filtering
7. **Save Changes**: Click **Save and exit** in the top right

**Important**: Both `Anomali Ingest` and `Anomali Ingest - 2` actions must use the same confidence filter values to ensure consistent filtering throughout pagination.

#### Option 2: Edit Workflow YAML Directly

Edit the workflow file `workflows/Anomali_Threat_Intelligence_Ingest.yml`:

```yaml
actions:
    AnomaliIngest:
        properties:
            confidence_gte: 70  # Only ingest IOCs with confidence >= 70
            limit: 1000
            repository: search-all
            status: active
```

Also update the loop action with the same confidence filter:

```yaml
loops:
    Loop:
        actions:
            AnomaliIngest2:
                properties:
                    confidence_gte: 70  # Must match AnomaliIngest confidence filter
                    limit: 1000
                    next: ${data['WorkflowCustomVariable.next']}
                    repository: search-all
                    status: active
```

You can combine multiple confidence filters for range-based filtering:

```yaml
actions:
    AnomaliIngest:
        properties:
            confidence_gte: 50   # Minimum confidence of 50
            confidence_lt: 90    # Maximum confidence below 90
            limit: 1000
            repository: search-all
            status: active
```

After editing the YAML, redeploy the app using `foundry apps deploy`.

**Understanding Confidence Scores**: Anomali ThreatStream assigns confidence scores based on multiple factors including source reliability, corroboration from multiple feeds, and historical accuracy. A score of 70+ generally indicates high-confidence threat intelligence suitable for automated blocking, while scores below 50 may require additional investigation before taking action.

### Fail-Fast File Size Estimation

For large IOC datasets, the function can estimate final file sizes after processing the first batch of data. This prevents wasting hours on pagination only to fail at the end when a file exceeds the 200 MB Falcon Next-Gen SIEM upload limit.

**Parameter**: `fail_fast_enabled` (default: `false`)

When enabled, the function:
1. Processes the first batch of IOCs
2. Calculates bytes per record and distribution by IOC type
3. Projects final file sizes based on Anomali's `total_count` metadata
4. Fails immediately with actionable guidance if any file would exceed 200 MB

**When to Enable**: Enable fail-fast if you're ingesting a large ThreatStream dataset for the first time and want early feedback on whether filtering is needed.

**When to Disable**: Keep disabled (default) when you want the function to process as much data as possible before hitting limits, or when you're incrementally syncing smaller batches.

#### Configuring Fail-Fast in the Workflow

Edit the workflow file `workflows/Anomali_Threat_Intelligence_Ingest.yml`:

```yaml
actions:
    AnomaliIngest:
        properties:
            fail_fast_enabled: true  # Enable early file size validation
            limit: 1000
            repository: search-all
            status: active
```

Also update the loop action with the same setting:

```yaml
loops:
    Loop:
        actions:
            AnomaliIngest2:
                properties:
                    fail_fast_enabled: true  # Must match AnomaliIngest setting
                    limit: 1000
                    next: ${data['WorkflowCustomVariable.next']}
                    repository: search-all
                    status: active
```

**If fail-fast triggers**, the error message suggests filtering strategies:
1. Use `feed_id` to limit ingestion to specific threat feeds
2. Use `confidence_gte` to filter low-confidence IOCs (e.g., `confidence_gte: 70`)
3. Use `type` parameter to ingest specific IOC types separately

## Data Output

**IOC Types**: IP addresses, domains, URLs, email addresses, MD5/SHA1/SHA256 hashes

**ECS-Compliant Fields**: 
- IPs: `destination.ip`, confidence, threat_type, source, tags, expiration_ts
- Domains: `dns.domain.name`, confidence, threat_type, source, tags, expiration_ts
- URLs: `url.original`, confidence, threat_type, source, tags, expiration_ts
- Emails: `email.sender.address`, confidence, threat_type, source, tags, expiration_ts
- Hashes: `file.hash.md5/sha1/sha256`, confidence, threat_type, source, tags, expiration_ts

**Output Format**: CSV lookup files uploaded to Falcon Next-Gen SIEM repository for joining with host data

## Monitoring

**Function Logs**: View execution logs in **Advanced Event Search**:
```json
// Function execution logs (replace YOUR_FUNCTION_ID with actual function ID after deployment)
#event_simpleName=FunctionLogMessage | fn_id="YOUR_FUNCTION_ID"

// Workflow execution logs (replace YOUR_WORKFLOW_ID with actual workflow ID after deployment)
#event_simpleName=FusionWorkflowEvent | definition_id="YOUR_WORKFLOW_ID"
```

**Verify Lookup Files Work**: Test that lookup files are properly created and functional. The values in the first line of each query should match a value in the lookup file to see data.
```json
// Test IP lookup file 
| createEvents(["{\"fake\":\"event\", \"destination.ip\": \"23.98.23.98\"}"]) | parseJson()
| destination.ip=*
| match(file="anomali_threatstream_ip.csv", column=destination.ip, field=destination.ip, strict=true, include=[confidence, threat_type, source])

// Test domain lookup file
| createEvents(["{\"fake\":\"event\", \"DomainName\": \"gen1xyz.com\"}"]) | parseJson()
| DomainName=*
| match(file="anomali_threatstream_domain.csv", field=[DomainName], column=dns.domain.name, strict=true, include=[confidence, threat_type, source])

// Test email lookup file
| createEvents(["{\"fake\":\"event\", \"SenderAddress\": \"rfv4@edc.com\"}"]) | parseJson()
| SenderAddress=*
| match(file="anomali_threatstream_email.csv", field=[SenderAddress], column=email.sender.address, strict=true, include=[confidence, threat_type, source])
```

**Job Status**: Function includes `/jobs` endpoint to check ingestion job status and collections track incremental sync progress.

## Threat Intelligence Queries

**Join IOC Lookup Files with Host Events** (similar to Splunk Anomali App):

```json
// Detect malicious IP connections using lookup files
#event_simpleName=NetworkConnectIP4
| match(file="anomali_threatstream_ip.csv", field=[RemoteAddressIP4], column=[destination.ip])
| table([ComputerName, UserName, RemoteAddressIP4, threat_type, confidence, source])

// Detect malicious domain lookups using lookup files
#event_simpleName=DnsRequest
| match(file="anomali_threatstream_domain.csv", field=[DomainName], column=[dns.domain.name])
| table([ComputerName, UserName, DomainName, threat_type, confidence, source])

// Detect malicious file hashes using lookup files
#event_simpleName=ProcessRollup2
| match(file="anomali_threatstream_hash_md5.csv", field=[MD5HashData], column=[file.hash.md5])
| table([ComputerName, UserName, FileName, MD5HashData, threat_type, confidence, source])

// Detect malicious email addresses using lookup files
#event_simpleName=EmailMessage OR #event_simpleName=EmailDelivery
| match(file="anomali_threatstream_email.csv", field=[SenderAddress], column=[email.sender.address])
| table([ComputerName, UserName, SenderAddress, threat_type, confidence, source])

// Combined threat hunting across multiple IOC types
#event_simpleName=NetworkConnectIP4 OR #event_simpleName=DnsRequest OR #event_simpleName=ProcessRollup2
| case {
    #event_simpleName=NetworkConnectIP4 | match(file="anomali_threatstream_ip.csv", field=[RemoteAddressIP4], column=[destination.ip]) | ioc_value := RemoteAddressIP4 | ioc_type := "ip" ;
    #event_simpleName=DnsRequest | match(file="anomali_threatstream_domain.csv", field=[DomainName], column=[dns.domain.name]) | ioc_value := DomainName | ioc_type := "domain" ;
    #event_simpleName=ProcessRollup2 | match(file="anomali_threatstream_hash_md5.csv", field=[MD5HashData], column=[file.hash.md5]) | ioc_value := MD5HashData | ioc_type := "hash" ;
  }
| table([ComputerName, UserName, ioc_value, ioc_type, threat_type, confidence, source, @timestamp])

// Match domains against first and third-party data in the same query
#repo!=xdr_indicatorsrepo
| DomainName=* OR destination.domain=*
| coalesce([DomainName, destination.domain], as=destination.domain)
| match(file="anomali_threatstream_domain.csv", field=[destination.domain], column=[dns.domain.name])
| table([#repo, #type, destination.domain, threat_type, confidence, source, @id])
```

**Create Detection Rules**: Use IOC lookups in custom detection rules for automated alerting when threats match your environment.

