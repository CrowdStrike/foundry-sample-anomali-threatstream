"""
Anomali ThreatStream IOC Ingestion Function

This function ingests threat intelligence indicators (IOCs) from Anomali ThreatStream
and converts them into lookup files for CrowdStrike Falcon Next-Gen SIEM.

Key Features:
- Incremental sync using update_id tracking for efficient data retrieval
- Workflow-managed pagination for processing large IOC datasets (64K+ records)
- Support for all IOC types: IP, domain, URL, email, hash (MD5/SHA1/SHA256)
- Type-specific filtering for parallel execution and selective ingestion
- Intelligent threat intelligence deduplication preserving most recent IOC data
- Deduplication and file merging for existing lookup files
- Comprehensive error handling and job tracking for monitoring

Threat Intelligence Deduplication:
- Implements STIX 2.1 compliant temporal precedence for IOC updates
- Preserves most recent confidence scores, threat classifications, and tags
- Ensures security analysts receive current threat intelligence for hunting and response
- Supports IOC evolution tracking (suspicious → malware → APT attribution)
- Critical for accurate incident response and threat hunting decisions

Architecture:
- Initial calls: Create jobs and fetch IOCs using saved update_id state
- Pagination calls: Use workflow next_token to continue fetching remaining data
- File processing: Download existing files, merge with new data, remove duplicates
- Progress tracking: Save latest update_id after each successful batch

Workflow Integration:
- Designed for use with Foundry workflows that handle pagination loops
- Returns 'next' token when more data is available for continued processing
- Preserves time constraints across pagination calls for data consistency
- Supports up to 10,000 iterations with 1-hour execution limits per IOC type

Sync Logic:
- For initial calls: Creates job record and uses last saved update_id from collections
- For pagination calls: Skips job creation and uses next_token from workflow variables
- Job tracking is optimized to reduce overhead while maintaining audit trail
- Workflow manages pagination with next tokens, function processes single pages
"""
# pylint: disable=too-many-lines

import csv
import json
import os
import random
import tempfile
import time
import uuid
from datetime import datetime, timezone, timedelta
from logging import Logger
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs

from crowdstrike.foundry.function import Function, Request, Response, APIError
from falconpy import APIIntegrations, NGSIEM, APIHarnessV2


FUNC = Function.instance()

# Maximum file size for NGSIEM lookup uploads (200 MB)
MAX_UPLOAD_SIZE_BYTES = 200 * 1024 * 1024
WARNING_THRESHOLD_BYTES = 180 * 1024 * 1024  # Warn when approaching limit


class AnomaliFunctionError(Exception):
    """Base exception for Anomali function errors."""


class CollectionError(AnomaliFunctionError):
    """Exception for collection storage errors."""


class APIIntegrationError(AnomaliFunctionError):
    """Exception for API integration errors."""


class JobError(AnomaliFunctionError):
    """Exception for job management errors."""


class FileSizeLimitError(AnomaliFunctionError):
    """Exception raised when a lookup file exceeds the NGSIEM upload size limit."""


def estimate_final_file_sizes(
    csv_files: List[str],
    iocs_in_batch: int,
    total_count: int,
    existing_files: Dict[str, str],
    logger: Logger
) -> Optional[str]:
    """
    Estimate final file sizes based on first batch and return error message if limit will be exceeded.

    This fail-fast check prevents wasting time on pagination when the final file size
    will exceed the 200 MB NGSIEM limit. Only runs on first execution (no existing files).

    Returns:
        Error message string if limit will be exceeded, None otherwise.
    """
    # Only run this check on first execution (no existing files)
    if existing_files:
        return None

    # Need at least some IOCs to estimate
    if iocs_in_batch == 0 or total_count == 0:
        return None

    # Calculate distribution and projected sizes for each file
    projections = []
    for filepath in csv_files:
        filename = os.path.basename(filepath)
        file_size = os.path.getsize(filepath)
        file_size_mb = file_size / (1024 * 1024)

        # Count records in this file (subtract 1 for header)
        with open(filepath, 'r', encoding='utf-8') as f:
            record_count = sum(1 for _ in f) - 1

        if record_count <= 0:
            continue

        # Calculate bytes per record for this file type
        bytes_per_record = file_size / record_count

        # Calculate what percentage of the batch went to this file
        distribution_pct = record_count / iocs_in_batch

        # Project total records for this file type
        projected_records = int(total_count * distribution_pct)

        # Project final file size
        projected_size = projected_records * bytes_per_record
        projected_size_mb = projected_size / (1024 * 1024)

        logger.info(
            f"File size projection: {filename} - "
            f"current: {record_count:,} records ({file_size_mb:.1f} MB), "
            f"distribution: {distribution_pct:.1%}, "
            f"projected: {projected_records:,} records ({projected_size_mb:.1f} MB)"
        )

        if projected_size > MAX_UPLOAD_SIZE_BYTES:
            projections.append({
                "filename": filename,
                "projected_records": projected_records,
                "projected_size_mb": projected_size_mb,
                "distribution_pct": distribution_pct
            })

    if projections:
        # Build error message for files that will exceed limit
        file_details = ", ".join([
            f"{p['filename']} (~{p['projected_size_mb']:.0f} MB with {p['projected_records']:,} records)"
            for p in projections
        ])
        return (
            f"The estimated file size will exceed the 200 MB NGSIEM API upload limit. "
            f"Based on first batch distribution: {file_details}. "
            f"Total IOCs matching query: {total_count:,}. "
            f"To reduce dataset size, configure the workflow to use filters: "
            f"1) Use 'feed_id' to limit ingestion to specific threat feeds, "
            f"2) Use 'confidence_gte' to filter low-confidence IOCs (e.g., confidence_gte: 70)."
        )

    return None


# IOC type mappings for CSV column headers
IOC_TYPE_MAPPINGS = {
    "ip": {
        "columns": [
            "destination.ip", "confidence", "threat_type", "source", "tags", "expiration_ts"
        ],
        "primary_field": "ip"
    },
    "domain": {
        "columns": [
            "dns.domain.name", "confidence", "threat_type", "source", "tags", "expiration_ts"
        ],
        "primary_field": "value"
    },
    "url": {
        "columns": [
            "url.original", "confidence", "threat_type", "source", "tags", "expiration_ts"
        ],
        "primary_field": "value"
    },
    "email": {
        "columns": [
            "email.sender.address", "confidence", "threat_type", "source", "tags", "expiration_ts"
        ],
        "primary_field": "value"
    },
    "hash_md5": {
        "columns": [
            "file.hash.md5", "confidence", "threat_type", "source", "tags", "expiration_ts"
        ],
        "primary_field": "value"
    },
    "hash_sha1": {
        "columns": [
            "file.hash.sha1", "confidence", "threat_type", "source", "tags", "expiration_ts"
        ],
        "primary_field": "value"
    },
    "hash_sha256": {
        "columns": [
            "file.hash.sha256", "confidence", "threat_type", "source", "tags", "expiration_ts"
        ],
        "primary_field": "value"
    }
}

# Collection names
COLLECTION_UPDATE_TRACKER = "update_id_tracker"
COLLECTION_INGEST_JOBS = "ingest_jobs"
KEY_LAST_UPDATE = "last_update"

# Job states
JOB_RUNNING = "running"
JOB_COMPLETED = "completed"
JOB_FAILED = "failed"

def get_last_update_id(
    api_client: APIHarnessV2, headers: Dict[str, str], ioc_type: Optional[str], logger: Logger
) -> Optional[Dict]:
    """Get the last update_id from collections for incremental sync"""
    # Use simple per-type key: last_update_ip, last_update_domain, etc.
    if ioc_type:
        object_key = f"last_update_{ioc_type}"
    else:
        object_key = "last_update"

    logger.info(f"Fetching last update_id from collections with key: {object_key}")

    # Try to get the object directly
    try:
        response = api_client.command("GetObject",
                                    collection_name=COLLECTION_UPDATE_TRACKER,
                                    object_key=object_key,
                                    headers=headers)

        # GetObject returns bytes directly, need to decode
        update_data = json.loads(response.decode("utf-8"))
        logger.info(
            f"Retrieved last update data for {ioc_type or 'all types'}: {update_data}"
        )
        return update_data

    except Exception:
        # If GetObject fails, it likely means the object doesn't exist
        logger.info(
            f"No previous update_id found for {ioc_type or 'all types'}, "
            "will fetch recent data"
        )
        return None

def save_update_id(
    api_client: APIHarnessV2,
    headers: Dict[str, str],
    update_data: Dict,
    ioc_type: Optional[str],
    logger: Logger
):
    """Save the current update_id to collections"""
    try:
        # Use simple per-type key: last_update_ip, last_update_domain, etc.
        if ioc_type:
            object_key = f"last_update_{ioc_type}"
        else:
            object_key = "last_update"

        logger.info(f"Saving update_id to collections with key {object_key}: {update_data}")

        response = api_client.command("PutObject",
                                    body=update_data,
                                    collection_name=COLLECTION_UPDATE_TRACKER,
                                    object_key=object_key,
                                    headers=headers)

        if response["status_code"] != 200:
            raise CollectionError(f"Failed to save update_id: {response}")

        logger.info(f"Successfully saved update_id for {ioc_type or 'all types'}")

    except Exception as e:
        logger.error(
            f"Error saving update_id for {ioc_type or 'all types'}: {str(e)}",
            exc_info=True
        )
        raise

def create_job(
    api_client: APIHarnessV2,
    headers: Dict[str, str],
    last_update: Optional[Dict],
    ioc_type: Optional[str],
    logger: Logger
) -> Dict:
    """Create a new ingest job record or mock job in test mode"""
    # Check if we're in test mode
    test_mode = os.environ.get("TEST_MODE", "false").lower() in ["true", "1", "yes"]

    if test_mode:
        # Create a mock job for testing
        base_id = str(uuid.uuid4())[:8]
        job_id = f"test_{base_id}_{ioc_type}" if ioc_type else f"test_{base_id}"
        now = datetime.now(timezone.utc)

        job_params = {
            "status": "active",
            "order_by": "update_id",
            "update_id__gt": "0"  # Start from beginning for testing
        }

        # Add type filter for type-specific jobs
        if ioc_type:
            job_params["type"] = ioc_type

        mock_job = {
            "id": job_id,
            "created_timestamp": now.isoformat(),
            "state": JOB_RUNNING,
            "ioc_type": ioc_type or "all",
            "parameters": job_params
        }

        logger.info(f"TEST MODE: Created mock job: {mock_job}")
        return mock_job

    # Production mode - original job creation logic
    # Create type-specific job ID for parallel execution tracking
    base_id = str(uuid.uuid4())[:8]  # Shorter UUID for readability
    job_id = f"{base_id}_{ioc_type}" if ioc_type else base_id
    now = datetime.now(timezone.utc)

    job_params = {
        "status": "active",
        "order_by": "update_id"
    }

    # Add type filter to job parameters for type-specific jobs
    if ioc_type:
        job_params["type"] = ioc_type

    if last_update:
        job_params["update_id__gt"] = last_update.get("update_id", "0")
        # Add lookback time for incremental sync - use 65 minutes to ensure
        # no data gaps with hourly scheduling
        lookback_time = now - timedelta(minutes=65)
        job_params["modified_ts_gt"] = lookback_time.isoformat()
        # Add upper time bound for incremental sync to ensure consistency
        job_params["modified_ts_lt"] = now.isoformat()
    else:
        # Fresh start for this type - get all available data (no time constraints)
        job_params["update_id__gt"] = "0"
        # No time constraints for fresh start to get all historical data
        logger.info(f"Fresh start for type {ioc_type or 'all types'} - no time constraints")

    job = {
        "id": job_id,
        "created_timestamp": now.isoformat(),
        "state": JOB_RUNNING,
        "ioc_type": ioc_type or "all",  # Track which type this job handles
        "parameters": job_params
    }

    try:
        logger.info(f"Creating job: {job}")

        response = api_client.command("PutObject",
                                    body=job,
                                    collection_name=COLLECTION_INGEST_JOBS,
                                    object_key=job_id,
                                    headers=headers)

        if response["status_code"] != 200:
            raise JobError(f"Failed to create job: {response}")

        logger.info(f"Successfully created job {job_id}")
        return job

    except Exception as e:
        logger.error(f"Error creating job: {str(e)}", exc_info=True)
        raise

def update_job(api_client: APIHarnessV2, headers: Dict[str, str], job: Dict, logger: Logger):
    """Update job status in collections or log in test mode"""
    # Check if we're in test mode
    test_mode = os.environ.get("TEST_MODE", "false").lower() in ["true", "1", "yes"]

    if test_mode:
        logger.info(f"TEST MODE: Mock job update for {job["id"]} with state: {job["state"]}")
        return

    # Production mode - original job update logic
    try:
        logger.info(f"Updating job {job["id"]} with state: {job["state"]}")

        response = api_client.command("PutObject",
                                    body=job,
                                    collection_name=COLLECTION_INGEST_JOBS,
                                    object_key=job["id"],
                                    headers=headers)

        if response["status_code"] != 200:
            raise JobError(f"Failed to update job: {response}")

        logger.info(f"Successfully updated job {job["id"]}")

    except Exception as e:
        logger.error(f"Error updating job: {str(e)}", exc_info=True)
        raise

def format_elapsed_time(elapsed_seconds: float) -> str:
    """Format elapsed time as minutes:seconds when >= 60s, otherwise as seconds"""
    if elapsed_seconds >= 60:
        minutes = int(elapsed_seconds // 60)
        seconds = elapsed_seconds % 60
        return f"{minutes}m {seconds:.1f}s"
    return f"{elapsed_seconds:.1f}s"


def fetch_iocs_from_anomali(
    api_integrations: APIIntegrations,
    params: Dict[str, Any],
    logger: Logger,
    max_retries: int = 5
) -> tuple[List[Dict], Dict]:
    """Fetch IOCs from Anomali ThreatStream using API Integration with retry logic for rate limiting"""
    # pylint: disable=too-many-branches,too-many-statements,too-many-locals

    for attempt in range(max_retries + 1):
        try:
            logger.info(f"Calling Anomali API with params (attempt {attempt + 1}): {params}")

            # Use the API Integration to call Anomali Intelligence endpoint
            response = api_integrations.execute_command_proxy(
                definition_id="Anomali API",
                operation_id="Intelligence",
                params={
                    "query": params
                }
            )

            logger.info(f"Anomali API response status: {response["status_code"]}")

            # Check for rate limiting in multiple formats
            is_rate_limited = False
            rate_limit_message = ""

            # Direct 429 status
            if response["status_code"] == 429:
                is_rate_limited = True
                rate_limit_message = response.get("body", {}).get("errors", "Rate limit exceeded")

            # Check for 207 Multi-Status with embedded 429 errors
            elif response["status_code"] == 207:
                error_body = response.get("body", {})
                errors = error_body.get("errors", [])

                # Check if any embedded error is a 429
                for error in errors:
                    if isinstance(error, dict) and error.get("code") == 429:
                        is_rate_limited = True
                        rate_limit_message = error.get(
                            "message", "Rate limit exceeded in multi-status response"
                        )
                        break

            # Handle rate limiting with Retry-After header or exponential backoff
            if is_rate_limited:
                if attempt < max_retries:
                    # Check for Retry-After header (standard for HTTP 429)
                    retry_after_header = response.get("headers", {}).get("Retry-After")
                    if retry_after_header:
                        # Retry-After can be seconds (int) or HTTP date (string)
                        try:
                            retry_after = int(retry_after_header)
                        except (ValueError, TypeError):
                            # If not an integer, fall back to exponential backoff
                            retry_after = 5 * (2 ** attempt) + random.uniform(0, 2)
                    else:
                        # No Retry-After header, use exponential backoff with jitter
                        retry_after = 5 * (2 ** attempt) + random.uniform(0, 2)

                    logger.warning(
                        f"Rate limited ({rate_limit_message}), retrying in "
                        f"{retry_after:.1f}s (attempt {attempt + 1}/{max_retries})"
                    )
                    time.sleep(retry_after)
                    continue

                raise APIIntegrationError(
                    f"Rate limit exceeded after {max_retries} retries: {rate_limit_message}"
                )

            if response["status_code"] not in [200, 207]:
                error_message = response.get("body", {}).get("errors", "Unknown error")
                raise APIIntegrationError(
                    f"API call failed with status {response["status_code"]}: {error_message}"
                )

            response_data = response.get("body", {})
            objects = response_data.get("objects", [])
            meta = response_data.get("meta", {})

            logger.info(f"Fetched {len(objects)} IOCs from Anomali (attempt {attempt + 1})")
            logger.info(f"API Response meta: {meta}")

            return objects, meta

        except APIIntegrationError:
            # Re-raise API integration errors (including rate limits)
            raise
        except Exception as e:
            if attempt < max_retries:
                logger.warning(f"Error on attempt {attempt + 1}: {str(e)}, retrying...")
                time.sleep(1 + attempt)  # Progressive delay for other errors
                continue

            logger.error(
                f"Error fetching IOCs from Anomali after {max_retries + 1} attempts: {str(e)}",
                exc_info=True
            )
            raise

def download_existing_lookup_files(
    repository: str, ioc_type: Optional[str], temp_dir: str, logger: Logger
) -> Dict[str, str]:
    """Download existing lookup files to disk (returns filename -> file path mapping)

    Memory-efficient disk-based streaming: files are downloaded directly to disk
    instead of being held in memory. This enables processing files up to 200MB
    with constant ~3-5MB memory overhead regardless of file size.
    """
    # Check if we're in test mode
    test_mode = os.environ.get("TEST_MODE", "false").lower() in ["true", "1", "yes"]

    if test_mode:
        return download_existing_lookup_files_locally(repository, ioc_type, temp_dir, logger)
    return download_existing_lookup_files_from_ngsiem(repository, ioc_type, temp_dir, logger)

def download_existing_lookup_files_locally(
    repository: str, ioc_type: Optional[str], temp_dir: str, logger: Logger
) -> Dict[str, str]:
    """Copy existing lookup files from local test directory to temp_dir (returns filename -> path)"""
    existing_files = {}

    # Local test directory
    test_dir = os.path.join(os.getcwd(), "test_output", repository)

    try:
        logger.info(f"TEST MODE: Checking for existing lookup files in: {test_dir}")
        if ioc_type:
            logger.info(f"TEST MODE: Filtering for IOC type: {ioc_type}")

        # Known Anomali lookup file names
        known_filenames = [
            "anomali_threatstream_ip.csv",
            "anomali_threatstream_domain.csv",
            "anomali_threatstream_url.csv",
            "anomali_threatstream_email.csv",
            "anomali_threatstream_hash_md5.csv"
        ]

        # Filter by type if specified
        if ioc_type:
            type_filter = ioc_type
            if ioc_type == "hash":
                # If type is "hash", read all hash types (md5, sha1, sha256)
                type_patterns = ["hash_md5", "hash_sha1", "hash_sha256"]
                filenames_to_try = [f for f in known_filenames
                                  if any(pattern in f for pattern in type_patterns)]
            else:
                # Map specific hash types
                if ioc_type == "md5":
                    type_filter = "hash_md5"
                elif ioc_type == "sha1":
                    type_filter = "hash_sha1"
                elif ioc_type == "sha256":
                    type_filter = "hash_sha256"

                filenames_to_try = [f for f in known_filenames if type_filter in f]
        else:
            filenames_to_try = known_filenames

        logger.info(f"TEST MODE: Attempting to read {len(filenames_to_try)} existing lookup files" +
                   (f" for type '{ioc_type}'" if ioc_type else ""))

        # Copy each existing file to temp_dir for streaming processing
        import shutil
        for filename in filenames_to_try:
            source_path = os.path.join(test_dir, filename)
            try:
                if os.path.exists(source_path):
                    logger.info(f"TEST MODE: Copying existing lookup file: {filename}")
                    dest_path = os.path.join(temp_dir, f"existing_{filename}")
                    shutil.copy2(source_path, dest_path)
                    file_size = os.path.getsize(dest_path)
                    existing_files[filename] = dest_path  # Return file PATH, not content
                    logger.info(f"TEST MODE: Copied {filename} ({file_size:,} bytes) to {dest_path}")
                else:
                    logger.info(f"TEST MODE: File {filename} not found (expected for new files)")

            except Exception as e:
                logger.info(f"TEST MODE: File {filename} not accessible: {str(e)}")
                continue

    except Exception as e:
        logger.error(f"TEST MODE: Error checking for existing lookup files: {str(e)}")

    return existing_files

def download_existing_lookup_files_from_ngsiem(
    repository: str, ioc_type: Optional[str], temp_dir: str, logger: Logger
) -> Dict[str, str]:
    """Download existing lookup files to disk using FalconPy streaming (returns filename -> path)

    Uses NGSIEM.get_file(stream=True) to download files directly to disk.
    This keeps memory usage constant (~3-5MB) regardless of file size,
    enabling processing of files up to the 200MB NGSIEM limit.

    Resilience features:
    - Streaming download with Content-Length verification
    - Retry with exponential backoff (5 attempts: 5s, 10s, 20s, 40s, 60s max)
    - Size verification to detect incomplete downloads
    - Aborts if any existing file fails to download (prevents data loss)
    """
    # pylint: disable=too-many-branches,too-many-statements,too-many-locals,too-many-nested-blocks
    existing_files = {}
    failed_downloads = []  # Track files that existed but failed to download
    max_retries = 5

    try:
        logger.info(f"Checking for existing lookup files in repository: {repository}")
        if ioc_type:
            logger.info(f"Filtering for IOC type: {ioc_type}")

        # Known Anomali lookup file names
        known_filenames = [
            "anomali_threatstream_ip.csv",
            "anomali_threatstream_domain.csv",
            "anomali_threatstream_url.csv",
            "anomali_threatstream_email.csv",
            "anomali_threatstream_hash_md5.csv"
        ]

        # Filter by type if specified
        if ioc_type:
            type_filter = ioc_type
            if ioc_type == "hash":
                # If type is "hash", download all hash types (md5, sha1, sha256)
                type_patterns = ["hash_md5", "hash_sha1", "hash_sha256"]
                filenames_to_try = [f for f in known_filenames
                                  if any(pattern in f for pattern in type_patterns)]
            else:
                # Map specific hash types
                if ioc_type == "md5":
                    type_filter = "hash_md5"
                elif ioc_type == "sha1":
                    type_filter = "hash_sha1"
                elif ioc_type == "sha256":
                    type_filter = "hash_sha256"

                filenames_to_try = [f for f in known_filenames if type_filter in f]
        else:
            filenames_to_try = known_filenames

        logger.info(f"Attempting to download {len(filenames_to_try)} existing Anomali lookup files" +
                   (f" for type '{ioc_type}'" if ioc_type else ""))

        # Use FalconPy NGSIEM client with streaming support
        # 10-minute timeout for large files (200MB at ~350KB/s = ~9.5 minutes)
        ngsiem = NGSIEM(timeout=600)

        for filename in filenames_to_try:
            # Retry logic for download
            last_error = None
            downloaded = False
            file_not_found = False

            for attempt in range(1, max_retries + 1):
                if attempt > 1:
                    # Exponential backoff: 5s, 10s, 20s, 40s, 60s (capped at 60s)
                    backoff = min(5 * (2 ** (attempt - 2)), 60)
                    logger.info(f"Retrying download of {filename} after {backoff}s "
                               f"(attempt {attempt}/{max_retries})")
                    time.sleep(backoff)

                try:
                    # Use FalconPy's streaming support
                    resp = ngsiem.get_file(
                        repository=repository,
                        filename=filename,
                        stream=True
                    )

                    # Extract status_code from response (handles both response object and dict)
                    status_code = 0
                    if hasattr(resp, 'status_code'):
                        status_code = resp.status_code
                    elif isinstance(resp, dict):
                        status_code = resp.get("status_code", 0)

                    # Handle 404 - file doesn't exist (not an error, just skip)
                    if status_code == 404:
                        logger.info(f"File {filename} not found (will be created)")
                        file_not_found = True
                        break  # Exit retry loop - no need to retry for non-existent files

                    # Handle non-200 responses (retry)
                    if status_code != 0 and status_code != 200:
                        last_error = f"HTTP {status_code}"
                        logger.warning(f"Download attempt {attempt} failed for {filename}: {last_error}")
                        continue

                    # Get expected size from Content-Length header for verification
                    expected_size = 0
                    if hasattr(resp, 'headers'):
                        expected_size = int(resp.headers.get("Content-Length", 0))
                        logger.info(f"File exists: {filename}, downloading {expected_size:,} bytes "
                                   f"({expected_size / (1024*1024):.2f} MB)")

                    dest_path = os.path.join(temp_dir, f"existing_{filename}")
                    bytes_written = 0
                    last_progress_log = 0  # Track when we last logged progress

                    # Stream to disk with progress logging for large files
                    with open(dest_path, 'wb') as f:
                        if hasattr(resp, 'iter_content'):
                            # Streaming response
                            for chunk in resp.iter_content(chunk_size=8192):
                                if chunk:
                                    f.write(chunk)
                                    bytes_written += len(chunk)
                                    # Log progress every 10MB for large files
                                    if bytes_written - last_progress_log >= 10 * 1024 * 1024:
                                        logger.info(f"Download progress: {filename} - "
                                                   f"{bytes_written / (1024*1024):.1f}MB / "
                                                   f"{expected_size / (1024*1024):.1f}MB")
                                        last_progress_log = bytes_written
                        elif isinstance(resp, bytes):
                            # Non-streaming fallback (shouldn't happen with stream=True)
                            f.write(resp)
                            bytes_written = len(resp)

                    # Verify downloaded size matches expected size (if known)
                    if expected_size > 0 and bytes_written != expected_size:
                        os.remove(dest_path)
                        last_error = f"Size mismatch: got {bytes_written}, expected {expected_size}"
                        logger.warning(f"Download attempt {attempt} for {filename}: {last_error}")
                        continue

                    # Success!
                    existing_files[filename] = dest_path
                    logger.info(f"Downloaded {filename} to disk ({bytes_written:,} bytes, "
                               f"attempt {attempt})")
                    downloaded = True
                    break

                except Exception as e:
                    last_error = str(e)
                    logger.warning(f"Error on download attempt {attempt} for {filename}: {last_error}")
                    continue

            # Skip files that don't exist - no data loss risk
            if file_not_found:
                continue

            # File existed but all retries failed - data loss risk
            if not downloaded:
                logger.error(f"Failed to download existing file {filename} after {max_retries} retries: "
                            f"{last_error}")
                failed_downloads.append(filename)

    except Exception as e:
        logger.error(f"Error checking for existing lookup files: {str(e)}")
        raise

    # If any existing files failed to download, abort to prevent data loss
    if failed_downloads:
        raise AnomaliFunctionError(
            f"Download failed for {len(failed_downloads)} existing file(s) after {max_retries} "
            f"retries each: {failed_downloads} - aborting to prevent data loss"
        )

    return existing_files

def clear_collection_data(
    api_client: APIHarnessV2, headers: Dict[str, str], logger: Logger
):
    """Clear collection data when starting from scratch"""
    try:
        logger.info("Clearing collection data for fresh start")

        # Clear the main update tracker and all type-specific trackers
        update_keys = [KEY_LAST_UPDATE]  # Main tracker
        # Add type-specific trackers
        for ioc_type in ["ip", "domain", "url", "email", "hash"]:
            update_keys.append(f"{KEY_LAST_UPDATE}_{ioc_type}")

        for key in update_keys:
            try:
                api_client.command("DeleteObject",
                                 collection_name=COLLECTION_UPDATE_TRACKER,
                                 object_key=key,
                                 headers=headers)
                logger.info(f"Cleared update tracker data for key: {key}")
            except Exception as e:
                logger.info(f"No update tracker data to clear for key {key}: {str(e)}")

        # Clear job data (optional - jobs are historical records)
        # We might want to keep job history, so this is commented out
        # try:
        #     # List and delete all job objects
        #     response = api_client.command("SearchObjects",
        #                                 collection_name=COLLECTION_INGEST_JOBS,
        #                                 headers=headers)
        #     # Delete logic would go here if needed
        # except Exception as e:
        #     logger.info(f"No job data to clear: {str(e)}")

    except Exception as e:
        logger.error(f"Error clearing collection data: {str(e)}")

def clear_update_id_for_type(
    api_client: APIHarnessV2, headers: Dict[str, str], ioc_type: str, logger: Logger
):
    """Clear the update_id for a specific IOC type when its lookup file is missing"""
    try:
        object_key = f"{KEY_LAST_UPDATE}_{ioc_type}"
        logger.info(f"Clearing update_id for type {ioc_type} (key: {object_key})")

        api_client.command("DeleteObject",
                         collection_name=COLLECTION_UPDATE_TRACKER,
                         object_key=object_key,
                         headers=headers)
        logger.info(f"Successfully cleared update_id for type {ioc_type}")

    except Exception as e:
        logger.info(f"No update_id to clear for type {ioc_type}: {str(e)}")
        # This is expected if the update_id doesn't exist yet

def process_iocs_to_csv(
    iocs: List[Dict], temp_dir: str, existing_files: Dict[str, str], logger: Logger
) -> tuple[List[str], Dict[str, int]]:
    """Process IOCs and create CSV files by type with intelligent threat intelligence deduplication

    Features advanced temporal precedence deduplication that preserves the most recent threat
    intelligence data for each IOC. This ensures security analysts receive current confidence
    scores, threat classifications, and APT attribution rather than outdated intelligence.

    Memory-Efficient Disk Streaming:
    - existing_files now contains file PATHS (not content) for O(1) memory
    - Streams through existing files on disk without loading into memory
    - Enables processing 200MB files with ~3-5MB constant memory overhead

    Deduplication Logic:
    - Implements STIX 2.1 compliant temporal precedence
    - Preserves latest IOC confidence scores and threat types
    - Supports IOC evolution tracking (suspicious -> malware -> APT)
    - Critical for accurate threat hunting and incident response

    Args:
        iocs: List of IOC dictionaries from Anomali ThreatStream
        temp_dir: Temporary directory for file creation
        existing_files: Dictionary of filename -> file PATH on disk (not content)
        logger: Logger instance for tracking operations

    Returns:
        tuple: (created_files, stats) where stats contains:
            - total_new_iocs: Total IOCs processed
            - total_duplicates_removed: Total duplicates that were filtered out
            - files_with_new_data: Number of files that had new unique data added
    """
    # pylint: disable=too-many-branches,too-many-statements,too-many-locals

    logger.info(f"Processing {len(iocs)} IOCs into CSV files")
    logger.info(f"Found {len(existing_files)} existing lookup files to append to")

    # Group IOCs by type
    iocs_by_type = {}
    for ioc in iocs:
        ioc_type = ioc.get("itype", "unknown")

        # Map some common variations to standardized types
        if ioc_type in ["mal_ip", "c2_ip", "apt_ip"]:
            ioc_type = "ip"
        elif ioc_type in ["mal_domain", "c2_domain", "apt_domain"]:
            ioc_type = "domain"
        elif ioc_type in ["mal_url", "apt_url"]:
            ioc_type = "url"
        elif ioc_type in ["apt_email", "mal_email"]:
            ioc_type = "email"
        elif ioc_type in ["apt_md5", "mal_md5"]:
            ioc_type = "hash_md5"
        elif ioc_type in ["apt_sha1", "mal_sha1"]:
            ioc_type = "hash_sha1"
        elif ioc_type in ["apt_sha256", "mal_sha256"]:
            ioc_type = "hash_sha256"

        if ioc_type not in iocs_by_type:
            iocs_by_type[ioc_type] = []
        iocs_by_type[ioc_type].append(ioc)

    logger.info(f"IOCs grouped by type: {[(t, len(iocs)) for t, iocs in iocs_by_type.items()]}")

    created_files = []
    stats = {
        "total_new_iocs": len(iocs),
        "total_duplicates_removed": 0,
        "files_with_new_data": 0
    }

    for ioc_type, type_iocs in iocs_by_type.items():
        if ioc_type not in IOC_TYPE_MAPPINGS:
            logger.warning(f"Unknown IOC type: {ioc_type}, skipping {len(type_iocs)} IOCs")
            continue

        mapping = IOC_TYPE_MAPPINGS[ioc_type]
        filename = f"anomali_threatstream_{ioc_type}.csv"
        filepath = os.path.join(temp_dir, filename)
        columns = mapping["columns"]
        primary_col = columns[0]

        # Build new IOC rows and collect their primary keys
        # Memory: O(new_iocs) - typically small compared to existing file
        new_rows = {}  # Use dict for O(1) lookup and automatic deduplication
        for ioc in type_iocs:
            tags = []
            if 'tags' in ioc and isinstance(ioc["tags"], list):
                tags = [tag.get("name", '') for tag in ioc["tags"] if tag.get('name')]
            tags_str = ",".join(tags) if tags else ""

            primary_value = str(ioc.get(mapping["primary_field"], ''))
            if primary_value:
                # Later entries overwrite earlier ones (temporal precedence)
                new_rows[primary_value] = [
                    primary_value,
                    str(ioc.get("confidence", '')),
                    str(ioc.get("threat_type", '')),
                    str(ioc.get("source", '')),
                    tags_str,
                    str(ioc.get("expiration_ts", ''))
                ]

        new_keys = set(new_rows.keys())
        logger.info(f"Prepared {len(new_rows)} new IOCs for {ioc_type}")

        # Check if we have existing data file to stream from
        existing_file_path = existing_files.get(filename)

        # Streaming CSV processing - memory efficient
        # Streams directly from existing file on disk (O(1) memory)
        original_count = 0
        duplicates_updated = 0
        rows_written = 0

        # Use larger buffer (1MB) for better I/O performance
        with open(filepath, 'w', newline='', encoding='utf-8', buffering=1024*1024) as outfile:
            writer = csv.writer(outfile, quoting=csv.QUOTE_ALL)
            writer.writerow(columns)  # Write header

            # Stream existing data from disk file, filtering out rows that will be replaced
            if existing_file_path and os.path.exists(existing_file_path):
                try:
                    # Open file directly - no memory loading
                    with open(existing_file_path, 'r', encoding='utf-8') as infile:
                        reader = csv.reader(infile)
                        header = next(reader)  # Skip header

                        # Verify columns match
                        if header[0] != primary_col:
                            logger.warning(
                                f"Existing file {filename} has incompatible columns "
                                f"(expected {primary_col}, got {header[0]}), starting fresh"
                            )
                        else:
                            # Batch writes for better performance
                            batch = []
                            batch_size = 10000

                            for row in reader:
                                original_count += 1
                                if row and row[0] not in new_keys:
                                    batch.append(row)
                                    rows_written += 1
                                    if len(batch) >= batch_size:
                                        writer.writerows(batch)
                                        batch = []
                                else:
                                    duplicates_updated += 1

                            # Write remaining batch
                            if batch:
                                writer.writerows(batch)

                            logger.info(f"Streamed {original_count} existing records from {filename}")
                except Exception as e:
                    logger.warning(f"Error reading existing file {filename}: {e}, starting fresh")

            # Write new rows in batch
            writer.writerows(new_rows.values())
            rows_written += len(new_rows)

        # Calculate statistics
        new_unique_added = len(new_rows) - duplicates_updated
        stats["total_duplicates_removed"] += duplicates_updated

        if new_unique_added > 0 or (not existing_file_path and new_rows):
            stats["files_with_new_data"] += 1

        # Check file size
        file_size = os.path.getsize(filepath)
        file_size_mb = file_size / (1024 * 1024)

        # SAFETY CHECK: If existing file was present, verify new file isn't dramatically smaller
        # This prevents data loss if something went wrong during download or processing
        if existing_file_path and os.path.exists(existing_file_path):
            existing_size = os.path.getsize(existing_file_path)
            # If new file is less than 10% of existing file size, something is wrong
            # (unless existing file was tiny, i.e., < 10KB)
            if existing_size > 10 * 1024 and file_size < existing_size // 10:
                error_msg = (
                    f"SAFETY CHECK FAILED: new file {filename} ({file_size_mb:.2f} MB, "
                    f"{rows_written:,} records) is dramatically smaller than existing file "
                    f"({existing_size / (1024*1024):.2f} MB). This likely indicates data loss. "
                    f"Aborting to protect existing data. Check download logs for errors."
                )
                logger.error(error_msg)
                raise AnomaliFunctionError(error_msg)

        if file_size > MAX_UPLOAD_SIZE_BYTES:
            error_msg = (
                f"File {filename} ({file_size_mb:.1f} MB) exceeds the NGSIEM upload limit of 200 MB. "
                f"The file contains {rows_written:,} IOC records. "
                f"To reduce file size, configure the workflow to use filters: "
                f"1) Use 'feed_id' to limit ingestion to specific threat feeds, "
                f"2) Use 'confidence_gte' to filter low-confidence IOCs (e.g., confidence_gte: 70), "
                f"3) Use 'type' parameter to ingest specific IOC types separately."
            )
            logger.error(error_msg)
            raise FileSizeLimitError(error_msg)

        if file_size > WARNING_THRESHOLD_BYTES:
            logger.warning(
                f"File {filename} ({file_size_mb:.1f} MB) is approaching the 200 MB upload limit. "
                f"Consider using filters to reduce data volume."
            )

        if existing_file_path:
            logger.info(
                f"Merged {original_count} existing + {len(new_rows)} new = "
                f"{rows_written} total records for {filename} "
                f"({new_unique_added} net new, {duplicates_updated} updated)"
            )
        else:
            logger.info(f"Created new {filename} with {rows_written} records ({file_size_mb:.2f} MB)")

        created_files.append(filepath)

    return created_files, stats

def upload_csv_files_to_ngsiem(csv_files: List[str], repository: str, logger: Logger) -> List[Dict]:
    """Upload CSV files to Falcon Next-Gen SIEM as lookup files or write locally in test mode"""
    # Check if we're in test mode
    test_mode = os.environ.get("TEST_MODE", "false").lower() in ["true", "1", "yes"]

    if test_mode:
        return upload_csv_files_locally(csv_files, repository, logger)
    return upload_csv_files_to_ngsiem_actual(csv_files, repository, logger)

def upload_csv_files_locally(csv_files: List[str], repository: str, logger: Logger) -> List[Dict]:
    """Write CSV files to local test directory simulating NGSIEM storage"""
    results = []

    # Create local test directory structure
    test_dir = os.path.join(os.getcwd(), "test_output", repository)
    os.makedirs(test_dir, exist_ok=True)

    logger.info(f"TEST MODE: Writing {len(csv_files)} files to local directory: {test_dir}")

    for csv_file in csv_files:
        try:
            filename = os.path.basename(csv_file)
            target_path = os.path.join(test_dir, filename)

            # Copy file to test directory
            import shutil
            shutil.copy2(csv_file, target_path)

            # Get file size for logging
            file_size = os.path.getsize(target_path)
            logger.info(f"TEST MODE: Wrote {filename} to {target_path} ({file_size:,} bytes)")

            results.append({
                "file": filename,
                "status": "success",
                "message": f"File written locally to {target_path}",
                "local_path": target_path,
                "size_bytes": file_size
            })

        except Exception as e:
            logger.error(f"Error writing {filename} locally: {str(e)}", exc_info=True)
            results.append({
                "file": os.path.basename(csv_file),
                "status": "error",
                "message": f"Local write failed: {str(e)}"
            })
            continue

    return results

def upload_csv_files_to_ngsiem_actual(csv_files: List[str], repository: str, logger: Logger) -> List[Dict]:
    """Upload CSV files to Falcon Next-Gen SIEM as lookup files (original implementation)"""
    ngsiem = NGSIEM()
    results = []

    for csv_file in csv_files:
        try:
            filename = os.path.basename(csv_file)
            logger.info(f"Uploading {filename} to Falcon Next-Gen SIEM repository: {repository}")

            response = ngsiem.upload_file(lookup_file=csv_file, repository=repository)

            # Log the raw response for troubleshooting
            logger.info(f"NGSIEM upload response for {filename}: {response}")

            # Handle 500 errors that may be successful uploads with empty responses
            if response["status_code"] == 500:
                error_body = response.get("body", {})
                errors = error_body.get("errors", [])

                # Check for JSON parsing errors that indicate successful upload
                is_likely_success = False
                if errors:
                    error_message = str(errors[0].get("message", "")).lower()
                    is_likely_success = any(phrase in error_message for phrase in [
                        "extra data: line 1 column",
                        "expecting value: line 1 column 1 (char 0)"
                    ])

                if is_likely_success:
                    logger.info(f"Upload successful for {filename} (recovered from parsing error)")
                    results.append({
                        "file": filename,
                        "status": "success",
                        "message": "File uploaded successfully"
                    })
                else:
                    # Real 500 error
                    results.append({
                        "file": filename,
                        "status": "error",
                        "message": f"Upload failed: {errors}"
                    })
            elif response["status_code"] >= 400:
                # Other 4xx errors are real failures
                error_messages = response.get("body", {}).get("errors", [])
                results.append({
                    "file": filename,
                    "status": "error",
                    "message": f"Upload failed: {error_messages}"
                })
            else:
                # 2xx success
                results.append({
                    "file": filename,
                    "status": "success",
                    "message": "File uploaded successfully"
                })

        except Exception as e:
            logger.error(f"Error uploading {filename}: {str(e)}", exc_info=True)
            results.append({
                "file": os.path.basename(csv_file),
                "status": "error",
                "message": f"Upload failed: {str(e)}"
            })
            # Continue processing other files
            continue

    return results

def build_query_params(next_token, status_filter, type_filter, limit, api_client, headers, logger,
                       job=None, request_body=None, trustedcircles=None, feed_id=None,
                       confidence_gt=None, confidence_gte=None, confidence_lt=None, confidence_lte=None):
    """Build query parameters for Anomali API call.

    Args:
        next_token: Pagination token
        status_filter: Status filter
        type_filter: IOC type filter
        limit: Records per page
        api_client: API client (unused, for compatibility)
        headers: Request headers (unused, for compatibility)
        logger: Logger instance
        job: Job record with parameters
        request_body: Request body for manual overrides
        trustedcircles: Trusted circles filter
        feed_id: Feed ID filter
        confidence_gt: Filter by confidence score greater than
        confidence_gte: Filter by confidence score greater than or equal to
        confidence_lt: Filter by confidence score less than
        confidence_lte: Filter by confidence score less than or equal to
    """
    # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-branches,unused-argument,too-many-locals
    if next_token:
        # Pagination call: only use update_id__gt, no time constraints
        logger.info(f"PAGINATION BRANCH: Using next_token: {next_token}")
        query_params = {
            "order_by": "update_id",
            "limit": limit,
            "update_id__gt": next_token
        }
        # Add status filter only if specified
        if status_filter:
            query_params["status"] = status_filter
        # For pagination, use the type filter if specified
        if type_filter:
            query_params["type"] = type_filter  # Use type for pagination consistency
        logger.info(f"PAGINATION: Set update_id__gt to: {query_params["update_id__gt"]}")
        # NOTE: No time constraints for pagination - they limit data incorrectly
    else:
        # Initial call: use job parameters if available
        logger.info("INITIAL BRANCH: Building parameters for initial call")

        if job and job.get("parameters"):
            # Use job's stored parameters (preferred approach)
            query_params = job["parameters"].copy()  # Copy all job parameters
            query_params["limit"] = limit  # Override limit with request parameter
            query_params["order_by"] = "update_id"  # Ensure consistent ordering

            logger.info(f"INITIAL: Using job's stored parameters: {query_params}")

            # Override status if explicitly provided in request
            if status_filter:
                query_params["status"] = status_filter
                logger.info(f"INITIAL: Overriding status with request parameter: {status_filter}")

        else:
            # Fallback logic for when no job exists (shouldn't happen with new architecture)
            logger.warning("INITIAL: No job found - using fallback parameter construction")

            start_update_id = "0"
            query_params = {
                "order_by": "update_id",
                "limit": limit,
                "update_id__gt": start_update_id
            }

            # Add type filter if specified
            if type_filter:
                query_params["type"] = type_filter

            # Add status filter if specified
            if status_filter:
                query_params["status"] = status_filter

        # Add status filter only if specified (for both job and fallback cases)
        if status_filter and "status" not in query_params:
            query_params["status"] = status_filter

        # Allow manual parameter overrides for initial calls only
        if request_body:
            if 'modified_ts_gt' in request_body:
                query_params["modified_ts__gt"] = request_body["modified_ts_gt"]
                logger.info("INITIAL: Manual modified_ts_gt override applied")
            if 'modified_ts_lt' in request_body:
                query_params["modified_ts__lt"] = request_body["modified_ts_lt"]
                logger.info("INITIAL: Manual modified_ts_lt override applied")
            if 'update_id_gt' in request_body:
                old_value = query_params.get('update_id__gt')
                query_params["update_id__gt"] = request_body["update_id_gt"]
                logger.info(
                    f"INITIAL: Manual override changed update_id__gt from "
                    f"{old_value} to {query_params['update_id__gt']}"
                )

    # Add trusted circles filtering if provided (works for both initial and pagination)
    if trustedcircles:
        logger.info(f"Filtering by trusted circles: {trustedcircles}")
        query_params["trustedcircles"] = trustedcircles

    # Add feed_id filtering if provided (works for both initial and pagination)
    if feed_id:
        logger.info(f"Filtering by feed_id: {feed_id}")
        query_params["feed_id"] = feed_id

    # Add confidence filtering if provided (works for both initial and pagination)
    if confidence_gt is not None:
        logger.info(f"Filtering by confidence__gt: {confidence_gt}")
        query_params["confidence__gt"] = confidence_gt
    if confidence_gte is not None:
        logger.info(f"Filtering by confidence__gte: {confidence_gte}")
        query_params["confidence__gte"] = confidence_gte
    if confidence_lt is not None:
        logger.info(f"Filtering by confidence__lt: {confidence_lt}")
        query_params["confidence__lt"] = confidence_lt
    if confidence_lte is not None:
        logger.info(f"Filtering by confidence__lte: {confidence_lte}")
        query_params["confidence__lte"] = confidence_lte

    return query_params


def extract_next_token_from_meta(meta, iocs, logger):
    """Extract next pagination token from API response metadata."""
    next_token = None

    if meta and meta.get("next") and iocs:
        # Parse the API's next URL to get the proper pagination parameters
        next_url = meta.get("next")
        try:
            # Extract from_update_id or search_after from the next URL
            parsed_url = urlparse(next_url)
            query_params_parsed = parse_qs(parsed_url.query)

            # Try search_after first (the actual next boundary), then fallback to others
            if 'search_after' in query_params_parsed:
                next_token = query_params_parsed["search_after"][0]
                logger.info(
                    f"More data available - next pagination token (search_after): {next_token}"
                )
            elif 'update_id__gt' in query_params_parsed:
                next_token = query_params_parsed["update_id__gt"][0]
                logger.info(
                    f"More data available - next pagination token (update_id__gt): {next_token}"
                )
            elif 'from_update_id' in query_params_parsed:
                next_token = query_params_parsed["from_update_id"][0]
                logger.info(
                    f"More data available - next pagination token (from_update_id): {next_token}"
                )
            else:
                # Fallback to last IOC's update_id
                last_ioc = iocs[-1]
                if 'update_id' in last_ioc:
                    next_token = str(last_ioc["update_id"])
                    logger.info(
                        f"More data available - next pagination token (fallback): {next_token}"
                    )
        except Exception as e:
            logger.warning(f"Could not parse next URL {next_url}: {str(e)}, using fallback")
            # Fallback to last IOC's update_id
            last_ioc = iocs[-1]
            if 'update_id' in last_ioc:
                next_token = str(last_ioc["update_id"])
                logger.info(
                    f"More data available - next pagination token (fallback): {next_token}"
                )

    return next_token


def check_and_recover_missing_files(
    repository: str,
    type_filter: Optional[str],
    temp_dir: str,
    api_client: APIHarnessV2,
    headers: Dict[str, str],
    logger: Logger
) -> tuple[bool, Dict[str, str]]:
    """Check for existing lookup files and handle missing file recovery.

    Args:
        repository: NGSIEM repository name
        type_filter: Optional IOC type filter
        temp_dir: Temporary directory for streaming file downloads
        api_client: API client for collections access
        headers: Request headers
        logger: Logger instance

    Returns:
        tuple: (should_start_fresh, existing_files) where should_start_fresh indicates
               if all files are missing and existing_files is a dict of filename -> file PATH
    """
    should_start_fresh = False
    existing_files = {}

    if not type_filter:
        # No type specified - check if any Anomali files exist
        logger.info("No type filter specified - checking for any existing Anomali lookup files")
        existing_files = download_existing_lookup_files(repository, None, temp_dir, logger)
        if not existing_files:
            logger.info("No existing Anomali lookup files found - starting completely fresh")
            should_start_fresh = True
        else:
            logger.info(
                f"Found {len(existing_files)} existing Anomali lookup files - "
                "continuing incremental sync"
            )

            # Check for missing specific type files and clear their update_ids
            # Build expected files list dynamically from IOC_TYPE_MAPPINGS
            expected_files = [
                f"anomali_threatstream_{ioc_type}.csv" for ioc_type in IOC_TYPE_MAPPINGS
            ]

            missing_files = [f for f in expected_files if f not in existing_files]
            if missing_files:
                logger.info(
                    f"Detected missing files: {missing_files} - "
                    "clearing update_ids for these types"
                )

                for missing_file in missing_files:
                    # Extract type from filename (remove prefix and suffix)
                    filename_base = missing_file.replace(
                        "anomali_threatstream_", ""
                    ).replace(".csv", "")

                    # Map filename back to collection key
                    if filename_base.startswith("hash_"):
                        collection_type = "hash"  # All hash types use the same collection key
                    else:
                        collection_type = filename_base

                    clear_update_id_for_type(api_client, headers, collection_type, logger)

                # Also clear the main last_update key
                logger.info("Clearing main last_update key to ensure fresh start for missing file types")
                try:
                    api_client.command("DeleteObject",
                                     collection_name=COLLECTION_UPDATE_TRACKER,
                                     object_key=KEY_LAST_UPDATE,
                                     headers=headers)
                    logger.info("Successfully cleared main last_update key")
                except Exception as e:
                    logger.info(f"Main last_update key was already cleared or didn't exist: {str(e)}")
    else:
        # Type filter specified - always download existing files for that type
        logger.info(f"Checking for existing files for type: {type_filter}")
        existing_files = download_existing_lookup_files(repository, type_filter, temp_dir, logger)
        if not existing_files:
            logger.info(f"No existing files found for type {type_filter} - will create new file")
            clear_update_id_for_type(api_client, headers, type_filter, logger)
        else:
            logger.info(f"Found existing files for type {type_filter} - will merge with existing data")

    return should_start_fresh, existing_files


@FUNC.handler(method="POST", path="/ingest")
def on_post(request: Request, _config: Optional[Dict[str, object]], logger: Logger) -> Response:
    """
    Main handler for IOC ingestion from Anomali ThreatStream.

    Processes a single page of IOCs for workflow-level pagination. The workflow
    handles looping based on the "next" token returned when more data is available.

    Memory-Efficient Disk Streaming:
    - Files are downloaded directly to disk (not memory) for O(1) memory usage
    - Enables processing 200MB files with ~3-5MB constant memory overhead
    - temp_dir is created early for streaming downloads and processing

    Args:
        request: The incoming request object containing the request body.
        _config: Configuration dictionary (unused).
        logger: Logger instance for logging.

    Returns:
        Response: JSON response with single-page ingestion results and optional next token.

    Required fields in request body:
    - repository: Falcon Next-Gen SIEM repository name (defaults to "search-all")

    Optional fields:
    - status: IOC status filter (default: "active")
    - type: IOC type filter (ip, domain, url, email, hash) for parallel execution
    - trustedcircles: Comma-separated feed IDs for filtering (e.g., "11631,12345")
    - feed_id: Comma-separated feed IDs for filtering (alternative to trustedcircles)
    - update_id_gt: Update ID greater than (for manual overrides)
    - limit: Number of records to fetch per call (default: 1000, max: 1000)
    - next: Continuation token for workflow pagination
    """
    # pylint: disable=too-many-branches,too-many-statements,too-many-locals

    start_time = time.time()

    try:
        # Parse request parameters
        repository = request.body.get("repository", "search-all").strip()
        status_filter = request.body.get("status", None)  # No default status filter - get all IOCs
        trustedcircles = request.body.get("trustedcircles", None)  # Feed ID filtering
        feed_id = request.body.get("feed_id", None)  # Feed ID filtering (alternative parameter)
        next_token = request.body.get("next", None)  # Workflow pagination continuation
        limit = request.body.get("limit", 1000)  # Number of records per API call

        # Parse confidence filters
        confidence_gt = request.body.get("confidence_gt", None)
        confidence_gte = request.body.get("confidence_gte", None)
        confidence_lt = request.body.get("confidence_lt", None)
        confidence_lte = request.body.get("confidence_lte", None)

        # Parse fail-fast setting (disabled by default for testing)
        fail_fast_enabled = request.body.get("fail_fast_enabled", False)

        # Parse type filter - only support single type or no type
        type_filter = request.body.get("type", None)  # Single IOC type filter
        if type_filter and ',' in str(type_filter):
            error_msg = (
                "Comma-delimited types not supported. Use no type filter to get all types, "
                "or specify a single type. Supported types: ip, domain, url, email, hash, md5, sha1, sha256."
            )
            return Response(
                errors=[APIError(code=400, message=error_msg)],
                code=400
            )

        logger.info(f"Starting IOC ingestion for repository: {repository}")
        logger.info(
            f"Request parameters: status={status_filter}, type={type_filter}, "
            f"trustedcircles={trustedcircles}, feed_id={feed_id}, next={next_token}, limit={limit}, "
            f"confidence_gte={confidence_gte}, confidence_gt={confidence_gt}"
        )

        # Initialize clients
        api_integrations = APIIntegrations()
        api_client = APIHarnessV2()

        # Set up headers for collections
        # Note: X-CS-APP-ID is needed for local development when accessing collections
        # In production, Foundry automatically sets this header
        headers = {}
        if os.environ.get("APP_ID"):
            headers = {"X-CS-APP-ID": os.environ.get("APP_ID")}

        # Create temp_dir early for disk-based streaming (O(1) memory)
        # This is used for downloading existing files and creating new CSV files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Phase 1: Download existing lookup files
            phase1_start = time.time()
            logger.info("Phase 1: Downloading existing lookup files...")

            # Check for existing files and handle missing file recovery
            # Files are streamed directly to temp_dir (not held in memory)
            should_start_fresh, existing_files = check_and_recover_missing_files(
                repository, type_filter, temp_dir, api_client, headers, logger
            )

            phase1_elapsed = time.time() - phase1_start
            logger.info(f"Phase 1 complete: Downloaded {len(existing_files)} existing files in {format_elapsed_time(phase1_elapsed)}")

            if should_start_fresh:
                logger.info("Starting completely fresh sync - clearing all collection data")
                clear_collection_data(api_client, headers, logger)

            # For pagination calls, skip job creation and use workflow parameters
            if next_token:
                logger.info(f"Pagination call detected with next_token: {next_token}")
                job = None  # No job needed for pagination
            else:
                # Initial call - create type-specific job for both all-types and single-type calls
                logger.info("Initial call - creating type-specific job")

                # Get type-specific update_id
                last_update = get_last_update_id(api_client, headers, type_filter, logger)

                # Create type-specific job
                job = create_job(api_client, headers, last_update, type_filter, logger)

            try:
                # Build query parameters using extracted helper function
                logger.info(f"Building query params: next_token='{next_token}', bool={bool(next_token)}")

                query_params = build_query_params(
                    next_token, status_filter, type_filter, limit, api_client, headers, logger, job,
                    request_body=request.body, trustedcircles=trustedcircles, feed_id=feed_id,
                    confidence_gt=confidence_gt, confidence_gte=confidence_gte,
                    confidence_lt=confidence_lt, confidence_lte=confidence_lte
                )

                logger.info(f"Final query_params before API call: {query_params}")

                # Phase 2: Fetch IOCs from Anomali
                phase2_start = time.time()
                logger.info("Phase 2: Fetching IOCs from Anomali...")
                iocs, meta = fetch_iocs_from_anomali(api_integrations, query_params, logger)

                phase2_elapsed = time.time() - phase2_start
                logger.info(f"Phase 2 complete: Fetched {len(iocs)} IOCs in {format_elapsed_time(phase2_elapsed)}")

                if not iocs:
                    # Mark job as completed even with no data (if job exists)
                    if job:
                        job["state"] = JOB_COMPLETED
                        update_job(api_client, headers, job, logger)

                    return Response(
                        body={
                            "message": "No IOCs found matching criteria",
                            "total_iocs": 0,
                            "files_created": 0,
                            "upload_results": [],
                            "job_id": job["id"] if job else "pagination-call",
                            "meta": {}
                            # No "next" field - pagination complete
                        },
                        code=200
                    )

                # Phase 3: Process IOCs and create CSV files
                phase3_start = time.time()
                logger.info("Phase 3: Processing IOCs and creating CSV files...")
                csv_files, process_stats = process_iocs_to_csv(iocs, temp_dir, existing_files, logger)

                phase3_elapsed = time.time() - phase3_start
                logger.info(f"Phase 3 complete: Created {len(csv_files)} CSV files in {format_elapsed_time(phase3_elapsed)}")

                if not csv_files:
                    # Mark job as completed but no valid data (if job exists)
                    if job:
                        job["state"] = JOB_COMPLETED
                        update_job(api_client, headers, job, logger)

                    return Response(
                        body={
                            "message": "No valid IOCs to process",
                            "total_iocs": 0,
                            "files_created": 0,
                            "upload_results": [],
                            "job_id": job["id"] if job else "pagination-call",
                            "meta": {}
                            # No "next" field - pagination complete
                        },
                        code=200
                    )

                # Fail-fast check: estimate final file sizes on first execution
                # This prevents wasting hours on pagination only to fail at the end
                # Disabled by default - set fail_fast_enabled=true to enable
                if fail_fast_enabled:
                    total_count = meta.get("total_count", 0) if meta else 0
                    size_limit_error = estimate_final_file_sizes(
                        csv_files, len(iocs), total_count, existing_files, logger
                    )
                    if size_limit_error:
                        logger.error(size_limit_error)
                        raise FileSizeLimitError(size_limit_error)

                # Phase 4: Upload CSV files to Falcon Next-Gen SIEM
                phase4_start = time.time()
                logger.info("Phase 4: Uploading CSV files to NGSIEM...")
                upload_results = upload_csv_files_to_ngsiem(csv_files, repository, logger)

                phase4_elapsed = time.time() - phase4_start
                logger.info(f"Phase 4 complete: Uploaded {len(csv_files)} files in {format_elapsed_time(phase4_elapsed)}")

                # Update collections with latest state
                if meta and iocs:
                    # Get the highest update_id from processed IOCs
                    update_ids = [str(ioc["update_id"]) for ioc in iocs if 'update_id' in ioc]
                    max_update_id = max(update_ids) if update_ids else "0"

                    update_data = {
                        "created_timestamp": datetime.now(timezone.utc).isoformat(),
                        "total_count": meta.get("total_count", len(iocs)),
                        "next_url": meta.get("next") or "",  # Handle null/None case
                        "update_id": max_update_id
                    }

                    # Save state for the appropriate type (single type or all types)
                    save_update_id(api_client, headers, update_data, type_filter, logger)

                # Mark job as completed (if job exists)
                if job:
                    job["state"] = JOB_COMPLETED
                    update_job(api_client, headers, job, logger)

                # Prepare response with consistent next field
                response_body = {
                    "message": f"Processed {len(iocs)} IOCs into {len(csv_files)} lookup files",
                    "total_iocs": len(iocs),
                    "files_created": len(csv_files),
                    "upload_results": upload_results,
                    "job_id": job["id"] if job else "pagination-call",
                    "meta": meta,
                    "process_stats": process_stats  # Include processing statistics
                }

                # Only include next token if there's more data
                next_token_value = extract_next_token_from_meta(meta, iocs, logger)
                if next_token_value:
                    response_body["next"] = next_token_value
                    logger.info(f"Response next field set to: {next_token_value}")
                else:
                    logger.info("No next token - pagination complete")

                # Log total elapsed time
                total_elapsed = time.time() - start_time
                logger.info(f"Total ingestion completed in {format_elapsed_time(total_elapsed)}")

                return Response(
                    body=response_body,
                    code=200
                )

            except Exception as e:
                # Mark job as failed (if job exists)
                if job:
                    job["state"] = JOB_FAILED
                    job["error"] = str(e)
                    update_job(api_client, headers, job, logger)
                raise

    except Exception as e:
        logger.error(f"Error in IOC ingestion: {str(e)}", exc_info=True)
        return Response(
            errors=[APIError(code=500, message=f"Internal error: {str(e)}")],
            code=500
        )

if __name__ == "__main__":
    FUNC.run()
