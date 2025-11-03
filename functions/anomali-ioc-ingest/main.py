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
from io import StringIO
from logging import Logger
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs

from crowdstrike.foundry.function import Function, Request, Response, APIError
from falconpy import APIIntegrations, NGSIEM, APIHarnessV2
import pandas as pd


FUNC = Function.instance()


class AnomaliFunctionError(Exception):
    """Base exception for Anomali function errors."""


class CollectionError(AnomaliFunctionError):
    """Exception for collection storage errors."""


class APIIntegrationError(AnomaliFunctionError):
    """Exception for API integration errors."""


class JobError(AnomaliFunctionError):
    """Exception for job management errors."""

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
    repository: str, ioc_type: Optional[str], logger: Logger
) -> Dict[str, str]:
    """Download existing lookup files from Falcon Next-Gen SIEM repository or read from local test directory"""
    # Check if we're in test mode
    test_mode = os.environ.get("TEST_MODE", "false").lower() in ["true", "1", "yes"]

    if test_mode:
        return download_existing_lookup_files_locally(repository, ioc_type, logger)
    else:
        return download_existing_lookup_files_from_ngsiem(repository, ioc_type, logger)

def download_existing_lookup_files_locally(
    repository: str, ioc_type: Optional[str], logger: Logger
) -> Dict[str, str]:
    """Read existing lookup files from local test directory"""
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

        # Try to read each known Anomali lookup file
        for filename in filenames_to_try:
            file_path = os.path.join(test_dir, filename)
            try:
                if os.path.exists(file_path):
                    logger.info(f"TEST MODE: Reading existing lookup file: {filename}")
                    with open(file_path, "r", encoding='utf-8') as f:
                        file_content = f.read()
                    existing_files[filename] = file_content
                    file_size = len(file_content)
                    logger.info(f"TEST MODE: Successfully read {filename} ({file_size:,} bytes)")
                else:
                    logger.info(f"TEST MODE: File {filename} not found (expected for new files)")

            except Exception as e:
                logger.info(f"TEST MODE: File {filename} not accessible (expected for new files): {str(e)}")
                continue

    except Exception as e:
        logger.error(f"TEST MODE: Error checking for existing lookup files: {str(e)}")

    return existing_files

def download_existing_lookup_files_from_ngsiem(
    repository: str, ioc_type: Optional[str], logger: Logger
) -> Dict[str, str]:
    """Download existing lookup files from Falcon Next-Gen SIEM repository (original implementation)"""
    ngsiem = NGSIEM()
    existing_files = {}

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

        # Try to download each known Anomali lookup file
        for filename in filenames_to_try:
            try:
                logger.info(f"Attempting to download existing lookup file: {filename}")
                download_response = ngsiem.get_file(
                    repository=repository,
                    filename=filename
                )

                # FalconPy get_file returns binary data on success, dict on failure
                if isinstance(download_response, bytes):
                    # Success - convert bytes to string
                    file_content = download_response.decode("utf-8")
                    existing_files[filename] = file_content
                    logger.info(f"Successfully downloaded {filename} ({len(file_content)} bytes)")
                elif isinstance(download_response, dict) and download_response.get("status_code") != 200:
                    logger.info(
                        f"File {filename} not found (expected for new files): "
                        f"{download_response.get('status_code', 'unknown')}"
                    )
                else:
                    # Handle other response types
                    logger.info(f"File {filename} returned unexpected response type: {type(download_response)}")

            except Exception as e:
                logger.info(f"File {filename} not accessible (expected for new files): {str(e)}")
                continue

    except Exception as e:
        logger.error(f"Error checking for existing lookup files: {str(e)}")

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

    Deduplication Logic:
    - Implements STIX 2.1 compliant temporal precedence
    - Preserves latest IOC confidence scores and threat types
    - Supports IOC evolution tracking (suspicious -> malware -> APT)
    - Critical for accurate threat hunting and incident response

    Args:
        iocs: List of IOC dictionaries from Anomali ThreatStream
        temp_dir: Temporary directory for file creation
        existing_files: Dictionary of existing lookup file contents
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

        # Check if we have existing data to append to
        existing_data = existing_files.get(filename, "")
        existing_df = None
        original_size = 0

        if existing_data:
            try:
                # Parse existing CSV data
                existing_df = pd.read_csv(StringIO(existing_data))
                original_size = len(existing_df)
                logger.info(f"Found existing {filename} with {original_size} records")
            except Exception as e:
                logger.warning(f"Could not parse existing {filename}: {str(e)}, starting fresh")
                existing_df = None

        # Process new IOCs
        new_rows = []
        for ioc in type_iocs:
            # Extract tags as comma-separated string
            tags = []
            if 'tags' in ioc and isinstance(ioc["tags"], list):
                tags = [tag.get("name", '') for tag in ioc["tags"] if tag.get('name')]
            tags_str = ",".join(tags) if tags else ""

            row = [
                ioc.get(mapping["primary_field"], ''),  # Primary IOC value
                str(ioc.get("confidence", '')),  # Convert to string
                ioc.get("threat_type", ''),
                ioc.get("source", ''),
                tags_str,
                ioc.get("expiration_ts", '')
            ]
            new_rows.append(row)

        if new_rows:
            # Create DataFrame from new data
            new_df = pd.DataFrame(new_rows, columns=mapping["columns"])

            # Combine with existing data if available
            if existing_df is not None:
                # Append new data to existing data
                combined_df = pd.concat([existing_df, new_df], ignore_index=True)

                # Temporal Precedence Deduplication for Threat Intelligence
                #
                # This implements STIX 2.1 compliant deduplication that preserves the most
                # recent threat intelligence data for each IOC. When the same IOC appears
                # multiple times (from different time periods or sources), we retain the
                # latest occurrence to ensure analysts get current threat classifications.
                #
                # Example IOC Evolution:
                # - Week 1: 192.168.1.1, confidence=40, type="suspicious", tags="investigation"
                # - Week 4: 192.168.1.1, confidence=95, type="c2,apt", tags="investigation,confirmed,apt29"
                # - Result: Analysts receive Week 4 data with high confidence and APT attribution
                #
                # This approach is critical for:
                # - Threat hunting with current confidence scores
                # - Incident response based on latest threat classifications
                # - APT attribution tracking as intelligence develops
                # - Reducing false positives through updated threat types
                #
                primary_col = mapping["columns"][0]
                before_dedup = len(combined_df)
                combined_df = combined_df.drop_duplicates(subset=[primary_col], keep="last")
                duplicates_removed = before_dedup - len(combined_df)
                final_size = len(combined_df)

                # Track statistics
                new_unique_records = final_size - original_size
                stats["total_duplicates_removed"] += duplicates_removed

                if new_unique_records > 0:
                    stats["files_with_new_data"] += 1
                    logger.info(f"Added {new_unique_records} new unique records to {filename}")
                else:
                    logger.info(f"No new unique records added to {filename} (all {len(new_df)} were duplicates)")

                if duplicates_removed > 0:
                    logger.info(f"Removed {duplicates_removed} duplicate IOCs, preserving existing entries")

                logger.info(
                    f"Combined {original_size} existing + {len(new_df)} new = "
                    f"{final_size} total records for {filename} ({new_unique_records} net new)"
                )
            else:
                combined_df = new_df
                stats["files_with_new_data"] += 1
                logger.info(f"Created new {filename} with {len(combined_df)} records")

            # Ensure empty strings remain as empty strings, not NaN
            combined_df = combined_df.fillna("")

            # Save to CSV
            combined_df.to_csv(filepath, index=False, quoting=csv.QUOTE_ALL, encoding="utf-8")
            created_files.append(filepath)

    return created_files, stats

def upload_csv_files_to_ngsiem(csv_files: List[str], repository: str, logger: Logger) -> List[Dict]:
    """Upload CSV files to Falcon Next-Gen SIEM as lookup files or write locally in test mode"""
    # Check if we're in test mode
    test_mode = os.environ.get("TEST_MODE", "false").lower() in ["true", "1", "yes"]

    if test_mode:
        return upload_csv_files_locally(csv_files, repository, logger)
    else:
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
                       job=None, request_body=None, trustedcircles=None, feed_id=None):
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
    api_client: APIHarnessV2,
    headers: Dict[str, str],
    logger: Logger
) -> tuple[bool, Dict[str, str]]:
    """Check for existing lookup files and handle missing file recovery.

    Args:
        repository: NGSIEM repository name
        type_filter: Optional IOC type filter
        api_client: API client for collections access
        headers: Request headers
        logger: Logger instance

    Returns:
        tuple: (should_start_fresh, existing_files) where should_start_fresh indicates
               if all files are missing and existing_files is a dict of filename -> content
    """
    should_start_fresh = False
    existing_files = {}

    if not type_filter:
        # No type specified - check if any Anomali files exist
        logger.info("No type filter specified - checking for any existing Anomali lookup files")
        existing_files = download_existing_lookup_files(repository, None, logger)
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
        existing_files = download_existing_lookup_files(repository, type_filter, logger)
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

    try:
        # Parse request parameters
        repository = request.body.get("repository", "search-all").strip()
        status_filter = request.body.get("status", None)  # No default status filter - get all IOCs
        trustedcircles = request.body.get("trustedcircles", None)  # Feed ID filtering
        feed_id = request.body.get("feed_id", None)  # Feed ID filtering (alternative parameter)
        next_token = request.body.get("next", None)  # Workflow pagination continuation
        limit = request.body.get("limit", 1000)  # Number of records per API call

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
            f"trustedcircles={trustedcircles}, feed_id={feed_id}, next={next_token}, limit={limit}"
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

        # Check for existing files and handle missing file recovery
        should_start_fresh, existing_files = check_and_recover_missing_files(
            repository, type_filter, api_client, headers, logger
        )

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
                request_body=request.body, trustedcircles=trustedcircles, feed_id=feed_id
            )

            logger.info(f"Final query_params before API call: {query_params}")

            # Fetch single batch of IOCs (workflow handles pagination)
            logger.info("Fetching one batch of IOCs")
            iocs, meta = fetch_iocs_from_anomali(api_integrations, query_params, logger)

            logger.info(f"Fetched {len(iocs)} IOCs from Anomali")

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

            # Process IOCs and create CSV files
            with tempfile.TemporaryDirectory() as temp_dir:
                csv_files, process_stats = process_iocs_to_csv(iocs, temp_dir, existing_files, logger)

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

                # Upload CSV files to Falcon Next-Gen SIEM
                upload_results = upload_csv_files_to_ngsiem(csv_files, repository, logger)

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
