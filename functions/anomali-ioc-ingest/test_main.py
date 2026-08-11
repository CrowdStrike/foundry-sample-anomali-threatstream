"""Test module for the Anomali ThreatStream IOC ingestion function."""
# pylint: disable=too-many-lines,too-many-public-methods,import-outside-toplevel
# pylint: disable=redefined-outer-name,reimported,unused-variable,unspecified-encoding

import csv
import re
import unittest
import importlib
from unittest.mock import patch, MagicMock, call
import tempfile
import os
import json

from crowdstrike.foundry.function import Request

import main


def mock_handler(*_args, **_kwargs):
    """Mock handler decorator for testing."""
    def identity(func):
        return func
    return identity


class AnomaliFunctionTestCase(unittest.TestCase):
    """Test case class for Anomali function handler tests."""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures once for all test methods."""
        cls.handler_patcher = patch("crowdstrike.foundry.function.Function.handler", new=mock_handler)
        cls.handler_patcher.start()
        # Mock time.sleep globally to prevent slow tests from retry/backoff logic
        cls.sleep_patcher = patch("main.time.sleep")
        cls.sleep_patcher.start()
        importlib.reload(main)

    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests."""
        cls.handler_patcher.stop()
        cls.sleep_patcher.stop()

    def test_get_last_update_id_not_found(self):
        """Test get_last_update_id when no previous update exists."""
        mock_custom_storage = MagicMock()
        mock_logger = MagicMock()
        headers = {"X-CS-APP-ID": "test-app"}

        # Mock GetObject to raise exception (object doesn't exist)
        mock_custom_storage.GetObject.side_effect = Exception("Object not found")

        result = main.get_last_update_id(mock_custom_storage, None, mock_logger)

        self.assertIsNone(result)
        mock_logger.info.assert_called_with("No previous update_id found for all types, will fetch recent data")

    def test_get_last_update_id_success(self):
        """Test get_last_update_id when previous update exists."""
        mock_custom_storage = MagicMock()
        mock_logger = MagicMock()
        headers = {"X-CS-APP-ID": "test-app"}

        update_data = {
            "update_id": "12345",
            "created_timestamp": "2024-01-01T10:00:00Z"
        }

        # Mock GetObject response - function uses direct GetObject approach
        mock_custom_storage.GetObject.return_value = json.dumps(update_data).encode('utf-8')

        result = main.get_last_update_id(mock_custom_storage, None, mock_logger)

        self.assertEqual(result, update_data)

    def test_get_last_update_id_not_found_due_to_error(self):
        """Test get_last_update_id when object doesn't exist (normal case)."""
        mock_custom_storage = MagicMock()
        mock_logger = MagicMock()

        # Mock the GetObject method to raise an exception (object not found)
        mock_custom_storage.GetObject.side_effect = Exception("Object not found")

        result = main.get_last_update_id(mock_custom_storage, None, mock_logger)

        # Should return None when object doesn't exist
        self.assertIsNone(result)

    def test_save_update_id_success(self):
        """Test save_update_id success."""
        mock_custom_storage = MagicMock()
        mock_logger = MagicMock()
        headers = {"X-CS-APP-ID": "test-app"}

        update_data = {"update_id": "12345"}
        mock_custom_storage.PutObject.return_value = {"status_code": 200}

        main.save_update_id(mock_custom_storage, update_data, None, mock_logger)

        mock_custom_storage.PutObject.assert_called_once_with(body=update_data,
                                                       collection_name="update_id_tracker",
                                                       object_key="last_update")

    def test_save_update_id_error(self):
        """Test save_update_id error handling."""
        mock_custom_storage = MagicMock()
        mock_logger = MagicMock()

        update_data = {"update_id": "12345"}
        mock_custom_storage.PutObject.return_value = {"status_code": 500}

        with self.assertRaises(Exception):
            main.save_update_id(mock_custom_storage, update_data, None, mock_logger)

    def test_create_job_first_run(self):
        """Test create_job for first run (no previous update)."""
        mock_custom_storage = MagicMock()
        mock_logger = MagicMock()
        headers = {"X-CS-APP-ID": "test-app"}

        mock_custom_storage.PutObject.return_value = {"status_code": 200}

        with patch('uuid.uuid4') as mock_uuid:
            # Create a mock UUID object that supports str() and slicing
            mock_uuid_obj = MagicMock()
            mock_uuid_obj.__str__ = MagicMock(return_value="test-job-id-12345678")
            mock_uuid.return_value = mock_uuid_obj

            result = main.create_job(mock_custom_storage, None, None, mock_logger)

            self.assertEqual(result["state"], "running")
            self.assertEqual(result["parameters"]["status"], "active")
            self.assertEqual(result["parameters"]["order_by"], "update_id")
            # First run doesn't have time constraints for fresh start
            self.assertNotIn("modified_ts_lt", result["parameters"])
            self.assertNotIn("modified_ts_gt", result["parameters"])
            # Cold start must omit the cursor entirely (some accounts reject a zero cursor)
            self.assertNotIn("update_id__gt", result["parameters"])
            self.assertNotIn("search_after", result["parameters"])

    def test_create_job_incremental_sync(self):
        """Test create_job for incremental sync (with previous update)."""
        mock_custom_storage = MagicMock()
        mock_logger = MagicMock()
        headers = {"X-CS-APP-ID": "test-app"}

        last_update = {"update_id": "12345"}
        mock_custom_storage.PutObject.return_value = {"status_code": 200}

        with patch('uuid.uuid4') as mock_uuid:
            # Create a mock UUID object that supports str() and slicing
            mock_uuid_obj = MagicMock()
            mock_uuid_obj.__str__ = MagicMock(return_value="test-job-id-12345678")
            mock_uuid.return_value = mock_uuid_obj

            result = main.create_job(mock_custom_storage, last_update, "hash", mock_logger)

            self.assertEqual(result["parameters"]["search_after"], "12345")

    def test_fetch_iocs_from_anomali_success(self):
        """Test fetch_iocs_from_anomali success."""
        mock_api_integrations = MagicMock()
        mock_logger = MagicMock()

        mock_response = {
            "status_code": 200,
            "body": {
                "objects": [
                    {"id": 1, "itype": "ip", "ip": "1.2.3.4"},
                    {"id": 2, "itype": "domain", "value": "evil.com"}
                ],
                "meta": {"total_count": 2, "next": None}
            }
        }

        mock_api_integrations.execute_command_proxy.return_value = mock_response

        params = {"status": "active"}
        iocs, meta = main.fetch_iocs_from_anomali(mock_api_integrations, params, mock_logger)

        self.assertEqual(len(iocs), 2)
        self.assertEqual(meta["total_count"], 2)

        mock_api_integrations.execute_command_proxy.assert_called_once_with(
            definition_id="Anomali API",
            operation_id="Intelligence",
            params={"query": params}
        )

    def test_no_hardcoded_definition_ids(self):
        """Test that no hardcoded definition IDs are used in the source code."""
        # Read the main.py file content
        with open('main.py', 'r', encoding='utf-8') as f:
            content = f.read()

        # Pattern to match potential hardcoded UUIDs/IDs (32 hex chars)
        uuid_pattern = r'definition_id\s*=\s*["\'][a-f0-9]{32}["\']'

        matches = re.findall(uuid_pattern, content, re.IGNORECASE)

        # Should not find any hardcoded definition IDs
        self.assertEqual(len(matches), 0,
                        f"Found hardcoded definition_id(s): {matches}. "
                        f"Use descriptive names like 'Anomali API' instead.")

        # Ensure we're using the correct descriptive name
        self.assertIn('definition_id="Anomali API"', content,
                     "Should use descriptive definition_id='Anomali API'")

    @patch.dict(os.environ, {"TEST_MODE": "true"})
    @patch('main.APIIntegrations')
    @patch('main.CustomStorage')
    @patch('main.download_existing_lookup_files')
    @patch('main.clear_update_id_for_type')
    @patch('main.NGSIEM')
    def test_missing_file_recovery_scenario(self, mock_ngsiem_class, mock_clear_update_id,
                                          mock_download_files, mock_custom_storage_class,
                                          mock_api_integrations_class):
        """Test missing file recovery only clears update_ids for previously tracked types."""
        from crowdstrike.foundry.function import Request

        # Setup mocks
        mock_api_integrations = MagicMock()
        mock_custom_storage = MagicMock()
        mock_ngsiem = MagicMock()
        mock_api_integrations_class.return_value = mock_api_integrations
        mock_custom_storage_class.return_value = mock_custom_storage
        mock_ngsiem_class.return_value = mock_ngsiem
        mock_logger = MagicMock()

        # Mock NGSIEM upload response
        mock_ngsiem.upload_file.return_value = {
            "status_code": 200,
            "body": {"message": "Success"}
        }

        # Simulate scenario: only ip and domain files exist
        mock_download_files.return_value = {
            "anomali_threatstream_ip.csv": "existing,data\n1.2.3.4,90",
            "anomali_threatstream_domain.csv": "existing,data\nevil.com,95"
            # Missing: url, email, hash_md5, hash_sha1, hash_sha256 files
        }

        # Missing types checked in IOC_TYPE_MAPPINGS order:
        #   url -> tracker_key "url" -> GetObject succeeds
        #   email -> tracker_key "email" -> GetObject succeeds
        #   hash_md5 -> tracker_key "hash" -> GetObject raises
        #   hash_sha1 -> tracker_key "hash" -> GetObject raises
        #   hash_sha256 -> tracker_key "hash" -> GetObject raises
        # Then get_last_update_id calls GetObject (not found)
        mock_custom_storage.GetObject.side_effect = [
            b'{"update_id": "100"}',   # check tracker for url -> exists
            b'{"update_id": "101"}',   # check tracker for email -> exists
            Exception("Not found"),     # check tracker for hash_md5 (key: hash)
            Exception("Not found"),     # check tracker for hash_sha1 (key: hash)
            Exception("Not found"),     # check tracker for hash_sha256 (key: hash)
            Exception("Object not found"),  # get_last_update_id
        ]
        # create_job + save_update_id + update_job: PutObject calls
        mock_custom_storage.PutObject.side_effect = [
            {"status_code": 200},  # create_job
            {"status_code": 200},  # save_update_id
            {"status_code": 200},  # update_job (completed)
        ]

        mock_api_integrations.execute_command_proxy.return_value = {
            "status_code": 200,
            "body": {
                "objects": [
                    {"id": 1, "itype": "url", "value": "http://evil.com", "update_id": "123"}
                ],
                "meta": {"total_count": 1, "next": None}
            }
        }

        request = Request()
        request.body = {"repository": "search-all"}  # No type filter = all types

        response = main.on_post(request, _config=None, logger=mock_logger)

        expected_clear_calls = [
            call(mock_custom_storage, "url", mock_logger),
            call(mock_custom_storage, "email", mock_logger),
        ]
        mock_clear_update_id.assert_has_calls(expected_clear_calls, any_order=True)
        self.assertEqual(mock_clear_update_id.call_count, 2)

        for c in mock_custom_storage.DeleteObject.call_args_list:
            self.assertNotEqual(
                c, call(collection_name="update_id_tracker", object_key="last_update"),
                "Main last_update key should not be cleared when only some types are missing"
            )

        self.assertEqual(response.code, 200)

    @patch('main.APIIntegrations')
    @patch('main.CustomStorage')
    @patch('main.NGSIEM')
    def test_no_valid_iocs_scenario(self, mock_ngsiem_class, mock_custom_storage_class, mock_api_integrations_class):
        """Test scenario where IOCs are fetched but none are valid for processing (lines 1441-1445)."""
        from crowdstrike.foundry.function import Request

        # Setup mocks
        mock_api_integrations = MagicMock()
        mock_custom_storage = MagicMock()
        mock_ngsiem = MagicMock()
        mock_api_integrations_class.return_value = mock_api_integrations
        mock_custom_storage_class.return_value = mock_custom_storage
        mock_ngsiem_class.return_value = mock_ngsiem
        mock_logger = MagicMock()

        # Mock NGSIEM - no existing files found (fresh start) - return 404 dict
        mock_ngsiem.get_file.return_value = {"status_code": 404}
        mock_ngsiem.upload_file.return_value = {
            "status_code": 200,
            "body": {"message": "Success"}
        }

        # Mock API responses - fresh start scenario requires clearing collection data
        # 9 keys: last_update + 8 type-specific (ip, domain, url, email, hash, hash_md5, hash_sha1, hash_sha256)
        mock_custom_storage.DeleteObject.side_effect = [Exception("Not found")] * 9
        # get_last_update_id
        mock_custom_storage.GetObject.side_effect = [
            Exception("Object not found"),
        ]
        # create_job + save_update_id + update_job (cursor saved before completion)
        mock_custom_storage.PutObject.side_effect = [
            {"status_code": 200},          # create_job
            {"status_code": 200},          # save_update_id
            {"status_code": 200},          # update_job (mark as completed)
        ]

        # Return IOCs with unknown/invalid types that can't be processed
        mock_api_integrations.execute_command_proxy.return_value = {
            "status_code": 200,
            "body": {
                "objects": [
                    {"id": 1, "itype": "unknown_type", "value": "some_value", "update_id": "789"},
                    {"id": 2, "itype": "invalid_type", "value": "other_value", "update_id": "790"}
                ],
                "meta": {"total_count": 2, "next": None}
            }
        }

        request = Request()
        request.body = {"repository": "search-all"}

        response = main.on_post(request, _config=None, logger=mock_logger)

        # Should return success but with no files created
        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["message"], "No valid IOCs to process")
        self.assertEqual(response.body["total_iocs"], 2)
        self.assertEqual(response.body["files_created"], 0)
        self.assertNotIn("next", response.body)  # No next field when meta.next is None

    @patch('main.APIIntegrations')
    @patch('main.CustomStorage')
    @patch('main.NGSIEM')
    def test_no_valid_iocs_advances_cursor_with_next(
        self, mock_ngsiem_class, mock_custom_storage_class, mock_api_integrations_class
    ):
        """Test that unsupported IOC types with meta 'next' advances cursor."""
        from crowdstrike.foundry.function import Request

        # Setup mocks
        mock_api_integrations = MagicMock()
        mock_custom_storage = MagicMock()
        mock_ngsiem = MagicMock()
        mock_api_integrations_class.return_value = mock_api_integrations
        mock_custom_storage_class.return_value = mock_custom_storage
        mock_ngsiem_class.return_value = mock_ngsiem
        mock_logger = MagicMock()

        # Mock NGSIEM - no existing files found (fresh start)
        mock_ngsiem.get_file.return_value = {"status_code": 404}

        # Mock API responses - fresh start
        mock_custom_storage.DeleteObject.side_effect = [Exception("Not found")] * 9
        mock_custom_storage.GetObject.side_effect = [
            Exception("Object not found"),
        ]
        # create_job + save_update_id + update_job (cursor saved before completion)
        mock_custom_storage.PutObject.side_effect = [
            {"status_code": 200},          # create_job
            {"status_code": 200},          # save_update_id
            {"status_code": 200},          # update_job (mark as completed)
        ]

        # Return IOCs with unsupported types BUT meta has a valid "next" URL
        mock_api_integrations.execute_command_proxy.return_value = {
            "status_code": 200,
            "body": {
                "objects": [
                    {"id": 1, "itype": "unknown_type", "value": "val1", "update_id": "100"},
                    {"id": 2, "itype": "another_unknown", "value": "val2", "update_id": "101"}
                ],
                "meta": {
                    "total_count": 1000,
                    "next": "/api/v2/intelligence/?update_id__gt=101&limit=1000"
                }
            }
        }

        request = Request()
        request.body = {"repository": "search-all"}

        response = main.on_post(request, _config=None, logger=mock_logger)

        # Should return success with 0 files but cursor must advance
        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["files_created"], 0)
        self.assertEqual(response.body["total_iocs"], 2)
        # Critical: "next" field MUST be present so pagination continues
        self.assertIn("next", response.body)
        self.assertEqual(response.body["next"], "101")

        # Critical: the cursor MUST be persisted via save_update_id so a fresh
        # run doesn't re-fetch the same page. Verify a PutObject wrote the
        # update tracker with the advanced update_id (not just the response next).
        save_update_calls = [
            c for c in mock_custom_storage.PutObject.call_args_list
            if c.kwargs.get("collection_name") == main.COLLECTION_UPDATE_TRACKER
        ]
        self.assertEqual(len(save_update_calls), 1, "save_update_id must be called exactly once")
        self.assertEqual(save_update_calls[0].kwargs["body"]["update_id"], "101")

    @patch('main.APIIntegrations')
    @patch('main.CustomStorage')
    @patch('main.NGSIEM')
    def test_no_valid_iocs_advances_cursor_without_meta(
        self, mock_ngsiem_class, mock_custom_storage_class, mock_api_integrations_class
    ):
        """Test cursor still advances when IOCs exist but meta is empty."""
        from crowdstrike.foundry.function import Request

        mock_api_integrations = MagicMock()
        mock_custom_storage = MagicMock()
        mock_ngsiem = MagicMock()
        mock_api_integrations_class.return_value = mock_api_integrations
        mock_custom_storage_class.return_value = mock_custom_storage
        mock_ngsiem_class.return_value = mock_ngsiem
        mock_logger = MagicMock()

        mock_ngsiem.get_file.return_value = {"status_code": 404}
        mock_custom_storage.DeleteObject.side_effect = [Exception("Not found")] * 9
        mock_custom_storage.GetObject.side_effect = [Exception("Object not found")]
        mock_custom_storage.PutObject.side_effect = [
            {"status_code": 200},          # create_job
            {"status_code": 200},          # save_update_id
            {"status_code": 200},          # update_job (mark as completed)
        ]

        # Unsupported types, and meta is empty (API omitted the envelope)
        mock_api_integrations.execute_command_proxy.return_value = {
            "status_code": 200,
            "body": {
                "objects": [
                    {"id": 1, "itype": "unknown_type", "value": "val1", "update_id": "100"},
                    {"id": 2, "itype": "another_unknown", "value": "val2", "update_id": "101"}
                ],
                "meta": {}
            }
        }

        request = Request()
        request.body = {"repository": "search-all"}

        response = main.on_post(request, _config=None, logger=mock_logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["files_created"], 0)
        # No meta.next, so no "next" token, but the cursor MUST still advance
        self.assertNotIn("next", response.body)
        save_update_calls = [
            c for c in mock_custom_storage.PutObject.call_args_list
            if c.kwargs.get("collection_name") == main.COLLECTION_UPDATE_TRACKER
        ]
        self.assertEqual(len(save_update_calls), 1, "cursor must advance even without meta")
        self.assertEqual(save_update_calls[0].kwargs["body"]["update_id"], "101")

    @patch('main.APIIntegrations')
    @patch('main.CustomStorage')
    def test_api_error_handling(self, mock_custom_storage_class, mock_api_integrations_class):
        """Test API error handling in fetch_iocs_from_anomali (lines 552-556)."""
        from crowdstrike.foundry.function import Request

        # Setup mocks
        mock_api_integrations = MagicMock()
        mock_custom_storage = MagicMock()
        mock_api_integrations_class.return_value = mock_api_integrations
        mock_custom_storage_class.return_value = mock_custom_storage
        mock_logger = MagicMock()

        # Mock collection operations to succeed
        mock_custom_storage.GetObject.side_effect = [
            Exception("Object not found"),  # get_last_update_id
        ]
        mock_custom_storage.PutObject.side_effect = [
            {"status_code": 200},  # create_job
            {"status_code": 200},  # update_job (mark as failed)
        ]

        # Simulate API integration throwing an exception after retries
        mock_api_integrations.execute_command_proxy.side_effect = Exception("Network timeout")

        request = Request()
        request.body = {"repository": "search-all"}

        response = main.on_post(request, _config=None, logger=mock_logger)

        # Should return 500 error
        self.assertEqual(response.code, 500)
        self.assertEqual(len(response.errors), 1)
        # Check that error message contains relevant information about the network timeout
        error_message = str(response.errors[0].message).lower()
        self.assertTrue("network timeout" in error_message or "internal error" in error_message)

    def test_csv_processing_error_handling(self):
        """Test error handling when CSV processing fails (line 848-850 area)."""
        import tempfile

        mock_logger = MagicMock()

        # Test with existing file that has invalid CSV data
        existing_files = {
            "anomali_threatstream_ip.csv": "invalid,csv,data\nno,proper,structure"
        }

        iocs = [
            {
                "itype": "ip",
                "ip": "1.2.3.4",
                "confidence": 90,
                "threat_type": "malware",
                "meta": {"severity": "high"},
                "source": "test",
                "tags": [],
                "expiration_ts": ""
            }
        ]

        # This should handle the CSV parsing error gracefully
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_files, stats = main.process_iocs_to_csv(iocs, temp_dir, existing_files, mock_logger)

            # Should create file despite existing invalid CSV (starts fresh)
            self.assertEqual(len(csv_files), 1)
            self.assertEqual(stats['files_with_new_data'], 1)

            # Verify that the function completed without errors despite invalid existing CSV

    def test_fetch_iocs_from_anomali_error(self):
        """Test fetch_iocs_from_anomali error handling."""
        mock_api_integrations = MagicMock()
        mock_logger = MagicMock()

        mock_response = {
            "status_code": 400,
            "body": {"errors": ["Bad request"]}
        }

        mock_api_integrations.execute_command_proxy.return_value = mock_response

        with self.assertRaises(Exception):
            main.fetch_iocs_from_anomali(mock_api_integrations, {}, mock_logger)

    def test_process_iocs_to_csv_ip_type(self):
        """Test process_iocs_to_csv with IP IOCs."""
        mock_logger = MagicMock()

        iocs = [
            {
                "itype": "ip",
                "ip": "1.2.3.4",
                "confidence": 90,
                "threat_type": "malware",
                "meta": {"severity": "high"},
                "source": "test",
                "tags": [{"name": "botnet"}, {"name": "c2"}],
                "expiration_ts": "2024-12-31T23:59:59Z"
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_files, stats = main.process_iocs_to_csv(iocs, temp_dir, {}, mock_logger)

            self.assertEqual(len(csv_files), 1)
            self.assertTrue(csv_files[0].endswith("anomali_threatstream_ip.csv"))

            # Check statistics
            self.assertEqual(stats['total_new_iocs'], 1)
            self.assertEqual(stats['total_duplicates_removed'], 0)
            self.assertEqual(stats['files_with_new_data'], 1)

            # Verify CSV content
            with open(csv_files[0], 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["destination.ip"], "1.2.3.4")
            self.assertEqual(rows[0]["confidence"], "90")
            self.assertEqual(rows[0]["tags"], "botnet,c2")

    def test_process_iocs_to_csv_domain_type(self):
        """Test process_iocs_to_csv with domain IOCs."""
        mock_logger = MagicMock()

        iocs = [
            {
                "itype": "domain",
                "value": "evil.com",
                "confidence": 85,
                "threat_type": "phishing",
                "meta": {"severity": "medium"},
                "source": "test",
                "tags": [],
                "expiration_ts": ""
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_files, stats = main.process_iocs_to_csv(iocs, temp_dir, {}, mock_logger)

            self.assertEqual(len(csv_files), 1)
            self.assertTrue(csv_files[0].endswith("anomali_threatstream_domain.csv"))

            # Verify CSV content
            with open(csv_files[0], 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["dns.domain.name"], "evil.com")
            self.assertEqual(rows[0]["tags"], "")

    def test_process_iocs_to_csv_itype_mapping(self):
        """Test process_iocs_to_csv with IOC type mapping."""
        mock_logger = MagicMock()

        iocs = [
            {"itype": "mal_ip", "ip": "1.2.3.4", "confidence": 90},
            {"itype": "c2_domain", "value": "evil.com", "confidence": 85},
            {"itype": "apt_md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "confidence": 95}
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_files, stats = main.process_iocs_to_csv(iocs, temp_dir, {}, mock_logger)

            self.assertEqual(len(csv_files), 3)
            filenames = [os.path.basename(f) for f in csv_files]
            self.assertIn("anomali_threatstream_ip.csv", filenames)
            self.assertIn("anomali_threatstream_domain.csv", filenames)
            self.assertIn("anomali_threatstream_hash_md5.csv", filenames)

    def test_process_iocs_to_csv_unknown_type(self):
        """Test process_iocs_to_csv with unknown IOC type."""
        mock_logger = MagicMock()

        iocs = [
            {"itype": "unknown_type", "value": "test", "confidence": 90}
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_files, stats = main.process_iocs_to_csv(iocs, temp_dir, {}, mock_logger)

            self.assertEqual(len(csv_files), 0)
            mock_logger.warning.assert_called()

    def test_process_iocs_to_csv_compromised_email(self):
        """Test process_iocs_to_csv normalizes compromised_email to email type."""
        mock_logger = MagicMock()

        iocs = [
            {"itype": "compromised_email", "value": "victim@example.com",
             "confidence": 80, "threat_type": "compromised", "source": "anomali",
             "tags": [], "expiration_ts": "", "meta": {}}
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_files, stats = main.process_iocs_to_csv(iocs, temp_dir, {}, mock_logger)

            self.assertEqual(len(csv_files), 1)
            filename = os.path.basename(csv_files[0])
            self.assertEqual(filename, "anomali_threatstream_email.csv")

            with open(csv_files[0], 'r') as f:
                content = f.read()
            self.assertIn("email.sender.address", content)
            self.assertIn("victim@example.com", content)

    @patch('main.NGSIEM')
    def test_upload_csv_files_to_ngsiem_success(self, mock_ngsiem_class):
        """Test upload_csv_files_to_ngsiem success."""
        mock_ngsiem = MagicMock()
        mock_ngsiem_class.return_value = mock_ngsiem
        mock_logger = MagicMock()

        mock_ngsiem.upload_file.return_value = {
            "status_code": 200,
            "body": {"message": "Success"}
        }

        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as temp_file:
            temp_file.write(b"test,data\n1,2")
            temp_file.flush()

            try:
                results = main.upload_csv_files_to_ngsiem([temp_file.name], "search-all", mock_logger)

                self.assertEqual(len(results), 1)
                self.assertEqual(results[0]["status"], "success")

                mock_ngsiem.upload_file.assert_called_once_with(
                    lookup_file=temp_file.name,
                    repository="search-all"
                )
            finally:
                os.unlink(temp_file.name)

    @patch('main.NGSIEM')
    def test_upload_csv_files_to_ngsiem_error(self, mock_ngsiem_class):
        """Test upload_csv_files_to_ngsiem error handling."""
        mock_ngsiem = MagicMock()
        mock_ngsiem_class.return_value = mock_ngsiem
        mock_logger = MagicMock()

        mock_ngsiem.upload_file.return_value = {
            "status_code": 400,
            "body": {"errors": ["Upload failed"]}
        }

        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as temp_file:
            try:
                results = main.upload_csv_files_to_ngsiem([temp_file.name], "search-all", mock_logger)

                self.assertEqual(len(results), 1)
                self.assertEqual(results[0]["status"], "error")
                self.assertIn("Upload failed", results[0]["message"])
            finally:
                os.unlink(temp_file.name)

    @patch('main.APIIntegrations')
    @patch('main.CustomStorage')
    def test_on_post_success_minimal(self, mock_custom_storage_class, mock_api_integrations_class):
        """Test successful POST request with minimal parameters."""
        # Setup mocks
        mock_api_integrations = MagicMock()
        mock_custom_storage = MagicMock()
        mock_api_integrations_class.return_value = mock_api_integrations
        mock_custom_storage_class.return_value = mock_custom_storage
        mock_logger = MagicMock()

        # Mock API harness commands for type-specific sync:
        # When type is provided but no existing files found, triggers fresh start
        mock_custom_storage.GetObject.side_effect = [
            Exception("Object not found"),  # get_last_update_id (not found - expected)
        ]
        mock_custom_storage.PutObject.side_effect = [
            {"status_code": 200},          # create_job
            {"status_code": 200},          # save_update_id
            {"status_code": 200},          # update_job (completed)
        ]

        # Mock Anomali API response
        mock_api_integrations.execute_command_proxy.return_value = {
            "status_code": 200,
            "body": {
                "objects": [
                    {
                        "itype": "ip",
                        "ip": "1.2.3.4",
                        "confidence": 90,
                        "threat_type": "malware",
                        "meta": {"severity": "high"},
                        "source": "test",
                        "tags": [],
                        "expiration_ts": "",
                        "update_id": "12345"
                    }
                ],
                "meta": {"total_count": 1, "next": None}
            }
        }

        with patch('main.NGSIEM') as mock_ngsiem_class:
            mock_ngsiem = MagicMock()
            mock_ngsiem_class.return_value = mock_ngsiem
            # Mock that no existing files are found initially (return 404 dict)
            mock_ngsiem.get_file.return_value = {"status_code": 404}
            mock_ngsiem.upload_file.return_value = {
                "status_code": 200,
                "body": {"message": "Success"}
            }

            request = Request()
            request.body = {"type": "ip"}  # Add type to avoid fresh start

            response = main.on_post(request, _config=None, logger=mock_logger)

            self.assertEqual(response.code, 200)
            self.assertEqual(response.body["total_iocs"], 1)
            self.assertEqual(response.body["files_created"], 1)
            self.assertEqual(len(response.body["upload_results"]), 1)
            # No next field when pagination complete
            self.assertNotIn("next", response.body)

    @patch('main.APIIntegrations')
    @patch('main.CustomStorage')
    def test_on_post_no_iocs_found(self, mock_custom_storage_class, mock_api_integrations_class):
        """Test POST request when no IOCs are found."""
        # Setup mocks
        mock_api_integrations = MagicMock()
        mock_custom_storage = MagicMock()
        mock_api_integrations_class.return_value = mock_api_integrations
        mock_custom_storage_class.return_value = mock_custom_storage
        mock_logger = MagicMock()

        # Mock API harness commands for type-specific sync:
        # 1. get_last_update_id calls GetObject - should fail (no previous update)
        # 2. create_job calls PutObject (success)
        # 3. update_job calls PutObject (success for completion)
        # Note: clear_update_id_for_type is no longer called when files are missing
        # (the update_id tracks API progress, not file existence)
        mock_custom_storage.GetObject.side_effect = [
            Exception("Object not found"),  # GetObject for last update (not found - expected)
        ]
        mock_custom_storage.PutObject.side_effect = [
            {"status_code": 200},          # PutObject for create_job
            {"status_code": 200},          # PutObject for update_job (completed)
        ]

        # Mock Anomali API response with no objects
        mock_api_integrations.execute_command_proxy.return_value = {
            "status_code": 200,
            "body": {
                "objects": [],
                "meta": {"total_count": 0, "next": None}
            }
        }

        with patch('main.NGSIEM') as mock_ngsiem_class, \
             patch('uuid.uuid4') as mock_uuid:
            mock_ngsiem = MagicMock()
            mock_ngsiem_class.return_value = mock_ngsiem
            # Mock that no existing files are found (return 404 dict)
            mock_ngsiem.get_file.return_value = {"status_code": 404}

            # Mock UUID for job creation
            mock_uuid_obj = MagicMock()
            mock_uuid_obj.__str__ = MagicMock(return_value="test-job-id-12345678")
            mock_uuid.return_value = mock_uuid_obj

            request = Request()
            request.body = {"repository": "test-repo", "type": "ip"}  # Add type to avoid fresh start

            response = main.on_post(request, _config=None, logger=mock_logger)

            self.assertEqual(response.code, 200)
            self.assertEqual(response.body["message"], "No IOCs found matching criteria")
            # No next field when pagination complete
            self.assertNotIn("next", response.body)

    @patch('main.APIIntegrations')
    @patch('main.CustomStorage')
    def test_on_post_anomali_api_error(self, mock_custom_storage_class, mock_api_integrations_class):
        """Test POST request when Anomali API returns error."""
        # Setup mocks
        mock_api_integrations = MagicMock()
        mock_custom_storage = MagicMock()
        mock_api_integrations_class.return_value = mock_api_integrations
        mock_custom_storage_class.return_value = mock_custom_storage
        mock_logger = MagicMock()

        # Mock get_last_update_id (no previous update) - GetObject raises exception
        mock_custom_storage.GetObject.side_effect = [
            Exception("Object not found"),  # GetObject for last update (not found)
        ]
        mock_custom_storage.PutObject.side_effect = [
            {"status_code": 200},  # PutObject for create_job
            {"status_code": 200},  # PutObject for update_job (failed)
        ]

        # Mock Anomali API error
        mock_api_integrations.execute_command_proxy.return_value = {
            "status_code": 401,
            "body": {"errors": ["Authentication failed"]}
        }

        with patch('uuid.uuid4') as mock_uuid:
            # Create a mock UUID object that supports str() and slicing
            mock_uuid_obj = MagicMock()
            mock_uuid_obj.__str__ = MagicMock(return_value="test-job-id-12345678")
            mock_uuid.return_value = mock_uuid_obj

            request = Request()
            request.body = {}

            response = main.on_post(request, _config=None, logger=mock_logger)

            self.assertEqual(response.code, 500)
            self.assertEqual(len(response.errors), 1)
            self.assertIn("Internal error", response.errors[0].message)

    def test_comma_separated_types_error(self):
        """Test POST request with comma-separated types returns error."""
        from crowdstrike.foundry.function import Request

        request = Request()
        request.body = {"type": "ip,domain"}  # Comma-separated types should error

        mock_logger = MagicMock()
        response = main.on_post(request, _config=None, logger=mock_logger)

        self.assertEqual(response.code, 400)
        self.assertEqual(len(response.errors), 1)
        self.assertIn("Comma-delimited types not supported", response.errors[0].message)
        self.assertIn("Use no type filter to get all types", response.errors[0].message)
        self.assertIn("Supported types:", response.errors[0].message)

    @patch('main.APIIntegrations')
    @patch('main.CustomStorage')
    def test_on_post_rate_limiting_retry(self, mock_custom_storage_class, mock_api_integrations_class):
        """Test POST request with rate limiting that succeeds on retry."""
        # Setup mocks
        mock_api_integrations = MagicMock()
        mock_custom_storage = MagicMock()
        mock_api_integrations_class.return_value = mock_api_integrations
        mock_custom_storage_class.return_value = mock_custom_storage
        mock_logger = MagicMock()

        # Mock API harness commands - need collection operations for type-specific sync
        mock_custom_storage.GetObject.side_effect = [
            Exception("Object not found"),  # get_last_update_id (not found)
        ]
        mock_custom_storage.PutObject.side_effect = [
            {"status_code": 200},          # create_job
            {"status_code": 200},          # save_update_id
            {"status_code": 200},          # update_job (completed)
        ]

        # Mock rate limit on first call, success on second
        mock_api_integrations.execute_command_proxy.side_effect = [
            {
                "status_code": 429,
                "body": {"errors": "Rate limit exceeded"}
            },
            {
                "status_code": 200,
                "body": {
                    "objects": [
                        {
                            "itype": "ip",
                            "ip": "1.2.3.4",
                            "confidence": 90,
                            "threat_type": "malware",
                            "meta": {"severity": "high"},
                            "source": "test",
                            "tags": [],
                            "expiration_ts": "",
                            "update_id": "12345"
                        }
                    ],
                    "meta": {"total_count": 1, "next": None}
                }
            }
        ]

        with patch('main.NGSIEM') as mock_ngsiem_class, \
             patch('main.time.sleep') as mock_sleep:
            mock_ngsiem = MagicMock()
            mock_ngsiem_class.return_value = mock_ngsiem
            # Mock that no existing files are found (return 404 dict)
            mock_ngsiem.get_file.return_value = {"status_code": 404}
            mock_ngsiem.upload_file.return_value = {
                "status_code": 200,
                "body": {"message": "Success"}
            }

            request = Request()
            request.body = {"type": "ip"}

            response = main.on_post(request, _config=None, logger=mock_logger)

            self.assertEqual(response.code, 200)
            self.assertEqual(response.body["total_iocs"], 1)
            # Verify retry happened
            self.assertEqual(mock_api_integrations.execute_command_proxy.call_count, 2)
            mock_sleep.assert_called()

    def test_fetch_iocs_rate_limit_max_retries(self):
        """Test fetch_iocs_from_anomali when rate limit exceeds max retries."""
        mock_api_integrations = MagicMock()
        mock_logger = MagicMock()

        # Mock consistent rate limiting
        mock_api_integrations.execute_command_proxy.return_value = {
            "status_code": 429,
            "body": {"errors": "Rate limit exceeded"}
        }

        with patch('main.time.sleep'):
            with self.assertRaises(main.APIIntegrationError) as context:
                main.fetch_iocs_from_anomali(mock_api_integrations, {}, mock_logger, max_retries=2)

            self.assertIn("Rate limit exceeded after 2 retries", str(context.exception))

    def test_fetch_iocs_retry_after_header_integer(self):
        """Test fetch_iocs_from_anomali respects Retry-After header with integer seconds."""
        mock_api_integrations = MagicMock()
        mock_logger = MagicMock()

        # Mock rate limiting with Retry-After header (integer seconds)
        mock_api_integrations.execute_command_proxy.side_effect = [
            {
                "status_code": 429,
                "headers": {"Retry-After": "30"},
                "body": {"errors": "Rate limit exceeded"}
            },
            {
                "status_code": 200,
                "body": {
                    "objects": [{"id": 1, "itype": "ip", "ip": "1.2.3.4"}],
                    "meta": {"total_count": 1, "next": None}
                }
            }
        ]

        with patch('main.time.sleep') as mock_sleep:
            iocs, meta = main.fetch_iocs_from_anomali(mock_api_integrations, {}, mock_logger, max_retries=1)

            self.assertEqual(len(iocs), 1)
            # Verify it used the Retry-After value (30 seconds)
            mock_sleep.assert_called_once_with(30)

    def test_fetch_iocs_retry_after_header_invalid_fallback(self):
        """Test fetch_iocs_from_anomali falls back to exponential backoff for invalid Retry-After."""
        mock_api_integrations = MagicMock()
        mock_logger = MagicMock()

        # Mock rate limiting with invalid Retry-After header (HTTP date string that can't be parsed)
        mock_api_integrations.execute_command_proxy.side_effect = [
            {
                "status_code": 429,
                "headers": {"Retry-After": "Wed, 21 Oct 2024 07:28:00 GMT"},
                "body": {"errors": "Rate limit exceeded"}
            },
            {
                "status_code": 200,
                "body": {
                    "objects": [{"id": 1, "itype": "ip", "ip": "1.2.3.4"}],
                    "meta": {"total_count": 1, "next": None}
                }
            }
        ]

        with patch('main.time.sleep') as mock_sleep, \
             patch('main.random.uniform', return_value=1.0):
            iocs, meta = main.fetch_iocs_from_anomali(mock_api_integrations, {}, mock_logger, max_retries=1)

            self.assertEqual(len(iocs), 1)
            # Verify it fell back to exponential backoff: 5 * (2 ** 0) + 1.0 = 6.0
            mock_sleep.assert_called_once_with(6.0)

    def test_fetch_iocs_retry_after_header_missing(self):
        """Test fetch_iocs_from_anomali uses exponential backoff when Retry-After is missing."""
        mock_api_integrations = MagicMock()
        mock_logger = MagicMock()

        # Mock rate limiting without Retry-After header
        mock_api_integrations.execute_command_proxy.side_effect = [
            {
                "status_code": 429,
                "body": {"errors": "Rate limit exceeded"}
            },
            {
                "status_code": 200,
                "body": {
                    "objects": [{"id": 1, "itype": "ip", "ip": "1.2.3.4"}],
                    "meta": {"total_count": 1, "next": None}
                }
            }
        ]

        with patch('main.time.sleep') as mock_sleep, \
             patch('main.random.uniform', return_value=1.5):
            iocs, meta = main.fetch_iocs_from_anomali(mock_api_integrations, {}, mock_logger, max_retries=1)

            self.assertEqual(len(iocs), 1)
            # Verify exponential backoff: 5 * (2 ** 0) + 1.5 = 6.5
            mock_sleep.assert_called_once_with(6.5)

    def test_process_iocs_with_existing_file_merge(self):
        """Test process_iocs_to_csv with existing file merge and deduplication (disk-based path)."""
        mock_logger = MagicMock()

        new_iocs = [
            {
                "itype": "ip",
                "ip": "1.2.3.4",  # Duplicate IP
                "confidence": 90,
                "threat_type": "malware",
                "meta": {"severity": "high"},
                "source": "test",
                "tags": [],
                "expiration_ts": ""
            },
            {
                "itype": "ip",
                "ip": "5.6.7.8",  # New IP
                "confidence": 85,
                "threat_type": "botnet",
                "meta": {"severity": "medium"},
                "source": "test2",
                "tags": [],
                "expiration_ts": ""
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            # Write existing file to a real temp path for disk-based merge
            existing_file_path = os.path.join(temp_dir, "existing_anomali_threatstream_ip.csv")
            with open(existing_file_path, 'w', encoding='utf-8') as f:
                f.write("destination.ip,confidence,threat_type,severity,source,tags,expiration_ts\n")
                f.write("1.2.3.4,95,existing,,original,tag1,2024-12-31T23:59:59Z\n")

            existing_files = {
                "anomali_threatstream_ip.csv": existing_file_path
            }

            csv_files, stats = main.process_iocs_to_csv(new_iocs, temp_dir, existing_files, mock_logger)

            self.assertEqual(len(csv_files), 1)

            # Verify merge and deduplication (new data takes precedence)
            with open(csv_files[0], 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            self.assertEqual(len(rows), 2)  # Original + new unique IP

            # Find rows by IP
            rows_by_ip = {row["destination.ip"]: row for row in rows}

            # Verify latest entry is preserved (new data takes precedence)
            self.assertEqual(rows_by_ip["1.2.3.4"]["confidence"], "90")  # Latest value
            self.assertEqual(rows_by_ip["1.2.3.4"]["source"], "test")  # Latest value

            # Verify new IP was added
            self.assertIn("5.6.7.8", rows_by_ip)

    @patch('main.NGSIEM')
    def test_upload_csv_files_500_error_recovery(self, mock_ngsiem_class):
        """Test upload recovery from 500 error with JSON parsing message."""
        mock_ngsiem = MagicMock()
        mock_ngsiem_class.return_value = mock_ngsiem
        mock_logger = MagicMock()

        # Mock 500 error with JSON parsing error (indicates successful upload)
        mock_ngsiem.upload_file.return_value = {
            "status_code": 500,
            "body": {
                "errors": [
                    {"message": "extra data: line 1 column 123 (char 122)"}
                ]
            }
        }

        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as temp_file:
            temp_file.write(b"test,data\n1,2")
            temp_file.flush()

            try:
                results = main.upload_csv_files_to_ngsiem([temp_file.name], "search-all", mock_logger)

                self.assertEqual(len(results), 1)
                self.assertEqual(results[0]["status"], "success")
                self.assertEqual(results[0]["message"], "File uploaded successfully")
            finally:
                os.unlink(temp_file.name)

    def test_clear_collection_data_success(self):
        """Test clear_collection_data functionality."""
        mock_custom_storage = MagicMock()
        mock_logger = MagicMock()
        headers = {"X-CS-APP-ID": "test-app"}

        # Mock successful deletion responses
        mock_custom_storage.DeleteObject.side_effect = [
            Exception("Object not found"),  # last_update (not found - OK)
            {"status_code": 200},          # last_update_ip
            {"status_code": 200},          # last_update_domain
            {"status_code": 200},          # last_update_url
            {"status_code": 200},          # last_update_email
            {"status_code": 200},          # last_update_hash
            {"status_code": 200},          # last_update_hash_md5
            {"status_code": 200},          # last_update_hash_sha1
            {"status_code": 200},          # last_update_hash_sha256
        ]

        # Should not raise exception
        main.clear_collection_data(mock_custom_storage, mock_logger)

        # Verify all delete operations were called
        # 9 keys: last_update + 8 type-specific (ip, domain, url, email, hash, hash_md5, hash_sha1, hash_sha256)
        self.assertEqual(mock_custom_storage.DeleteObject.call_count, 9)

    def test_save_update_id_error_handling(self):
        """Test save_update_id error handling."""
        mock_custom_storage = MagicMock()
        mock_logger = MagicMock()
        headers = {"X-CS-APP-ID": "test-app"}

        update_data = {"update_id": "12345"}
        mock_custom_storage.PutObject.return_value = {"status_code": 500}

        with self.assertRaises(main.CollectionError):
            main.save_update_id(mock_custom_storage, update_data, "ip", mock_logger)

    def test_update_job_success(self):
        """Test update_job success."""
        mock_custom_storage = MagicMock()
        mock_logger = MagicMock()
        headers = {"X-CS-APP-ID": "test-app"}

        job = {"id": "test-job", "state": "completed"}
        mock_custom_storage.PutObject.return_value = {"status_code": 200}

        main.update_job(mock_custom_storage, job, mock_logger)

        mock_custom_storage.PutObject.assert_called_once_with(body=job,
                                                       collection_name="ingest_jobs",
                                                       object_key="test-job")

    def test_ioc_type_mappings_completeness(self):
        """Test that all IOC type mappings are complete."""
        for _, mapping in main.IOC_TYPE_MAPPINGS.items():
            self.assertIn('columns', mapping)
            self.assertIn('primary_field', mapping)
            self.assertEqual(len(mapping['columns']), 7)  # Should have 7 columns
            self.assertIn('confidence', mapping['columns'])
            self.assertIn('threat_type', mapping['columns'])
            self.assertIn('severity', mapping['columns'])
            self.assertIn('source', mapping['columns'])
            self.assertIn('tags', mapping['columns'])
            self.assertIn('expiration_ts', mapping['columns'])

    @patch('main.APIIntegrations')
    @patch('main.CustomStorage')
    def test_no_iocs_returns_no_next_field(self, mock_custom_storage_class, mock_api_integrations_class):
        """Test that when no IOCs are found, next field is omitted from response."""
        # Setup mocks
        mock_api_integrations = MagicMock()
        mock_custom_storage = MagicMock()
        mock_api_integrations_class.return_value = mock_api_integrations
        mock_custom_storage_class.return_value = mock_custom_storage
        mock_logger = MagicMock()

        # Mock API harness calls:
        # 1. get_last_update_id calls GetObject (not found)
        # 2. create_job calls PutObject (success)
        # 3. update_job calls PutObject (success for completion)
        # Note: clear_update_id_for_type is no longer called when files are missing
        # (the update_id tracks API progress, not file existence)
        mock_custom_storage.GetObject.side_effect = [
            Exception("Object not found"),  # GetObject for last update (not found)
        ]
        mock_custom_storage.PutObject.side_effect = [
            {"status_code": 200},          # PutObject for create_job
            {"status_code": 200},          # PutObject for update_job (completed)
        ]

        # Mock Anomali API response with no objects
        mock_api_integrations.execute_command_proxy.return_value = {
            "status_code": 200,
            "body": {
                "objects": [],  # No IOCs
                "meta": {"total_count": 0, "next": None}
            }
        }

        with patch('main.NGSIEM') as mock_ngsiem_class, \
             patch('uuid.uuid4') as mock_uuid:
            mock_ngsiem = MagicMock()
            mock_ngsiem_class.return_value = mock_ngsiem
            # Return 404 dict for file not found (instead of exception)
            mock_ngsiem.get_file.return_value = {"status_code": 404}

            # Mock UUID for job creation
            mock_uuid_obj = MagicMock()
            mock_uuid_obj.__str__ = MagicMock(return_value="test-job-id-12345678")
            mock_uuid.return_value = mock_uuid_obj

            request = Request()
            request.body = {"repository": "test-repo", "type": "ip"}

            response = main.on_post(request, _config=None, logger=mock_logger)

            # Verify response structure
            self.assertEqual(response.code, 200)
            self.assertEqual(response.body["message"], "No IOCs found matching criteria")
            self.assertEqual(response.body["total_iocs"], 0)
            self.assertEqual(response.body["files_created"], 0)

            # Critical test: verify next field is omitted when pagination complete
            self.assertNotIn("next", response.body)

            # Verify JSON serialization doesn't include next field
            import json
            json_response = json.dumps(response.body)
            self.assertNotIn('"next"', json_response)

    @patch('main.NGSIEM')
    def test_download_existing_lookup_files_hash_mapping(self, mock_ngsiem_class):
        """Test download_existing_lookup_files with hash type mapping."""
        mock_ngsiem = MagicMock()
        mock_ngsiem_class.return_value = mock_ngsiem
        mock_logger = MagicMock()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Test md5 type mapping - return 404 dict for file not found
            mock_ngsiem.get_file.return_value = {"status_code": 404}
            result = main.download_existing_lookup_files("search-all", "md5", temp_dir, mock_logger)
            self.assertEqual(result, {})
            # Check that md5 was mapped to hash_md5
            call_args_list = [call[1]['filename'] for call in mock_ngsiem.get_file.call_args_list]
            self.assertIn("anomali_threatstream_hash_md5.csv", call_args_list)
            mock_ngsiem.reset_mock()

            # Test sha1 type mapping
            mock_ngsiem.get_file.return_value = {"status_code": 404}
            result = main.download_existing_lookup_files("search-all", "sha1", temp_dir, mock_logger)
            # Note: sha1 and sha256 are not currently mapped in the function, test what actually happens
            self.assertEqual(result, {})

    def test_extract_next_token_from_meta_variations(self):
        """Test extract_next_token_from_meta with different URL parameter variations."""
        mock_logger = MagicMock()

        test_cases = [
            # search_after parameter (highest priority)
            ({
                "next": "https://api.example.com/v1/intelligence/?search_after=12345&limit=1000"
            }, [{"update_id": "999"}], "12345"),

            # update_id__gt parameter
            ({
                "next": "https://api.example.com/v1/intelligence/?update_id__gt=67890&limit=1000"
            }, [{"update_id": "999"}], "67890"),

            # from_update_id parameter
            ({
                "next": "https://api.example.com/v1/intelligence/?from_update_id=11111&limit=1000"
            }, [{"update_id": "999"}], "11111"),

            # Fallback to last IOC update_id when no recognized parameters
            ({
                "next": "https://api.example.com/v1/intelligence/?some_other_param=xyz&limit=1000"
            }, [{"update_id": "fallback_id"}], "fallback_id"),

            # No next URL - should return None
            ({}, [{"update_id": "999"}], None),

            # Empty IOCs - should return None
            ({"next": "https://api.example.com/v1/intelligence/?search_after=12345"}, [], None),
        ]

        for meta, iocs, expected_result in test_cases:
            result = main.extract_next_token_from_meta(meta, iocs, mock_logger)
            self.assertEqual(result, expected_result)

    def test_extract_next_token_url_parsing_error(self):
        """Test extract_next_token_from_meta with URL parsing errors."""
        mock_logger = MagicMock()

        # Test with URL that has no recognized parameters (not an error, just fallback behavior)
        meta = {"next": "https://api.example.com/v1/intelligence/?unknown_param=xyz&limit=1000"}
        iocs = [{"update_id": "fallback_123"}]

        # The function should use fallback (last IOC's update_id) when no recognized parameters found
        result = main.extract_next_token_from_meta(meta, iocs, mock_logger)

        # Should fallback to last IOC's update_id
        self.assertEqual(result, "fallback_123")
        # Should have info log about fallback, but no warning since no actual parsing error occurred
        mock_logger.info.assert_called_with("More data available - next pagination token (fallback): fallback_123")

    def test_format_elapsed_time(self):
        """Test format_elapsed_time helper function."""
        # Test seconds only
        self.assertEqual(main.format_elapsed_time(30.5), "30.5s")
        self.assertEqual(main.format_elapsed_time(59.9), "59.9s")

        # Test minutes and seconds
        self.assertEqual(main.format_elapsed_time(60.0), "1m 0.0s")
        self.assertEqual(main.format_elapsed_time(65.3), "1m 5.3s")
        self.assertEqual(main.format_elapsed_time(125.7), "2m 5.7s")

    def test_exception_classes(self):
        """Test custom exception classes."""
        # Test base exception
        base_error = main.AnomaliFunctionError("Base error")
        self.assertEqual(str(base_error), "Base error")
        self.assertIsInstance(base_error, Exception)

        # Test collection error
        collection_error = main.CollectionError("Collection failed")
        self.assertEqual(str(collection_error), "Collection failed")
        self.assertIsInstance(collection_error, main.AnomaliFunctionError)

        # Test API integration error
        api_error = main.APIIntegrationError("API failed")
        self.assertEqual(str(api_error), "API failed")
        self.assertIsInstance(api_error, main.AnomaliFunctionError)

        # Test job error
        job_error = main.JobError("Job failed")
        self.assertEqual(str(job_error), "Job failed")
        self.assertIsInstance(job_error, main.AnomaliFunctionError)

    def test_build_query_params_error_handling(self):
        """Test build_query_params error handling with fallback case."""
        mock_api_client = MagicMock()
        mock_headers = {}
        mock_logger = MagicMock()

        # With the new architecture, build_query_params uses the fallback case
        # only when no job is provided. Test the error handling in that case
        result = main.build_query_params(
            None, "active", "ip", 1000, mock_api_client, mock_headers, mock_logger, None
        )

        # Should still work with fallback parameters (cursor omitted on cold start)
        self.assertNotIn("update_id__gt", result)
        self.assertNotIn("search_after", result)
        self.assertEqual(result["type"], "ip")
        self.assertEqual(result["status"], "active")

    def test_download_existing_lookup_files_multiple_types(self):
        """Test download_existing_lookup_files with hash type handling."""
        mock_logger = MagicMock()

        with patch('main.NGSIEM') as mock_ngsiem_class:
            mock_ngsiem = MagicMock()
            mock_ngsiem_class.return_value = mock_ngsiem

            with tempfile.TemporaryDirectory() as temp_dir:
                # Test "hash" type downloads all hash types - return 404 dict for file not found
                mock_ngsiem.get_file.return_value = {"status_code": 404}
                result = main.download_existing_lookup_files("search-all", "hash", temp_dir, mock_logger)

                # Should attempt to download md5, sha1, sha256 hash files
                call_args_list = [call[1]['filename'] for call in mock_ngsiem.get_file.call_args_list]
                hash_files = [f for f in call_args_list if 'hash' in f]
                self.assertGreater(len(hash_files), 0)
                self.assertEqual(result, {})

    def test_create_job_error_handling(self):
        """Test create_job with PutObject failure."""
        mock_api_client = MagicMock()
        mock_headers = {"X-CS-APP-ID": "test-app"}
        mock_logger = MagicMock()

        # Mock PutObject to return error status
        mock_api_client.PutObject.return_value = {"status_code": 500}

        with self.assertRaises(main.JobError):
            main.create_job(mock_api_client, None, "ip", mock_logger)

    def test_build_query_params_no_job_no_update(self):
        """Test build_query_params when no job exists and no saved update_id."""
        mock_api_client = MagicMock()
        mock_headers = {}
        mock_logger = MagicMock()

        # Mock get_last_update_id to return None (no saved update)
        with patch('main.get_last_update_id', return_value=None):
            result = main.build_query_params(
                None, "active", "ip", 1000, mock_api_client, mock_headers, mock_logger, None
            )

            # Should omit the cursor when no saved update_id (cold start)
            self.assertNotIn("update_id__gt", result)
            self.assertNotIn("search_after", result)
            self.assertEqual(result["type"], "ip")
            self.assertEqual(result["status"], "active")

    def test_fetch_iocs_api_integration_error_retry(self):
        """Test fetch_iocs_from_anomali with APIIntegrationError retry logic."""
        mock_api_integrations = MagicMock()
        mock_logger = MagicMock()

        # First call raises APIIntegrationError, second succeeds
        mock_api_integrations.execute_command_proxy.side_effect = [
            main.APIIntegrationError("Connection error"),
            {
                "status_code": 200,
                "body": {
                    "objects": [{"id": 1, "itype": "ip", "ip": "1.2.3.4"}],
                    "meta": {"total_count": 1, "next": None}
                }
            }
        ]

        with patch('main.time.sleep'):  # Mock sleep to speed up test
            with self.assertRaises(main.APIIntegrationError):
                # Should re-raise APIIntegrationError without retry
                main.fetch_iocs_from_anomali(mock_api_integrations, {}, mock_logger, max_retries=0)

    def test_download_existing_lookup_files_specific_type_filters(self):
        """Test download_existing_lookup_files with specific type filters beyond hash."""
        mock_logger = MagicMock()

        with patch('main.NGSIEM') as mock_ngsiem_class:
            mock_ngsiem = MagicMock()
            mock_ngsiem_class.return_value = mock_ngsiem
            # Mock that no existing files are found (return 404 dict)
            mock_ngsiem.get_file.return_value = {"status_code": 404}

            with tempfile.TemporaryDirectory() as temp_dir:
                # Test sha1 and sha256 specific types (these don't map to anything currently)
                result_sha1 = main.download_existing_lookup_files("search-all", "sha1", temp_dir, mock_logger)
                result_sha256 = main.download_existing_lookup_files("search-all", "sha256", temp_dir, mock_logger)

                self.assertEqual(result_sha1, {})
                self.assertEqual(result_sha256, {})

    def test_clear_update_id_for_type_success(self):
        """Test clear_update_id_for_type successful deletion."""
        mock_api_client = MagicMock()
        mock_headers = {"X-CS-APP-ID": "test-app"}
        mock_logger = MagicMock()

        mock_api_client.DeleteObject.return_value = {"status_code": 200}

        main.clear_update_id_for_type(mock_api_client, "ip", mock_logger)

        mock_api_client.DeleteObject.assert_called_once_with(
            collection_name="update_id_tracker",
            object_key="last_update_ip"
        )
        mock_logger.info.assert_any_call("Successfully cleared update_id for type ip")

    def test_clear_update_id_for_type_not_found(self):
        """Test clear_update_id_for_type when update_id doesn't exist."""
        mock_api_client = MagicMock()
        mock_headers = {"X-CS-APP-ID": "test-app"}
        mock_logger = MagicMock()

        mock_api_client.DeleteObject.side_effect = Exception("Object not found")

        # Should not raise exception, just log
        main.clear_update_id_for_type(mock_api_client, "domain", mock_logger)

        mock_logger.info.assert_any_call("No update_id to clear for type domain: Object not found")

    def test_update_job_error_handling(self):
        """Test update_job with PutObject failure."""
        mock_api_client = MagicMock()
        mock_headers = {"X-CS-APP-ID": "test-app"}
        mock_logger = MagicMock()

        job = {"id": "test-job", "state": "completed"}
        mock_api_client.PutObject.return_value = {"status_code": 500}

        with self.assertRaises(main.JobError):
            main.update_job(mock_api_client, job, mock_logger)

    def test_get_last_update_id_with_errors(self):
        """Test get_last_update_id with various error scenarios."""
        mock_api_client = MagicMock()
        mock_headers = {"X-CS-APP-ID": "test-app"}
        mock_logger = MagicMock()

        # Test with logger.info failure (should re-raise from outer exception handler)
        mock_api_client.GetObject.return_value = b'{"update_id": "123"}'
        mock_logger.info.side_effect = RuntimeError("Logger error")

        with self.assertRaises(RuntimeError):
            main.get_last_update_id(mock_api_client, "ip", mock_logger)

    def test_clear_collection_data_error_handling(self):
        """Test clear_collection_data error handling."""
        mock_api_client = MagicMock()
        mock_headers = {"X-CS-APP-ID": "test-app"}
        mock_logger = MagicMock()

        # Mock one DeleteObject call to fail
        mock_api_client.DeleteObject.side_effect = [
            Exception("Not found"),  # last_update (expected)
            RuntimeError("Unexpected error"),  # last_update_ip (unexpected)
            {"status_code": 200},  # remaining calls
            {"status_code": 200},
            {"status_code": 200},
            {"status_code": 200},
            {"status_code": 200},
            {"status_code": 200},
            {"status_code": 200},
        ]

        # Should not raise exception, just log errors
        main.clear_collection_data(mock_api_client, mock_logger)

        # Verify the expected number of calls were made
        # 9 keys: last_update + 8 type-specific (ip, domain, url, email, hash, hash_md5, hash_sha1, hash_sha256)
        self.assertEqual(mock_api_client.DeleteObject.call_count, 9)

    def test_process_iocs_existing_file_parse_error(self):
        """Test process_iocs_to_csv with existing file parsing error."""
        mock_logger = MagicMock()

        new_iocs = [
            {
                "itype": "ip",
                "ip": "1.2.3.4",
                "confidence": 90,
                "threat_type": "malware",
                "meta": {"severity": "high"},
                "source": "test",
                "tags": [],
                "expiration_ts": ""
            }
        ]

        # Existing file with truly invalid CSV content that will cause csv reader to fail
        existing_files = {
            "anomali_threatstream_ip.csv": "invalid\x00binary\x01content\x02"
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_files, stats = main.process_iocs_to_csv(new_iocs, temp_dir, existing_files, mock_logger)

            # Should create file despite parse error
            self.assertEqual(len(csv_files), 1)

            # Verify warning was logged about parse error
            # Just verify the function completed without raising an exception

    def test_save_update_id_with_errors(self):
        """Test save_update_id with various error scenarios."""
        mock_api_client = MagicMock()
        mock_headers = {"X-CS-APP-ID": "test-app"}
        mock_logger = MagicMock()

        update_data = {"update_id": "12345"}

        # Test with non-Exception error (should re-raise)
        mock_api_client.PutObject.side_effect = RuntimeError("Unexpected error")

        with self.assertRaises(RuntimeError):
            main.save_update_id(mock_api_client, update_data, "ip", mock_logger)

    def test_build_query_params_with_job_update_id(self):
        """Test build_query_params uses job's stored update_id."""
        mock_api_client = MagicMock()
        mock_headers = {}
        mock_logger = MagicMock()

        # Create a job with stored parameters
        job = {
            "id": "test-job",
            "parameters": {
                "search_after": "job_stored_12345",
                "status": "active"
            }
        }

        # Test that job's cursor is used instead of calling get_last_update_id
        result = main.build_query_params(
            None, "active", None, 1000, mock_api_client, mock_headers, mock_logger, job
        )

        # Should use job's stored cursor
        self.assertEqual(result["search_after"], "job_stored_12345")
        self.assertEqual(result["status"], "active")
        self.assertEqual(result["limit"], 1000)
        self.assertEqual(result["order_by"], "update_id")

        # Verify the new log message format
        expected_params = {
            'search_after': 'job_stored_12345', 'status': 'active',
            'limit': 1000, 'order_by': 'update_id'
        }
        mock_logger.info.assert_any_call(
            f"INITIAL: Using job's stored parameters: {expected_params}"
        )

    def test_build_query_params_job_fallback_to_direct_lookup(self):
        """Test build_query_params with job parameters (preferred approach)."""
        mock_api_client = MagicMock()
        mock_headers = {}
        mock_logger = MagicMock()

        # Create a job with stored parameters
        job = {
            "id": "test-job",
            "parameters": {
                "search_after": "job_stored_67890",
                "status": "active",
                "type": "ip"
            }
        }

        result = main.build_query_params(
            None, None, "ip", 1000, mock_api_client, mock_headers, mock_logger, job
        )

        # Should use job's stored parameters
        self.assertEqual(result["search_after"], "job_stored_67890")
        self.assertEqual(result["type"], "ip")
        self.assertEqual(result["status"], "active")
        self.assertEqual(result["limit"], 1000)
        self.assertEqual(result["order_by"], "update_id")

    def test_build_query_params_with_confidence_filters(self):
        """Test build_query_params with confidence filtering parameters."""
        mock_api_client = MagicMock()
        mock_headers = {}
        mock_logger = MagicMock()

        # Create a job with stored parameters
        job = {
            "id": "test-job",
            "parameters": {
                "search_after": "12345",
                "status": "active",
                "type": "ip"
            }
        }

        # Test with all confidence filters
        result = main.build_query_params(
            None, "active", "ip", 1000, mock_api_client, mock_headers, mock_logger, job,
            confidence_gt=50, confidence_gte=60, confidence_lt=90, confidence_lte=95
        )

        # Should include confidence filtering parameters
        self.assertEqual(result["confidence__gt"], 50)
        self.assertEqual(result["confidence__gte"], 60)
        self.assertEqual(result["confidence__lt"], 90)
        self.assertEqual(result["confidence__lte"], 95)

    def test_build_query_params_with_partial_confidence_filters(self):
        """Test build_query_params with only some confidence filters."""
        mock_api_client = MagicMock()
        mock_headers = {}
        mock_logger = MagicMock()

        job = {
            "id": "test-job",
            "parameters": {
                "search_after": "12345",
                "status": "active"
            }
        }

        # Test with only confidence_gte filter
        result = main.build_query_params(
            None, "active", None, 1000, mock_api_client, mock_headers, mock_logger, job,
            confidence_gte=70
        )

        # Should include only the specified confidence filter
        self.assertEqual(result["confidence__gte"], 70)
        self.assertNotIn("confidence__gt", result)
        self.assertNotIn("confidence__lt", result)
        self.assertNotIn("confidence__lte", result)

    def test_build_query_params_no_confidence_filters(self):
        """Test build_query_params without confidence filters (default behavior)."""
        mock_api_client = MagicMock()
        mock_headers = {}
        mock_logger = MagicMock()

        job = {
            "id": "test-job",
            "parameters": {
                "search_after": "12345",
                "status": "active"
            }
        }

        # Test without any confidence filters
        result = main.build_query_params(
            None, "active", None, 1000, mock_api_client, mock_headers, mock_logger, job
        )

        # Should not include confidence filtering parameters
        self.assertNotIn("confidence__gt", result)
        self.assertNotIn("confidence__gte", result)
        self.assertNotIn("confidence__lt", result)
        self.assertNotIn("confidence__lte", result)

    def test_build_query_params_with_severity_filter(self):
        """Test build_query_params with severity filtering parameter."""
        mock_api_client = MagicMock()
        mock_headers = {}
        mock_logger = MagicMock()

        job = {
            "id": "test-job",
            "parameters": {
                "search_after": "12345",
                "status": "active"
            }
        }

        result = main.build_query_params(
            None, "active", None, 1000, mock_api_client, mock_headers, mock_logger, job,
            severity="high"
        )

        self.assertEqual(result["meta.severity"], "high")

    def test_build_query_params_no_severity_filter(self):
        """Test build_query_params without severity filter (default behavior)."""
        mock_api_client = MagicMock()
        mock_headers = {}
        mock_logger = MagicMock()

        job = {
            "id": "test-job",
            "parameters": {
                "search_after": "12345",
                "status": "active"
            }
        }

        result = main.build_query_params(
            None, "active", None, 1000, mock_api_client, mock_headers, mock_logger, job
        )

        self.assertNotIn("severity", result)

    def test_download_existing_lookup_files_unexpected_response(self):
        """Test download_existing_lookup_files with unexpected response types."""
        mock_logger = MagicMock()

        with patch('main.NGSIEM') as mock_ngsiem_class:
            mock_ngsiem = MagicMock()
            mock_ngsiem_class.return_value = mock_ngsiem

            with tempfile.TemporaryDirectory() as temp_dir:
                # Test with unexpected response type (not bytes, dict with status, or streaming response)
                # An unexpected response (like an integer) will result in an empty file being created
                # since it has no iter_content method and isn't bytes
                mock_ngsiem.get_file.return_value = 12345  # Unexpected integer response

                result = main.download_existing_lookup_files("search-all", "ip", temp_dir, mock_logger)

                # Should return a file path (empty file was "successfully" downloaded)
                # This is an edge case - in practice, FalconPy will return proper response types
                self.assertEqual(len(result), 1)
                self.assertIn("anomali_threatstream_ip.csv", result)

    def test_fetch_iocs_multi_status_rate_limit(self):
        """Test fetch_iocs_from_anomali with 207 multi-status containing 429 rate limit."""
        mock_api_integrations = MagicMock()
        mock_logger = MagicMock()

        # Mock 207 response with embedded 429 error
        mock_api_integrations.execute_command_proxy.side_effect = [
            {
                "status_code": 207,
                "body": {
                    "errors": [{"code": 429, "message": "Rate limit in multi-status"}]
                }
            },
            {
                "status_code": 200,
                "body": {
                    "objects": [{"id": 1, "itype": "ip", "ip": "1.2.3.4"}],
                    "meta": {"total_count": 1, "next": None}
                }
            }
        ]

        with patch('main.time.sleep'):
            iocs, meta = main.fetch_iocs_from_anomali(mock_api_integrations, {}, mock_logger, max_retries=1)

            self.assertEqual(len(iocs), 1)
            self.assertEqual(mock_api_integrations.execute_command_proxy.call_count, 2)

    def test_fetch_iocs_non_api_error_retry(self):
        """Test fetch_iocs_from_anomali with non-API error that gets retried."""
        mock_api_integrations = MagicMock()
        mock_logger = MagicMock()

        # First call raises general exception, second succeeds
        mock_api_integrations.execute_command_proxy.side_effect = [
            RuntimeError("Connection timeout"),
            {
                "status_code": 200,
                "body": {
                    "objects": [{"id": 1, "itype": "ip", "ip": "1.2.3.4"}],
                    "meta": {"total_count": 1, "next": None}
                }
            }
        ]

        with patch('main.time.sleep'):
            iocs, meta = main.fetch_iocs_from_anomali(mock_api_integrations, {}, mock_logger, max_retries=1)

            self.assertEqual(len(iocs), 1)
            self.assertEqual(mock_api_integrations.execute_command_proxy.call_count, 2)

    def test_extract_next_token_malformed_url(self):
        """Test extract_next_token_from_meta with malformed URL that causes parsing error."""
        mock_logger = MagicMock()

        # Create a mock that will cause urlparse to raise an exception
        meta = {"next": "not-a-valid-url://malformed"}
        iocs = [{"update_id": "fallback_123"}]

        with patch('main.urlparse', side_effect=ValueError("Invalid URL")):
            result = main.extract_next_token_from_meta(meta, iocs, mock_logger)

            # Should fallback to last IOC's update_id
            self.assertEqual(result, "fallback_123")
            mock_logger.warning.assert_called_with(
                "Could not parse next URL not-a-valid-url://malformed: Invalid URL, using fallback"
            )

    def test_upload_csv_files_exception_handling(self):
        """Test upload_csv_files_to_ngsiem with exception during upload."""
        mock_logger = MagicMock()

        with patch('main.NGSIEM') as mock_ngsiem_class:
            mock_ngsiem = MagicMock()
            mock_ngsiem_class.return_value = mock_ngsiem

            # Mock upload_file to raise exception
            mock_ngsiem.upload_file.side_effect = RuntimeError("Network error")

            with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as temp_file:
                temp_file.write(b"test,data\n1,2")
                temp_file.flush()

                try:
                    results = main.upload_csv_files_to_ngsiem([temp_file.name], "search-all", mock_logger)

                    self.assertEqual(len(results), 1)
                    self.assertEqual(results[0]["status"], "error")
                    self.assertIn("Network error", results[0]["message"])
                finally:
                    os.unlink(temp_file.name)

    @patch.dict(os.environ, {'TEST_MODE': 'true'})
    def test_create_job_test_mode(self):
        """Test create_job in test mode (lines 231-254)."""
        mock_custom_storage = MagicMock()
        mock_logger = MagicMock()
        headers = {"X-CS-APP-ID": "test-app"}

        with patch('uuid.uuid4') as mock_uuid:
            # Create a mock UUID object that supports str() and slicing
            mock_uuid_obj = MagicMock()
            mock_uuid_obj.__str__ = MagicMock(return_value="test-uuid-12345678")
            mock_uuid.return_value = mock_uuid_obj

            # Test with no IOC type
            result = main.create_job(mock_custom_storage, None, None, mock_logger)

            # Verify mock job structure for test mode
            self.assertTrue(result["id"].startswith("test_"))
            self.assertEqual(result["state"], "running")
            self.assertEqual(result["ioc_type"], "all")
            self.assertEqual(result["parameters"]["status"], "active")
            self.assertNotIn("update_id__gt", result["parameters"])
            self.assertNotIn("search_after", result["parameters"])
            self.assertNotIn("type", result["parameters"])  # No type filter for all types

            # Test with specific IOC type
            result_typed = main.create_job(mock_custom_storage, None, "ip", mock_logger)

            # Verify type-specific mock job
            self.assertTrue(result_typed["id"].endswith("_ip"))
            self.assertEqual(result_typed["ioc_type"], "ip")
            self.assertEqual(result_typed["parameters"]["type"], "ip")

            # Verify no actual API calls were made in test mode
            mock_custom_storage.PutObject.assert_not_called()

            # Verify test mode log message
            mock_logger.info.assert_any_call(f"TEST MODE: Created mock job: {result}")

    @patch.dict(os.environ, {'TEST_MODE': 'true'})
    def test_update_job_test_mode(self):
        """Test update_job in test mode (lines 318-319)."""
        mock_custom_storage = MagicMock()
        mock_logger = MagicMock()
        headers = {"X-CS-APP-ID": "test-app"}

        job = {"id": "test-job-123", "state": "completed"}

        main.update_job(mock_custom_storage, job, mock_logger)

        # Verify no actual API calls were made in test mode
        mock_custom_storage.PutObject.assert_not_called()

        # Verify test mode log message
        mock_logger.info.assert_called_with("TEST MODE: Mock job update for test-job-123 with state: completed")

    @patch.dict(os.environ, {'TEST_MODE': 'true'})
    def test_download_existing_lookup_files_locally(self):
        """Test download_existing_lookup_files_locally functionality (lines 576-640)."""
        mock_logger = MagicMock()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test output directory structure
            test_output_dir = os.path.join(temp_dir, "test_output", "search-all")
            os.makedirs(test_output_dir, exist_ok=True)

            # Create some test lookup files
            ip_csv = (
                "destination.ip,confidence,threat_type,severity,source,tags,expiration_ts\n"
                "1.2.3.4,90,malware,high,test,tag1,2024-12-31T23:59:59Z\n"
            )
            domain_csv = (
                "dns.domain.name,confidence,threat_type,severity,source,tags,expiration_ts\n"
                "evil.com,85,phishing,medium,test,tag2,2024-12-31T23:59:59Z\n"
            )
            test_files = {
                "anomali_threatstream_ip.csv": ip_csv,
                "anomali_threatstream_domain.csv": domain_csv
            }

            for filename, content in test_files.items():
                with open(os.path.join(test_output_dir, filename), 'w', encoding='utf-8') as f:
                    f.write(content)

            # Create a destination temp_dir for downloads
            with tempfile.TemporaryDirectory() as download_dir:
                # Mock os.getcwd to return our temp directory
                with patch('os.getcwd', return_value=temp_dir):
                    # Test downloading all files (no type filter)
                    result = main.download_existing_lookup_files_locally("search-all", None, download_dir, mock_logger)

                    # Should find both files (now returns file PATHS, not content)
                    self.assertEqual(len(result), 2)
                    self.assertIn("anomali_threatstream_ip.csv", result)
                    self.assertIn("anomali_threatstream_domain.csv", result)
                    # Verify files were copied to download_dir
                    self.assertTrue(os.path.exists(result["anomali_threatstream_ip.csv"]))
                    self.assertTrue(result["anomali_threatstream_ip.csv"].endswith(".csv"))

                    # Test with specific type filter
                    result_ip = main.download_existing_lookup_files_locally("search-all", "ip", download_dir, mock_logger)

                    # Should find only IP file
                    self.assertEqual(len(result_ip), 1)
                    self.assertIn("anomali_threatstream_ip.csv", result_ip)
                    self.assertNotIn("anomali_threatstream_domain.csv", result_ip)

                    # Test with hash type (should look for hash_md5, hash_sha1, hash_sha256)
                    result_hash = main.download_existing_lookup_files_locally(
                        "search-all", "hash", download_dir, mock_logger
                    )

                    # Should find no hash files (we didn't create any)
                    self.assertEqual(len(result_hash), 0)

                    # Test with md5 type mapping
                    result_md5 = main.download_existing_lookup_files_locally(
                        "search-all", "md5", download_dir, mock_logger
                    )

                    # Should find no md5 files (we didn't create any)
                    self.assertEqual(len(result_md5), 0)

                    # Test with non-existent type
                    result_unknown = main.download_existing_lookup_files_locally(
                        "search-all", "unknown", download_dir, mock_logger
                    )

                    # Should find no files
                    self.assertEqual(len(result_unknown), 0)

    @patch.dict(os.environ, {'TEST_MODE': 'true'})
    def test_upload_csv_files_locally(self):
        """Test upload_csv_files_locally functionality (lines 960-998)."""
        mock_logger = MagicMock()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test CSV file
            test_csv_path = os.path.join(temp_dir, "test_file.csv")
            test_csv_content = (
                "destination.ip,confidence,threat_type,severity,source,tags,expiration_ts\n"
                "1.2.3.4,90,malware,high,test,tag1,2024-12-31T23:59:59Z\n"
            )

            with open(test_csv_path, 'w', encoding='utf-8') as f:
                f.write(test_csv_content)

            # Mock os.getcwd to return our temp directory
            with patch('os.getcwd', return_value=temp_dir):
                # Test uploading the file locally
                results = main.upload_csv_files_locally([test_csv_path], "search-all", mock_logger)

                # Should return success result
                self.assertEqual(len(results), 1)
                self.assertEqual(results[0]["status"], "success")
                self.assertEqual(results[0]["file"], "test_file.csv")
                self.assertIn("local_path", results[0])
                self.assertIn("size_bytes", results[0])

                # Verify file was copied to test output directory
                expected_path = os.path.join(temp_dir, "test_output", "search-all", "test_file.csv")
                self.assertTrue(os.path.exists(expected_path))

                # Verify file content is preserved
                with open(expected_path, 'r', encoding='utf-8') as f:
                    copied_content = f.read()
                self.assertEqual(copied_content, test_csv_content)

                # Test error handling with invalid file
                invalid_file_path = os.path.join(temp_dir, "nonexistent.csv")
                error_results = main.upload_csv_files_locally([invalid_file_path], "search-all", mock_logger)

                # Should return error result
                self.assertEqual(len(error_results), 1)
                self.assertEqual(error_results[0]["status"], "error")
                self.assertIn("Local write failed", error_results[0]["message"])

    def test_on_post_job_creation_failure(self):
        """Test on_post when job creation fails."""
        mock_logger = MagicMock()

        with patch('main.APIIntegrations'), \
             patch('main.CustomStorage') as mock_custom_storage_class, \
             patch('main.NGSIEM') as mock_ngsiem_class:

            mock_custom_storage = MagicMock()
            mock_custom_storage_class.return_value = mock_custom_storage
            mock_ngsiem = MagicMock()
            mock_ngsiem_class.return_value = mock_ngsiem

            # Mock that no existing files are found (return 404 dict)
            mock_ngsiem.get_file.return_value = {"status_code": 404}

            # Mock clear_collection_data calls - all fail (not found)
            # 9 keys: last_update + 8 type-specific
            mock_custom_storage.DeleteObject.side_effect = [Exception("Not found")] * 9
            # Mock get_last_update_id - GetObject raises exception
            mock_custom_storage.GetObject.side_effect = [
                Exception("Object not found"),  # get_last_update_id
            ]
            # Mock create_job - PutObject fails
            mock_custom_storage.PutObject.side_effect = [
                {"status_code": 500}  # create_job PutObject fails
            ]

            request = Request()
            request.body = {}

            response = main.on_post(request, _config=None, logger=mock_logger)

            self.assertEqual(response.code, 500)
            self.assertEqual(len(response.errors), 1)
            self.assertIn("Internal error", response.errors[0].message)



    def test_response_stream_adapter(self):
        """Test ResponseStreamAdapter with known byte sequences."""
        # Simulate a response with iter_content
        chunks = [b"hello ", b"world\n", b"second line\n"]
        mock_response = MagicMock()
        mock_response.iter_content.return_value = iter(chunks)

        adapter = main.ResponseStreamAdapter(mock_response, chunk_size=65536)

        # Read into a buffer
        buf = bytearray(6)
        n = adapter.readinto(buf)
        self.assertEqual(n, 6)
        self.assertEqual(bytes(buf[:n]), b"hello ")

        buf = bytearray(100)
        n = adapter.readinto(buf)
        self.assertEqual(n, 6 + 12)  # "world\n" + "second line\n"
        self.assertEqual(bytes(buf[:n]), b"world\nsecond line\n")

        # Verify EOF
        buf = bytearray(10)
        n = adapter.readinto(buf)
        self.assertEqual(n, 0)

        # Verify total bytes consumed
        self.assertEqual(adapter.bytes_consumed, len(b"hello world\nsecond line\n"))

    def test_response_stream_adapter_with_text_wrapper(self):
        """Test ResponseStreamAdapter works with TextIOWrapper and csv.reader."""
        import io

        csv_content = b"col1,col2\nval1,val2\nval3,val4\n"
        mock_response = MagicMock()
        mock_response.iter_content.return_value = iter([csv_content])

        adapter = main.ResponseStreamAdapter(mock_response, chunk_size=65536)
        text_stream = io.TextIOWrapper(io.BufferedReader(adapter), encoding='utf-8')
        reader = csv.reader(text_stream)

        rows = list(reader)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0], ["col1", "col2"])
        self.assertEqual(rows[1], ["val1", "val2"])
        self.assertEqual(rows[2], ["val3", "val4"])
        self.assertEqual(adapter.bytes_consumed, len(csv_content))

    @patch('main.NGSIEM')
    def test_check_existing_file_metadata(self, mock_ngsiem_class):
        """Test check_existing_file_metadata returns correct filename->size mapping."""
        mock_ngsiem = MagicMock()
        mock_ngsiem_class.return_value = mock_ngsiem
        mock_logger = MagicMock()

        # Mock responses: ip exists (200), domain not found (404)
        mock_resp_ip = MagicMock()
        mock_resp_ip.status_code = 200
        mock_resp_ip.headers = {"Content-Length": "1048576"}

        mock_resp_domain = MagicMock()
        mock_resp_domain.status_code = 404

        mock_ngsiem.get_file.side_effect = [mock_resp_ip, mock_resp_domain]

        result = main.check_existing_file_metadata("search-all", "ip", mock_logger)

        self.assertEqual(result, {"anomali_threatstream_ip.csv": 1048576})
        self.assertEqual(mock_ngsiem.get_file.call_count, 1)  # Only 1 file for type "ip"

    @patch('main.NGSIEM')
    def test_check_existing_file_metadata_hash_type(self, mock_ngsiem_class):
        """Test check_existing_file_metadata with hash type (checks all 3 hash files)."""
        mock_ngsiem = MagicMock()
        mock_ngsiem_class.return_value = mock_ngsiem
        mock_logger = MagicMock()

        # Mock responses: md5 exists, sha1 exists, sha256 not found
        mock_resp_md5 = MagicMock()
        mock_resp_md5.status_code = 200
        mock_resp_md5.headers = {"Content-Length": "500000"}

        mock_resp_sha1 = MagicMock()
        mock_resp_sha1.status_code = 200
        mock_resp_sha1.headers = {"Content-Length": "600000"}

        mock_resp_sha256 = MagicMock()
        mock_resp_sha256.status_code = 404

        mock_ngsiem.get_file.side_effect = [mock_resp_md5, mock_resp_sha1, mock_resp_sha256]

        result = main.check_existing_file_metadata("search-all", "hash", mock_logger)

        self.assertEqual(result, {
            "anomali_threatstream_hash_md5.csv": 500000,
            "anomali_threatstream_hash_sha1.csv": 600000
        })

    @patch('main.NGSIEM')
    def test_stream_merge_removed_uses_server_side_update(self, mock_ngsiem_class):
        """Test that when existing_files values are ints, only new rows are written to CSV.

        Server-side deduplication via update_lookup_file_entries() replaces the old
        stream-merge approach. The CSV file should contain only new rows (not existing).
        """
        mock_ngsiem = MagicMock()
        mock_ngsiem_class.return_value = mock_ngsiem
        mock_logger = MagicMock()

        new_iocs = [
            {
                "itype": "ip",
                "ip": "5.6.7.8",
                "confidence": 85,
                "threat_type": "botnet",
                "meta": {"severity": "medium"},
                "source": "test2",
                "tags": [],
                "expiration_ts": ""
            }
        ]

        # existing_files with int value (Content-Length) triggers server-side update path
        existing_files = {
            "anomali_threatstream_ip.csv": 1000
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_files, stats = main.process_iocs_to_csv(
                new_iocs, temp_dir, existing_files, mock_logger, repository="search-all"
            )

            self.assertEqual(len(csv_files), 1)

            with open(csv_files[0], 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            # Only new rows written (server-side dedup handles existing rows)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["destination.ip"], "5.6.7.8")

        # NGSIEM.get_file should NOT be called (no stream-merge)
        mock_ngsiem.get_file.assert_not_called()

    @patch('main.NGSIEM')
    def test_upload_entries_to_ngsiem_existing_file(self, mock_ngsiem_class):
        """Test upload_entries_to_ngsiem uses update mode for existing files."""
        mock_ngsiem = MagicMock()
        mock_ngsiem_class.return_value = mock_ngsiem
        mock_logger = MagicMock()

        mock_ngsiem.update_lookup_file_entries.return_value = {
            "status_code": 200,
            "body": {"message": "success"}
        }

        existing_files = {
            "anomali_threatstream_ip.csv": 1048576
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            # Write a test CSV file
            csv_path = os.path.join(temp_dir, "anomali_threatstream_ip.csv")
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, quoting=csv.QUOTE_ALL)
                writer.writerow(["destination.ip", "confidence", "threat_type", "severity", "source", "tags", "expiration_ts"])
                writer.writerow(["1.2.3.4", "90", "malware", "high", "feed1", "tag1", "2026-01-01"])

            results = main.upload_entries_to_ngsiem(
                [csv_path], "search-all", existing_files, mock_logger
            )

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["status"], "success")

            # Verify update_lookup_file_entries was called with correct params
            mock_ngsiem.update_lookup_file_entries.assert_called_once()
            call_kwargs = mock_ngsiem.update_lookup_file_entries.call_args[1]
            self.assertEqual(call_kwargs["update_mode"], "update")
            self.assertEqual(call_kwargs["key_columns"], "destination.ip")
            self.assertEqual(call_kwargs["ignore_case"], "false")
            self.assertEqual(call_kwargs["filename"], "anomali_threatstream_ip.csv")

    @patch('main.NGSIEM')
    def test_upload_entries_to_ngsiem_new_file(self, mock_ngsiem_class):
        """Test upload_entries_to_ngsiem uses append mode for new files."""
        mock_ngsiem = MagicMock()
        mock_ngsiem_class.return_value = mock_ngsiem
        mock_logger = MagicMock()

        mock_ngsiem.update_lookup_file_entries.return_value = {
            "status_code": 200,
            "body": {"message": "success"}
        }

        # File not in existing_files dict → it's a new file
        existing_files = {}

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = os.path.join(temp_dir, "anomali_threatstream_domain.csv")
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, quoting=csv.QUOTE_ALL)
                writer.writerow(["dns.domain.name", "confidence", "threat_type", "severity", "source", "tags", "expiration_ts"])
                writer.writerow(["evil.com", "95", "c2", "critical", "feed1", "", "2026-01-01"])

            results = main.upload_entries_to_ngsiem(
                [csv_path], "search-all", existing_files, mock_logger
            )

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["status"], "success")

            # Verify append mode was used
            call_kwargs = mock_ngsiem.update_lookup_file_entries.call_args[1]
            self.assertEqual(call_kwargs["update_mode"], "append")
            # key_columns and ignore_case should NOT be passed for append mode
            self.assertNotIn("key_columns", call_kwargs)
            self.assertNotIn("ignore_case", call_kwargs)

    @patch('main.NGSIEM')
    def test_upload_entries_to_ngsiem_error_handling(self, mock_ngsiem_class):
        """Test upload_entries_to_ngsiem raises on API errors (fail-fast)."""
        mock_ngsiem = MagicMock()
        mock_ngsiem_class.return_value = mock_ngsiem
        mock_logger = MagicMock()

        mock_ngsiem.update_lookup_file_entries.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "Internal server error"}]}
        }

        existing_files = {
            "anomali_threatstream_ip.csv": 1048576
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = os.path.join(temp_dir, "anomali_threatstream_ip.csv")
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, quoting=csv.QUOTE_ALL)
                writer.writerow(["destination.ip", "confidence", "threat_type", "severity", "source", "tags", "expiration_ts"])
                writer.writerow(["1.2.3.4", "90", "malware", "high", "feed1", "", ""])

            with self.assertRaises(main.AnomaliFunctionError) as ctx:
                main.upload_entries_to_ngsiem(
                    [csv_path], "search-all", existing_files, mock_logger
                )

            self.assertIn("HTTP 500", str(ctx.exception))

    @patch('main.time.sleep')
    @patch('main.NGSIEM')
    def test_upload_entries_to_ngsiem_429_retry_then_success(self, mock_ngsiem_class, mock_sleep):
        """Test upload_entries_to_ngsiem retries on 429 with backoff then succeeds."""
        mock_ngsiem = MagicMock()
        mock_ngsiem_class.return_value = mock_ngsiem
        mock_logger = MagicMock()

        # First two calls return 429, third succeeds
        mock_ngsiem.update_lookup_file_entries.side_effect = [
            {"status_code": 429, "body": {"errors": [{"message": "rate limited"}]}},
            {"status_code": 429, "body": {"errors": [{"message": "rate limited"}]}},
            {"status_code": 200, "body": {"message": "success"}},
        ]

        existing_files = {"anomali_threatstream_ip.csv": 1048576}

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = os.path.join(temp_dir, "anomali_threatstream_ip.csv")
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, quoting=csv.QUOTE_ALL)
                writer.writerow(["destination.ip", "confidence", "threat_type", "severity", "source", "tags", "expiration_ts"])
                writer.writerow(["1.2.3.4", "90", "malware", "high", "feed1", "", ""])

            results = main.upload_entries_to_ngsiem(
                [csv_path], "search-all", existing_files, mock_logger
            )

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["status"], "success")
            # Called 3 times total (2 retries + 1 success)
            self.assertEqual(mock_ngsiem.update_lookup_file_entries.call_count, 3)
            # Slept twice (backoff between retries)
            self.assertEqual(mock_sleep.call_count, 2)

    @patch('main.time.sleep')
    @patch('main.NGSIEM')
    def test_upload_entries_to_ngsiem_429_exhausted(self, mock_ngsiem_class, mock_sleep):
        """Test upload_entries_to_ngsiem raises after exhausting 429 retries."""
        mock_ngsiem = MagicMock()
        mock_ngsiem_class.return_value = mock_ngsiem
        mock_logger = MagicMock()

        # All calls return 429
        mock_ngsiem.update_lookup_file_entries.return_value = {
            "status_code": 429,
            "body": {"errors": [{"message": "rate limited"}]}
        }

        existing_files = {"anomali_threatstream_ip.csv": 1048576}

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = os.path.join(temp_dir, "anomali_threatstream_ip.csv")
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, quoting=csv.QUOTE_ALL)
                writer.writerow(["destination.ip", "confidence", "threat_type", "severity", "source", "tags", "expiration_ts"])
                writer.writerow(["1.2.3.4", "90", "malware", "high", "feed1", "", ""])

            with self.assertRaises(main.AnomaliFunctionError) as ctx:
                main.upload_entries_to_ngsiem(
                    [csv_path], "search-all", existing_files, mock_logger
                )

            self.assertIn("429", str(ctx.exception))
            self.assertIn("after 5 retries", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
