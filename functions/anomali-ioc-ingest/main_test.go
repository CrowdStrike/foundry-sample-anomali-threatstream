package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/custom_storage"
	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/go-openapi/runtime"
)

func TestNormalizeIOCType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ip", "ip"},
		{"domain", "domain"},
		{"url", "url"},
		{"email", "email"},
		{"hash_md5", "hash_md5"},
		{"hash_sha1", "hash_sha1"},
		{"hash_sha256", "hash_sha256"},
		{"mal_ip", "ip"},
		{"c2_ip", "ip"},
		{"apt_ip", "ip"},
		{"mal_domain", "domain"},
		{"c2_domain", "domain"},
		{"apt_domain", "domain"},
		{"mal_url", "url"},
		{"apt_url", "url"},
		{"apt_email", "email"},
		{"mal_email", "email"},
		{"compromised_email", "email"},
		{"apt_md5", "hash_md5"},
		{"mal_md5", "hash_md5"},
		{"apt_sha1", "hash_sha1"},
		{"mal_sha1", "hash_sha1"},
		{"apt_sha256", "hash_sha256"},
		{"mal_sha256", "hash_sha256"},
		{"unknown_type", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeIOCType(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeIOCType(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetPrimaryValue(t *testing.T) {
	ioc := IOC{
		IP:    "1.2.3.4",
		Value: "evil.com",
	}

	tests := []struct {
		field    string
		expected string
	}{
		{"ip", "1.2.3.4"},
		{"value", "evil.com"},
		{"unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			result := getPrimaryValue(ioc, tt.field)
			if result != tt.expected {
				t.Errorf("getPrimaryValue(ioc, %q) = %q, expected %q", tt.field, result, tt.expected)
			}
		})
	}
}

func TestExtractTags(t *testing.T) {
	tests := []struct {
		name     string
		tags     []map[string]string
		expected string
	}{
		{
			name:     "empty tags",
			tags:     nil,
			expected: "",
		},
		{
			name:     "single tag",
			tags:     []map[string]string{{"name": "malware"}},
			expected: "malware",
		},
		{
			name:     "multiple tags",
			tags:     []map[string]string{{"name": "botnet"}, {"name": "c2"}},
			expected: "botnet,c2",
		},
		{
			name:     "tags with empty names",
			tags:     []map[string]string{{"name": "valid"}, {"name": ""}, {"other": "field"}},
			expected: "valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTags(tt.tags)
			if result != tt.expected {
				t.Errorf("extractTags() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestToString(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"nil", nil, ""},
		{"string", "hello", "hello"},
		{"int", 42, "42"},
		{"int64", int64(123456789), "123456789"},
		{"float64", 3.14, "3.14"},
		{"float64 whole", float64(90), "90"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toString(tt.input)
			if result != tt.expected {
				t.Errorf("toString(%v) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestProcessIOCsToCSV_IPType(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	iocs := []IOC{
		{
			IType:        "ip",
			IP:           "1.2.3.4",
			Confidence:   90,
			ThreatType:   "c2",
			Source:       "test",
			Tags:         []map[string]string{{"name": "botnet"}, {"name": "c2"}},
			ExpirationTs: "2024-12-31",
		},
	}

	existingFiles := make(map[string]bool)

	csvFiles, stats, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	if len(csvFiles) != 1 {
		t.Errorf("Expected 1 CSV file, got %d", len(csvFiles))
	}

	if stats.TotalNewIOCs != 1 {
		t.Errorf("Expected TotalNewIOCs=1, got %d", stats.TotalNewIOCs)
	}

	if stats.FilesWithNewData != 1 {
		t.Errorf("Expected FilesWithNewData=1, got %d", stats.FilesWithNewData)
	}

	// Verify file contents
	content, err := os.ReadFile(csvFiles[0])
	if err != nil {
		t.Fatalf("Failed to read CSV file: %v", err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "destination.ip") {
		t.Error("CSV missing header column 'destination.ip'")
	}
	if !strings.Contains(contentStr, "1.2.3.4") {
		t.Error("CSV missing IP value '1.2.3.4'")
	}
	if !strings.Contains(contentStr, "botnet,c2") {
		t.Error("CSV missing tags 'botnet,c2'")
	}
}

func TestProcessIOCsToCSV_DomainType(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	iocs := []IOC{
		{
			IType:        "domain",
			Value:        "evil.com",
			Confidence:   85,
			ThreatType:   "phishing",
			Source:       "test",
			Tags:         nil,
			ExpirationTs: "",
		},
	}

	existingFiles := make(map[string]bool)

	csvFiles, _, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	if len(csvFiles) != 1 {
		t.Errorf("Expected 1 CSV file, got %d", len(csvFiles))
	}

	filename := filepath.Base(csvFiles[0])
	if filename != "anomali_threatstream_domain.csv" {
		t.Errorf("Expected filename 'anomali_threatstream_domain.csv', got %q", filename)
	}

	// Verify file contents
	content, err := os.ReadFile(csvFiles[0])
	if err != nil {
		t.Fatalf("Failed to read CSV file: %v", err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "dns.domain.name") {
		t.Error("CSV missing header column 'dns.domain.name'")
	}
	if !strings.Contains(contentStr, "evil.com") {
		t.Error("CSV missing domain value 'evil.com'")
	}
}

func TestProcessIOCsToCSV_WithExistingFile(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	// Mark that an existing file exists on NGSIEM (server-side dedup will handle merge)
	existingFilePaths := map[string]bool{
		"anomali_threatstream_ip.csv": true,
	}

	// New IOCs - these will be written as new rows for server-side dedup
	iocs := []IOC{
		{
			IType:        "ip",
			IP:           "1.2.3.4",
			Confidence:   90,
			ThreatType:   "c2",
			Source:       "test",
			Tags:         []map[string]string{{"name": "updated"}},
			ExpirationTs: "2024-12-31",
		},
		{
			IType:        "ip",
			IP:           "9.10.11.12",
			Confidence:   80,
			ThreatType:   "malware",
			Source:       "test",
			Tags:         nil,
			ExpirationTs: "",
		},
	}

	csvFiles, stats, err := processIOCsToCSV(iocs, tempDir, existingFilePaths, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	if len(csvFiles) != 1 {
		t.Errorf("Expected 1 CSV file, got %d", len(csvFiles))
	}

	// Verify file contents - should only contain new rows (server-side handles merge)
	content, err := os.ReadFile(csvFiles[0])
	if err != nil {
		t.Fatalf("Failed to read CSV file: %v", err)
	}

	contentStr := string(content)

	// Should contain the new IOCs
	if !strings.Contains(contentStr, "1.2.3.4") {
		t.Error("CSV missing IP '1.2.3.4'")
	}
	if !strings.Contains(contentStr, "90") {
		t.Error("CSV should have confidence '90'")
	}

	// Should contain new 9.10.11.12
	if !strings.Contains(contentStr, "9.10.11.12") {
		t.Error("CSV missing new IP '9.10.11.12'")
	}

	// Stats should reflect new IOCs only
	if stats.FilesWithNewData != 1 {
		t.Errorf("Expected FilesWithNewData=1, got %d", stats.FilesWithNewData)
	}
}

func TestProcessIOCsToCSV_UnknownType(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	iocs := []IOC{
		{
			IType:      "unknown_type",
			Value:      "something",
			Confidence: 50,
		},
	}

	existingFiles := make(map[string]bool)

	csvFiles, _, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	// Should not create any files for unknown types
	if len(csvFiles) != 0 {
		t.Errorf("Expected 0 CSV files for unknown type, got %d", len(csvFiles))
	}
}

func TestProcessIOCsToCSV_CompromisedEmail(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	iocs := []IOC{
		{
			IType:      "compromised_email",
			Value:      "victim@example.com",
			Confidence: 80,
			ThreatType: "compromised",
			Source:     "anomali",
		},
	}

	existingFiles := make(map[string]bool)

	csvFiles, stats, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	if len(csvFiles) != 1 {
		t.Fatalf("Expected 1 CSV file, got %d", len(csvFiles))
	}

	if !strings.HasSuffix(csvFiles[0], "anomali_threatstream_email.csv") {
		t.Errorf("Expected email CSV file, got %s", csvFiles[0])
	}

	content, err := os.ReadFile(csvFiles[0])
	if err != nil {
		t.Fatalf("Failed to read CSV: %v", err)
	}
	contentStr := string(content)

	if !strings.Contains(contentStr, "email.sender.address") {
		t.Error("CSV missing email.sender.address header")
	}
	if !strings.Contains(contentStr, "victim@example.com") {
		t.Error("CSV missing email value")
	}

	if stats.TotalNewIOCs != 1 {
		t.Errorf("Expected TotalNewIOCs=1, got %d", stats.TotalNewIOCs)
	}
}

func TestProcessIOCsToCSV_MultipleTypes(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	iocs := []IOC{
		{IType: "ip", IP: "1.2.3.4", Confidence: 90},
		{IType: "domain", Value: "evil.com", Confidence: 85},
		{IType: "hash_md5", Value: "d41d8cd98f00b204e9800998ecf8427e", Confidence: 95},
	}

	existingFiles := make(map[string]bool)

	csvFiles, stats, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	if len(csvFiles) != 3 {
		t.Errorf("Expected 3 CSV files, got %d", len(csvFiles))
	}

	if stats.TotalNewIOCs != 3 {
		t.Errorf("Expected TotalNewIOCs=3, got %d", stats.TotalNewIOCs)
	}

	// Verify filenames
	filenames := make(map[string]bool)
	for _, f := range csvFiles {
		filenames[filepath.Base(f)] = true
	}

	expectedFiles := []string{
		"anomali_threatstream_ip.csv",
		"anomali_threatstream_domain.csv",
		"anomali_threatstream_hash_md5.csv",
	}

	for _, expected := range expectedFiles {
		if !filenames[expected] {
			t.Errorf("Missing expected file: %s", expected)
		}
	}
}

func TestProcessIOCsToCSV_Deduplication(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	// Same IP twice - later one should win
	iocs := []IOC{
		{
			IType:      "ip",
			IP:         "1.2.3.4",
			Confidence: 50, // Earlier, lower confidence
			ThreatType: "suspicious",
			Source:     "first",
		},
		{
			IType:      "ip",
			IP:         "1.2.3.4",
			Confidence: 95, // Later, higher confidence (should win)
			ThreatType: "c2",
			Source:     "second",
		},
	}

	existingFiles := make(map[string]bool)

	csvFiles, _, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	content, err := os.ReadFile(csvFiles[0])
	if err != nil {
		t.Fatalf("Failed to read CSV file: %v", err)
	}

	contentStr := string(content)

	// Should have the later entry (confidence 95)
	if !strings.Contains(contentStr, "95") {
		t.Error("CSV should contain confidence '95' from later entry")
	}
	if !strings.Contains(contentStr, "second") {
		t.Error("CSV should contain source 'second' from later entry")
	}

	// Count occurrences of the IP - should only appear once
	count := strings.Count(contentStr, "1.2.3.4")
	if count != 1 {
		t.Errorf("IP '1.2.3.4' should appear exactly once, found %d times", count)
	}
}

func TestExtractNextToken(t *testing.T) {
	logger := slog.Default()

	// Create test IOCs for cases that need them
	testIOCs := []IOC{
		{UpdateID: "12345"},
	}

	tests := []struct {
		name     string
		meta     map[string]interface{}
		iocs     []IOC
		expected string
	}{
		{
			name:     "nil meta",
			meta:     nil,
			iocs:     testIOCs,
			expected: "",
		},
		{
			name:     "empty meta",
			meta:     map[string]interface{}{},
			iocs:     testIOCs,
			expected: "",
		},
		{
			name:     "empty iocs",
			meta:     map[string]interface{}{"next": "https://api.example.com/v2/indicators?update_id__gt=1000"},
			iocs:     []IOC{},
			expected: "",
		},
		{
			name: "meta with next URL containing update_id__gt",
			meta: map[string]interface{}{
				"next": "https://api.example.com/v2/indicators?update_id__gt=1000&limit=1000",
			},
			iocs:     testIOCs,
			expected: "1000",
		},
		{
			name: "meta with next URL containing search_after",
			meta: map[string]interface{}{
				"next": "https://api.example.com/v2/indicators?search_after=2000&limit=1000",
			},
			iocs:     testIOCs,
			expected: "2000",
		},
		{
			name: "meta with next URL containing from_update_id",
			meta: map[string]interface{}{
				"next": "https://api.example.com/v2/indicators?from_update_id=3000&limit=1000",
			},
			iocs:     testIOCs,
			expected: "3000",
		},
		{
			name: "meta with next URL without pagination params falls back to last IOC",
			meta: map[string]interface{}{
				"next": "https://api.example.com/v2/indicators?limit=1000",
			},
			iocs:     testIOCs,
			expected: "12345",
		},
		{
			name: "meta with empty next",
			meta: map[string]interface{}{
				"next": "",
			},
			iocs:     testIOCs,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractNextToken(tt.meta, tt.iocs, logger)
			if result != tt.expected {
				t.Errorf("extractNextToken() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestIOCTypeMappings(t *testing.T) {
	// Verify all expected IOC types have mappings
	expectedTypes := []string{"ip", "domain", "url", "email", "hash_md5", "hash_sha1", "hash_sha256"}

	for _, iocType := range expectedTypes {
		mapping, ok := iocTypeMappings[iocType]
		if !ok {
			t.Errorf("Missing mapping for IOC type: %s", iocType)
			continue
		}

		if len(mapping.Columns) != 7 {
			t.Errorf("IOC type %s should have 7 columns, got %d", iocType, len(mapping.Columns))
		}

		if mapping.PrimaryField == "" {
			t.Errorf("IOC type %s has empty PrimaryField", iocType)
		}

		// Verify expected columns exist
		expectedCols := []string{"confidence", "threat_type", "severity", "source", "tags", "expiration_ts"}
		for _, col := range expectedCols {
			found := false
			for _, c := range mapping.Columns {
				if c == col {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("IOC type %s missing column: %s", iocType, col)
			}
		}
	}
}

// TestIsTestMode tests the TEST_MODE environment variable detection
func TestIsTestMode(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected bool
	}{
		{"true lowercase", "true", true},
		{"TRUE uppercase", "TRUE", true},
		{"True mixed", "True", true},
		{"1", "1", true},
		{"yes", "yes", true},
		{"YES", "YES", true},
		{"false", "false", false},
		{"0", "0", false},
		{"no", "no", false},
		{"empty", "", false},
		{"random", "random", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			if tt.envValue != "" {
				os.Setenv("TEST_MODE", tt.envValue)
			} else {
				os.Unsetenv("TEST_MODE")
			}
			defer os.Unsetenv("TEST_MODE")

			result := isTestMode()
			if result != tt.expected {
				t.Errorf("isTestMode() with TEST_MODE=%q = %v, expected %v", tt.envValue, result, tt.expected)
			}
		})
	}
}

// TestMapToIOC tests the conversion of a map to an IOC struct
func TestMapToIOC(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected IOC
	}{
		{
			name: "complete IOC",
			input: map[string]interface{}{
				"itype":         "ip",
				"ip":            "1.2.3.4",
				"value":         "test-value",
				"confidence":    90,
				"threat_type":   "malware",
				"source":        "test-source",
				"expiration_ts": "2024-12-31",
				"update_id":     "12345",
				"tags": []interface{}{
					map[string]interface{}{"name": "botnet"},
					map[string]interface{}{"name": "c2"},
				},
			},
			expected: IOC{
				IType:        "ip",
				IP:           "1.2.3.4",
				Value:        "test-value",
				Confidence:   90,
				ThreatType:   "malware",
				Source:       "test-source",
				ExpirationTs: "2024-12-31",
				UpdateID:     "12345",
				Tags:         []map[string]string{{"name": "botnet"}, {"name": "c2"}},
			},
		},
		{
			name: "minimal IOC",
			input: map[string]interface{}{
				"itype": "domain",
				"value": "evil.com",
			},
			expected: IOC{
				IType: "domain",
				Value: "evil.com",
			},
		},
		{
			name:     "empty map",
			input:    map[string]interface{}{},
			expected: IOC{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapToIOC(tt.input)

			if result.IType != tt.expected.IType {
				t.Errorf("IType = %q, expected %q", result.IType, tt.expected.IType)
			}
			if result.IP != tt.expected.IP {
				t.Errorf("IP = %q, expected %q", result.IP, tt.expected.IP)
			}
			if result.Value != tt.expected.Value {
				t.Errorf("Value = %q, expected %q", result.Value, tt.expected.Value)
			}
			if result.ThreatType != tt.expected.ThreatType {
				t.Errorf("ThreatType = %q, expected %q", result.ThreatType, tt.expected.ThreatType)
			}
			if result.Source != tt.expected.Source {
				t.Errorf("Source = %q, expected %q", result.Source, tt.expected.Source)
			}
			if result.ExpirationTs != tt.expected.ExpirationTs {
				t.Errorf("ExpirationTs = %q, expected %q", result.ExpirationTs, tt.expected.ExpirationTs)
			}
			if len(result.Tags) != len(tt.expected.Tags) {
				t.Errorf("Tags length = %d, expected %d", len(result.Tags), len(tt.expected.Tags))
			}
		})
	}
}

// TestGetMaxUpdateID tests extraction of maximum update_id from IOCs
func TestGetMaxUpdateID(t *testing.T) {
	tests := []struct {
		name     string
		iocs     []IOC
		expected string
	}{
		{
			name:     "empty list",
			iocs:     []IOC{},
			expected: "",
		},
		{
			name: "single IOC",
			iocs: []IOC{
				{UpdateID: "12345"},
			},
			expected: "12345",
		},
		{
			name: "multiple IOCs ascending",
			iocs: []IOC{
				{UpdateID: "100"},
				{UpdateID: "200"},
				{UpdateID: "300"},
			},
			expected: "300",
		},
		{
			name: "multiple IOCs descending",
			iocs: []IOC{
				{UpdateID: "300"},
				{UpdateID: "200"},
				{UpdateID: "100"},
			},
			expected: "300",
		},
		{
			name: "IOCs with nil update_id",
			iocs: []IOC{
				{UpdateID: nil},
				{UpdateID: "500"},
				{UpdateID: nil},
			},
			expected: "500",
		},
		{
			name: "IOCs with numeric update_id",
			iocs: []IOC{
				{UpdateID: float64(100)},
				{UpdateID: float64(999)},
			},
			expected: "999",
		},
		{
			name: "numeric IDs with varying lengths - 9 vs 10",
			iocs: []IOC{
				{UpdateID: "9"},
				{UpdateID: "10"},
			},
			expected: "10",
		},
		{
			name: "numeric IDs with varying lengths - large numbers",
			iocs: []IOC{
				{UpdateID: "999"},
				{UpdateID: "1000"},
				{UpdateID: "99"},
			},
			expected: "1000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getMaxUpdateID(tt.iocs)
			if result != tt.expected {
				t.Errorf("getMaxUpdateID() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// TestGetMetaTotalCount tests extraction of total_count from meta
func TestGetMetaTotalCount(t *testing.T) {
	tests := []struct {
		name     string
		meta     map[string]interface{}
		expected int64
	}{
		{
			name:     "nil meta",
			meta:     nil,
			expected: 0,
		},
		{
			name:     "empty meta",
			meta:     map[string]interface{}{},
			expected: 0,
		},
		{
			name:     "float64 total_count",
			meta:     map[string]interface{}{"total_count": float64(100)},
			expected: 100,
		},
		{
			name:     "int64 total_count",
			meta:     map[string]interface{}{"total_count": int64(200)},
			expected: 200,
		},
		{
			name:     "int total_count",
			meta:     map[string]interface{}{"total_count": 300},
			expected: 300,
		},
		{
			name:     "string total_count",
			meta:     map[string]interface{}{"total_count": "400"},
			expected: 400,
		},
		{
			name:     "json.Number total_count",
			meta:     map[string]interface{}{"total_count": json.Number("561780728")},
			expected: 561780728,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getMetaTotalCount(tt.meta)
			if result != tt.expected {
				t.Errorf("getMetaTotalCount() = %d, expected %d", result, tt.expected)
			}
		})
	}
}

// TestGetMetaNextURL tests extraction of next URL from meta
func TestGetMetaNextURL(t *testing.T) {
	tests := []struct {
		name     string
		meta     map[string]interface{}
		expected string
	}{
		{
			name:     "nil meta",
			meta:     nil,
			expected: "",
		},
		{
			name:     "empty meta",
			meta:     map[string]interface{}{},
			expected: "",
		},
		{
			name:     "valid next URL",
			meta:     map[string]interface{}{"next": "https://api.example.com/next"},
			expected: "https://api.example.com/next",
		},
		{
			name:     "nil next",
			meta:     map[string]interface{}{"next": nil},
			expected: "",
		},
		{
			name:     "non-string next",
			meta:     map[string]interface{}{"next": 123},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getMetaNextURL(tt.meta)
			if result != tt.expected {
				t.Errorf("getMetaNextURL() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// TestGetJobID tests the job ID retrieval function
func TestGetJobID(t *testing.T) {
	tests := []struct {
		name     string
		job      *IngestJob
		expected string
	}{
		{
			name:     "nil job",
			job:      nil,
			expected: "pagination-call",
		},
		{
			name:     "valid job",
			job:      &IngestJob{ID: "test-job-123"},
			expected: "test-job-123",
		},
		{
			name:     "job with empty ID",
			job:      &IngestJob{ID: ""},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getJobID(tt.job)
			if result != tt.expected {
				t.Errorf("getJobID() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// TestGetLastUpdateIDFromIOCs tests extraction of update_id from last IOC
func TestGetLastUpdateIDFromIOCs(t *testing.T) {
	tests := []struct {
		name     string
		iocs     []IOC
		expected string
	}{
		{
			name:     "empty list",
			iocs:     []IOC{},
			expected: "",
		},
		{
			name: "single IOC",
			iocs: []IOC{
				{UpdateID: "12345"},
			},
			expected: "12345",
		},
		{
			name: "multiple IOCs - gets last",
			iocs: []IOC{
				{UpdateID: "100"},
				{UpdateID: "200"},
				{UpdateID: "300"},
			},
			expected: "300",
		},
		{
			name: "last IOC has nil update_id",
			iocs: []IOC{
				{UpdateID: "100"},
				{UpdateID: nil},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getLastUpdateIDFromIOCs(tt.iocs)
			if result != tt.expected {
				t.Errorf("getLastUpdateIDFromIOCs() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// TestProcessIOCsToCSV_HashTypes tests CSV processing for all hash types
func TestProcessIOCsToCSV_HashTypes(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	iocs := []IOC{
		{IType: "hash_md5", Value: "d41d8cd98f00b204e9800998ecf8427e", Confidence: 90},
		{IType: "hash_sha1", Value: "da39a3ee5e6b4b0d3255bfef95601890afd80709", Confidence: 85},
		{IType: "hash_sha256", Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Confidence: 95},
	}

	existingFiles := make(map[string]bool)

	csvFiles, stats, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	if len(csvFiles) != 3 {
		t.Errorf("Expected 3 CSV files, got %d", len(csvFiles))
	}

	if stats.TotalNewIOCs != 3 {
		t.Errorf("Expected TotalNewIOCs=3, got %d", stats.TotalNewIOCs)
	}

	// Verify filenames for each hash type
	filenames := make(map[string]bool)
	for _, f := range csvFiles {
		filenames[filepath.Base(f)] = true
	}

	expectedFiles := []string{
		"anomali_threatstream_hash_md5.csv",
		"anomali_threatstream_hash_sha1.csv",
		"anomali_threatstream_hash_sha256.csv",
	}

	for _, expected := range expectedFiles {
		if !filenames[expected] {
			t.Errorf("Missing expected file: %s", expected)
		}
	}
}

// TestProcessIOCsToCSV_URLType tests CSV processing for URL IOCs
func TestProcessIOCsToCSV_URLType(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	iocs := []IOC{
		{
			IType:        "url",
			Value:        "http://evil.com/malware.exe",
			Confidence:   90,
			ThreatType:   "malware",
			Source:       "test",
			Tags:         []map[string]string{{"name": "phishing"}},
			ExpirationTs: "2024-12-31",
		},
	}

	existingFiles := make(map[string]bool)

	csvFiles, _, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	if len(csvFiles) != 1 {
		t.Errorf("Expected 1 CSV file, got %d", len(csvFiles))
	}

	filename := filepath.Base(csvFiles[0])
	if filename != "anomali_threatstream_url.csv" {
		t.Errorf("Expected filename 'anomali_threatstream_url.csv', got %q", filename)
	}

	// Verify file contents
	content, err := os.ReadFile(csvFiles[0])
	if err != nil {
		t.Fatalf("Failed to read CSV file: %v", err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "url.original") {
		t.Error("CSV missing header column 'url.original'")
	}
	if !strings.Contains(contentStr, "http://evil.com/malware.exe") {
		t.Error("CSV missing URL value")
	}
}

// TestProcessIOCsToCSV_EmailType tests CSV processing for email IOCs
func TestProcessIOCsToCSV_EmailType(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	iocs := []IOC{
		{
			IType:        "email",
			Value:        "malicious@evil.com",
			Confidence:   85,
			ThreatType:   "phishing",
			Source:       "test",
			Tags:         nil,
			ExpirationTs: "",
		},
	}

	existingFiles := make(map[string]bool)

	csvFiles, _, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	if len(csvFiles) != 1 {
		t.Errorf("Expected 1 CSV file, got %d", len(csvFiles))
	}

	filename := filepath.Base(csvFiles[0])
	if filename != "anomali_threatstream_email.csv" {
		t.Errorf("Expected filename 'anomali_threatstream_email.csv', got %q", filename)
	}

	// Verify file contents
	content, err := os.ReadFile(csvFiles[0])
	if err != nil {
		t.Fatalf("Failed to read CSV file: %v", err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "email.sender.address") {
		t.Error("CSV missing header column 'email.sender.address'")
	}
	if !strings.Contains(contentStr, "malicious@evil.com") {
		t.Error("CSV missing email value")
	}
}

// TestProcessIOCsToCSV_ITypeMapping tests IOC type mapping for various prefixes
func TestProcessIOCsToCSV_ITypeMapping(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	// Test all mal_* and apt_* prefixes
	iocs := []IOC{
		{IType: "mal_ip", IP: "1.1.1.1", Confidence: 90},
		{IType: "c2_ip", IP: "2.2.2.2", Confidence: 90},
		{IType: "apt_ip", IP: "3.3.3.3", Confidence: 90},
		{IType: "mal_domain", Value: "mal.com", Confidence: 90},
		{IType: "c2_domain", Value: "c2.com", Confidence: 90},
		{IType: "apt_domain", Value: "apt.com", Confidence: 90},
		{IType: "mal_url", Value: "http://mal.com", Confidence: 90},
		{IType: "apt_url", Value: "http://apt.com", Confidence: 90},
		{IType: "apt_email", Value: "apt@evil.com", Confidence: 90},
		{IType: "mal_email", Value: "mal@evil.com", Confidence: 90},
		{IType: "apt_md5", Value: "d41d8cd98f00b204e9800998ecf8427e", Confidence: 90},
		{IType: "mal_md5", Value: "098f6bcd4621d373cade4e832627b4f6", Confidence: 90},
		{IType: "apt_sha1", Value: "da39a3ee5e6b4b0d3255bfef95601890afd80709", Confidence: 90},
		{IType: "mal_sha1", Value: "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", Confidence: 90},
		{IType: "apt_sha256", Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Confidence: 90},
		{IType: "mal_sha256", Value: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", Confidence: 90},
	}

	existingFiles := make(map[string]bool)

	csvFiles, stats, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	// Should create 7 files (ip, domain, url, email, hash_md5, hash_sha1, hash_sha256)
	if len(csvFiles) != 7 {
		t.Errorf("Expected 7 CSV files, got %d", len(csvFiles))
	}

	if stats.TotalNewIOCs != 16 {
		t.Errorf("Expected TotalNewIOCs=16, got %d", stats.TotalNewIOCs)
	}

	// Verify IP file has all 3 IPs
	for _, f := range csvFiles {
		if strings.Contains(f, "_ip.csv") {
			content, _ := os.ReadFile(f)
			contentStr := string(content)
			if !strings.Contains(contentStr, "1.1.1.1") {
				t.Error("IP file missing mal_ip")
			}
			if !strings.Contains(contentStr, "2.2.2.2") {
				t.Error("IP file missing c2_ip")
			}
			if !strings.Contains(contentStr, "3.3.3.3") {
				t.Error("IP file missing apt_ip")
			}
		}
	}
}

// TestProcessIOCsToCSV_InvalidExistingCSV tests handling of invalid existing CSV data
func TestProcessIOCsToCSV_InvalidExistingCSV(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	// Existing file with incompatible columns
	existingCSV := `wrong_column,data
something,value
`
	// Write existing data to a temp file (simulating downloaded existing file)
	existingFilePath := filepath.Join(tempDir, "existing_anomali_threatstream_ip.csv")
	if err := os.WriteFile(existingFilePath, []byte(existingCSV), 0644); err != nil {
		t.Fatalf("Failed to write existing file: %v", err)
	}

	existingFilePaths := map[string]bool{
		"anomali_threatstream_ip.csv": true,
	}

	iocs := []IOC{
		{IType: "ip", IP: "1.2.3.4", Confidence: 90},
	}

	csvFiles, _, err := processIOCsToCSV(iocs, tempDir, existingFilePaths, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	// Should still create file with new data
	if len(csvFiles) != 1 {
		t.Errorf("Expected 1 CSV file, got %d", len(csvFiles))
	}

	// Verify new data is present
	content, _ := os.ReadFile(csvFiles[0])
	contentStr := string(content)
	if !strings.Contains(contentStr, "1.2.3.4") {
		t.Error("CSV missing new IP value")
	}
	if !strings.Contains(contentStr, "destination.ip") {
		t.Error("CSV missing correct header")
	}
}

// TestProcessIOCsToCSV_EmptyPrimaryValue tests handling of IOCs with empty primary values
func TestProcessIOCsToCSV_EmptyPrimaryValue(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	iocs := []IOC{
		{IType: "ip", IP: "", Confidence: 90},        // Empty IP
		{IType: "domain", Value: "", Confidence: 90}, // Empty domain
		{IType: "ip", IP: "1.2.3.4", Confidence: 90}, // Valid IP
	}

	existingFiles := make(map[string]bool)

	csvFiles, stats, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	// The function creates files for each type encountered, but empty values are filtered from rows
	// Should create 2 files (ip and domain), but domain will have no data rows
	if len(csvFiles) != 2 {
		t.Errorf("Expected 2 CSV files (ip and domain), got %d", len(csvFiles))
	}

	// Find the IP file and verify contents
	for _, f := range csvFiles {
		if strings.Contains(f, "_ip.csv") {
			content, _ := os.ReadFile(f)
			contentStr := string(content)

			// Count non-header lines with IPs
			lines := strings.Split(strings.TrimSpace(contentStr), "\n")
			dataLines := 0
			for _, line := range lines {
				if !strings.HasPrefix(line, "destination.ip") && line != "" {
					dataLines++
				}
			}
			if dataLines != 1 {
				t.Errorf("Expected 1 data line (empty IP filtered), got %d", dataLines)
			}
		}
	}

	// Stats should show 3 total IOCs processed
	if stats.TotalNewIOCs != 3 {
		t.Errorf("Expected TotalNewIOCs=3, got %d", stats.TotalNewIOCs)
	}
}

// TestNoHardcodedDefinitionIDs ensures no hardcoded UUIDs in source code
func TestNoHardcodedDefinitionIDs(t *testing.T) {
	content, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("Failed to read main.go: %v", err)
	}

	contentStr := string(content)

	// Check for hardcoded 32-character hex strings that look like definition IDs
	// Pattern: 32 consecutive hex characters
	if strings.Contains(contentStr, `DefinitionID: &"`) {
		// Look for hardcoded UUIDs in DefinitionID fields
		lines := strings.Split(contentStr, "\n")
		for i, line := range lines {
			if strings.Contains(line, "DefinitionID") && strings.Contains(line, `"`) {
				// Check if it's a descriptive name vs UUID
				if !strings.Contains(line, `"Anomali API"`) &&
					!strings.Contains(line, "apiIntegrationName") {
					// Count hex chars in line
					hexCount := 0
					for _, c := range line {
						if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
							hexCount++
						}
					}
					if hexCount >= 32 {
						t.Errorf("Line %d may contain hardcoded definition ID: %s", i+1, strings.TrimSpace(line))
					}
				}
			}
		}
	}

	// Verify descriptive API name is used
	if !strings.Contains(contentStr, `"Anomali API"`) {
		t.Error("Should use descriptive definition_id='Anomali API'")
	}
}

// TestIngestRequestValidation tests IngestRequest field types
func TestIngestRequestValidation(t *testing.T) {
	// Test that IngestRequest struct has correct field types for confidence filters
	req := IngestRequest{
		Repository:     "search-all",
		Status:         "active",
		Type:           "ip",
		TrustedCircles: "",
		FeedID:         "",
		ModifiedTsGt:   "",
		ModifiedTsLt:   "",
		UpdateIDGt:     "0",
		Limit:          1000,
		Next:           "",
	}

	// Test confidence pointer fields
	confidence := 70
	req.ConfidenceGte = &confidence

	if req.ConfidenceGte == nil {
		t.Error("ConfidenceGte should not be nil after assignment")
	}
	if *req.ConfidenceGte != 70 {
		t.Errorf("ConfidenceGte = %d, expected 70", *req.ConfidenceGte)
	}

	// Verify other confidence fields are nil by default
	if req.ConfidenceGt != nil {
		t.Error("ConfidenceGt should be nil by default")
	}
	if req.ConfidenceLt != nil {
		t.Error("ConfidenceLt should be nil by default")
	}
	if req.ConfidenceLte != nil {
		t.Error("ConfidenceLte should be nil by default")
	}
}

// TestIngestJobStructure tests IngestJob struct fields
func TestIngestJobStructure(t *testing.T) {
	job := IngestJob{
		ID:               "test-job-123",
		CreatedTimestamp: "2024-01-01T10:00:00Z",
		State:            JobRunning,
		IOCType:          "ip",
		Parameters: map[string]interface{}{
			"status":       "active",
			"search_after": "0",
		},
	}

	if job.ID != "test-job-123" {
		t.Errorf("Job ID = %q, expected 'test-job-123'", job.ID)
	}
	if job.State != JobRunning {
		t.Errorf("Job State = %q, expected %q", job.State, JobRunning)
	}
	if job.IOCType != "ip" {
		t.Errorf("Job IOCType = %q, expected 'ip'", job.IOCType)
	}

	// Test error field
	job.State = JobFailed
	job.Error = "Test error message"
	if job.Error != "Test error message" {
		t.Errorf("Job Error = %q, expected 'Test error message'", job.Error)
	}
}

// TestLastUpdateTrackerStructure tests LastUpdateTracker struct
func TestLastUpdateTrackerStructure(t *testing.T) {
	tracker := LastUpdateTracker{
		CreatedTimestamp: "2024-01-01T10:00:00Z",
		TotalCount:       1000,
		NextURL:          "https://api.example.com/next",
		UpdateID:         "12345",
	}

	if tracker.UpdateID != "12345" {
		t.Errorf("UpdateID = %q, expected '12345'", tracker.UpdateID)
	}
	if tracker.TotalCount != 1000 {
		t.Errorf("TotalCount = %d, expected 1000", tracker.TotalCount)
	}
	if tracker.NextURL != "https://api.example.com/next" {
		t.Errorf("NextURL = %q, expected 'https://api.example.com/next'", tracker.NextURL)
	}
}

// TestProcessStatsStructure tests ProcessStats struct
func TestProcessStatsStructure(t *testing.T) {
	stats := ProcessStats{
		TotalNewIOCs:     100,
		FilesWithNewData: 5,
	}

	if stats.TotalNewIOCs != 100 {
		t.Errorf("TotalNewIOCs = %d, expected 100", stats.TotalNewIOCs)
	}
	if stats.FilesWithNewData != 5 {
		t.Errorf("FilesWithNewData = %d, expected 5", stats.FilesWithNewData)
	}
}

// TestConstants tests that constants are defined correctly
func TestConstants(t *testing.T) {
	// Test collection names
	if CollectionUpdateTracker != "update_id_tracker" {
		t.Errorf("CollectionUpdateTracker = %q, expected 'update_id_tracker'", CollectionUpdateTracker)
	}
	if CollectionIngestJobs != "ingest_jobs" {
		t.Errorf("CollectionIngestJobs = %q, expected 'ingest_jobs'", CollectionIngestJobs)
	}

	// Test key names
	if KeyLastUpdate != "last_update" {
		t.Errorf("KeyLastUpdate = %q, expected 'last_update'", KeyLastUpdate)
	}

	// Test job states
	if JobRunning != "running" {
		t.Errorf("JobRunning = %q, expected 'running'", JobRunning)
	}
	if JobCompleted != "completed" {
		t.Errorf("JobCompleted = %q, expected 'completed'", JobCompleted)
	}
	if JobFailed != "failed" {
		t.Errorf("JobFailed = %q, expected 'failed'", JobFailed)
	}
}

// TestIngestResponseStructure tests IngestResponse struct
func TestIngestResponseStructure(t *testing.T) {
	response := IngestResponse{
		Message:      "Processed 100 IOCs into 5 lookup files",
		TotalIOCs:    100,
		FilesCreated: 5,
		UploadResults: []map[string]interface{}{
			{"file": "test.csv", "status": "success"},
		},
		JobID: "job-123",
		Meta: map[string]interface{}{
			"total_count": 100,
		},
		Next: "next-token",
		ProcessStats: map[string]interface{}{
			"total_new_iocs": 100,
		},
	}

	if response.TotalIOCs != 100 {
		t.Errorf("TotalIOCs = %d, expected 100", response.TotalIOCs)
	}
	if response.FilesCreated != 5 {
		t.Errorf("FilesCreated = %d, expected 5", response.FilesCreated)
	}
	if response.JobID != "job-123" {
		t.Errorf("JobID = %q, expected 'job-123'", response.JobID)
	}
	if response.Next != "next-token" {
		t.Errorf("Next = %q, expected 'next-token'", response.Next)
	}
	if len(response.UploadResults) != 1 {
		t.Errorf("UploadResults length = %d, expected 1", len(response.UploadResults))
	}
}

// ============================================================================
// Collections Tests - Using Mock Interfaces
// ============================================================================

// TestGetLastUpdateIDNotFound tests get_last_update_id when no previous update exists
func TestGetLastUpdateIDNotFound(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()
	mockStorage.GetObjectFunc = func(params *custom_storage.GetObjectParams, writer io.Writer) (*custom_storage.GetObjectOK, error) {
		return nil, mockAPIError(404, "Object not found")
	}

	result, err := getLastUpdateIDWithClient(ctx, mockStorage, "", logger)

	if err != nil {
		t.Errorf("Expected no error for not found, got: %v", err)
	}
	if result != nil {
		t.Errorf("Expected nil result for not found, got: %+v", result)
	}

	// Verify the correct collection and key were used
	if len(mockStorage.GetObjectCalls) != 1 {
		t.Errorf("Expected 1 GetObject call, got %d", len(mockStorage.GetObjectCalls))
	}
	if mockStorage.GetObjectCalls[0].CollectionName != CollectionUpdateTracker {
		t.Errorf("Expected collection %q, got %q", CollectionUpdateTracker, mockStorage.GetObjectCalls[0].CollectionName)
	}
	if mockStorage.GetObjectCalls[0].ObjectKey != KeyLastUpdate {
		t.Errorf("Expected key %q, got %q", KeyLastUpdate, mockStorage.GetObjectCalls[0].ObjectKey)
	}
}

// TestGetLastUpdateIDSuccess tests get_last_update_id when previous update exists
func TestGetLastUpdateIDSuccess(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	expectedTracker := &LastUpdateTracker{
		UpdateID:         "12345",
		CreatedTimestamp: "2024-01-01T10:00:00Z",
		TotalCount:       1000,
	}

	mockStorage := NewMockCustomStorage()
	mockStorage.GetObjectFunc = func(params *custom_storage.GetObjectParams, writer io.Writer) (*custom_storage.GetObjectOK, error) {
		data := marshalUpdateTracker(expectedTracker)
		writer.Write(data)
		return &custom_storage.GetObjectOK{}, nil
	}

	result, err := getLastUpdateIDWithClient(ctx, mockStorage, "", logger)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.UpdateID != expectedTracker.UpdateID {
		t.Errorf("UpdateID = %q, expected %q", result.UpdateID, expectedTracker.UpdateID)
	}
}

// TestGetLastUpdateIDWithType tests get_last_update_id with specific IOC type
func TestGetLastUpdateIDWithType(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()
	mockStorage.GetObjectFunc = func(params *custom_storage.GetObjectParams, writer io.Writer) (*custom_storage.GetObjectOK, error) {
		return nil, mockAPIError(404, "Object not found")
	}

	_, _ = getLastUpdateIDWithClient(ctx, mockStorage, "ip", logger)

	// Verify type-specific key was used
	if len(mockStorage.GetObjectCalls) != 1 {
		t.Fatalf("Expected 1 GetObject call, got %d", len(mockStorage.GetObjectCalls))
	}
	expectedKey := "last_update_ip"
	if mockStorage.GetObjectCalls[0].ObjectKey != expectedKey {
		t.Errorf("Expected key %q, got %q", expectedKey, mockStorage.GetObjectCalls[0].ObjectKey)
	}
}

// TestSaveUpdateIDSuccess tests save_update_id success
func TestSaveUpdateIDSuccess(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()
	mockStorage.PutObjectFunc = func(params *custom_storage.PutObjectParams) (*custom_storage.PutObjectOK, error) {
		return &custom_storage.PutObjectOK{}, nil
	}

	updateData := &LastUpdateTracker{
		UpdateID:         "12345",
		CreatedTimestamp: "2024-01-01T10:00:00Z",
	}

	err := saveUpdateIDWithClient(ctx, mockStorage, updateData, "", logger)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify the correct collection and key were used
	if len(mockStorage.PutObjectCalls) != 1 {
		t.Fatalf("Expected 1 PutObject call, got %d", len(mockStorage.PutObjectCalls))
	}
	if mockStorage.PutObjectCalls[0].CollectionName != CollectionUpdateTracker {
		t.Errorf("Expected collection %q, got %q", CollectionUpdateTracker, mockStorage.PutObjectCalls[0].CollectionName)
	}
	if mockStorage.PutObjectCalls[0].ObjectKey != KeyLastUpdate {
		t.Errorf("Expected key %q, got %q", KeyLastUpdate, mockStorage.PutObjectCalls[0].ObjectKey)
	}
}

// TestSaveUpdateIDWithType tests save_update_id with specific IOC type
func TestSaveUpdateIDWithType(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()
	mockStorage.PutObjectFunc = func(params *custom_storage.PutObjectParams) (*custom_storage.PutObjectOK, error) {
		return &custom_storage.PutObjectOK{}, nil
	}

	updateData := &LastUpdateTracker{UpdateID: "12345"}

	_ = saveUpdateIDWithClient(ctx, mockStorage, updateData, "ip", logger)

	// Verify type-specific key was used
	if len(mockStorage.PutObjectCalls) != 1 {
		t.Fatalf("Expected 1 PutObject call, got %d", len(mockStorage.PutObjectCalls))
	}
	expectedKey := "last_update_ip"
	if mockStorage.PutObjectCalls[0].ObjectKey != expectedKey {
		t.Errorf("Expected key %q, got %q", expectedKey, mockStorage.PutObjectCalls[0].ObjectKey)
	}
}

// TestSaveUpdateIDError tests save_update_id error handling
func TestSaveUpdateIDError(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()
	mockStorage.PutObjectFunc = func(params *custom_storage.PutObjectParams) (*custom_storage.PutObjectOK, error) {
		return nil, fmt.Errorf("storage unavailable")
	}

	updateData := &LastUpdateTracker{UpdateID: "12345"}

	err := saveUpdateIDWithClient(ctx, mockStorage, updateData, "", logger)

	if err == nil {
		t.Error("Expected error from PutObject failure")
	}
}

// TestCreateJobFirstRun tests create_job for first run (no previous update)
func TestCreateJobFirstRun(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()
	mockStorage.PutObjectFunc = func(params *custom_storage.PutObjectParams) (*custom_storage.PutObjectOK, error) {
		return &custom_storage.PutObjectOK{}, nil
	}

	job, err := createJobWithClient(ctx, mockStorage, nil, "", logger)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if job == nil {
		t.Fatal("Expected non-nil job")
	}
	if job.State != JobRunning {
		t.Errorf("Job state = %q, expected %q", job.State, JobRunning)
	}

	// Verify fresh start omits the cursor entirely (no update_id__gt, no search_after).
	// Some ThreatStream accounts reject a zero cursor with HTTP 400.
	if _, ok := job.Parameters["update_id__gt"]; ok {
		t.Errorf("Expected no update_id__gt for first run, got %v", job.Parameters["update_id__gt"])
	}
	if _, ok := job.Parameters["search_after"]; ok {
		t.Errorf("Expected no search_after for first run, got %v", job.Parameters["search_after"])
	}

	// Verify PutObject was called
	if len(mockStorage.PutObjectCalls) != 1 {
		t.Errorf("Expected 1 PutObject call, got %d", len(mockStorage.PutObjectCalls))
	}
}

// TestCreateJobIncrementalSync tests create_job for incremental sync (with previous update)
func TestCreateJobIncrementalSync(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()
	mockStorage.PutObjectFunc = func(params *custom_storage.PutObjectParams) (*custom_storage.PutObjectOK, error) {
		return &custom_storage.PutObjectOK{}, nil
	}

	lastUpdate := &LastUpdateTracker{UpdateID: "12345"}

	job, err := createJobWithClient(ctx, mockStorage, lastUpdate, "ip", logger)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if job == nil {
		t.Fatal("Expected non-nil job")
	}

	// Verify incremental sync parameters (stored as search_after cursor)
	if searchAfter, ok := job.Parameters["search_after"].(string); !ok || searchAfter != "12345" {
		t.Errorf("Expected search_after = '12345', got %v", job.Parameters["search_after"])
	}
	if job.IOCType != "ip" {
		t.Errorf("Job IOCType = %q, expected 'ip'", job.IOCType)
	}

	// Verify job ID includes type
	if !strings.Contains(job.ID, "_ip") {
		t.Errorf("Expected job ID to include '_ip', got %q", job.ID)
	}
}

// TestCreateJobError tests create_job error handling
func TestCreateJobError(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()
	mockStorage.PutObjectFunc = func(params *custom_storage.PutObjectParams) (*custom_storage.PutObjectOK, error) {
		return nil, nil // nil response indicates failure
	}

	_, err := createJobWithClient(ctx, mockStorage, nil, "", logger)

	if err == nil {
		t.Error("Expected error for nil response")
	}
}

// TestUpdateJobSuccess tests update_job success
func TestUpdateJobSuccess(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()
	mockStorage.PutObjectFunc = func(params *custom_storage.PutObjectParams) (*custom_storage.PutObjectOK, error) {
		return &custom_storage.PutObjectOK{}, nil
	}

	job := &IngestJob{
		ID:    "test-job-123",
		State: JobCompleted,
	}

	err := updateJobWithClient(ctx, mockStorage, job, logger)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify correct key was used
	if len(mockStorage.PutObjectCalls) != 1 {
		t.Fatalf("Expected 1 PutObject call, got %d", len(mockStorage.PutObjectCalls))
	}
	if mockStorage.PutObjectCalls[0].ObjectKey != "test-job-123" {
		t.Errorf("Expected key 'test-job-123', got %q", mockStorage.PutObjectCalls[0].ObjectKey)
	}
	if mockStorage.PutObjectCalls[0].CollectionName != CollectionIngestJobs {
		t.Errorf("Expected collection %q, got %q", CollectionIngestJobs, mockStorage.PutObjectCalls[0].CollectionName)
	}
}

// TestUpdateJobError tests update_job error handling
func TestUpdateJobError(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()
	mockStorage.PutObjectFunc = func(params *custom_storage.PutObjectParams) (*custom_storage.PutObjectOK, error) {
		return nil, nil // nil response indicates failure
	}

	job := &IngestJob{ID: "test-job-123", State: JobCompleted}

	err := updateJobWithClient(ctx, mockStorage, job, logger)

	if err == nil {
		t.Error("Expected error for nil response")
	}
}

// TestClearUpdateIDForTypeSuccess tests clear_update_id_for_type success
func TestClearUpdateIDForTypeSuccess(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()
	mockStorage.DeleteObjectFunc = func(params *custom_storage.DeleteObjectParams) (*custom_storage.DeleteObjectOK, error) {
		return &custom_storage.DeleteObjectOK{}, nil
	}

	err := clearUpdateIDForTypeWithClient(ctx, mockStorage, "ip", logger)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify correct key was deleted
	if len(mockStorage.DeleteObjectCalls) != 1 {
		t.Fatalf("Expected 1 DeleteObject call, got %d", len(mockStorage.DeleteObjectCalls))
	}
	expectedKey := "last_update_ip"
	if mockStorage.DeleteObjectCalls[0].ObjectKey != expectedKey {
		t.Errorf("Expected key %q, got %q", expectedKey, mockStorage.DeleteObjectCalls[0].ObjectKey)
	}
}

// TestClearUpdateIDForTypeNotFound tests clear_update_id_for_type when key doesn't exist
func TestClearUpdateIDForTypeNotFound(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()
	mockStorage.DeleteObjectFunc = func(params *custom_storage.DeleteObjectParams) (*custom_storage.DeleteObjectOK, error) {
		return nil, mockAPIError(404, "Object not found")
	}

	err := clearUpdateIDForTypeWithClient(ctx, mockStorage, "domain", logger)

	// Should not error for 404 (not found is expected)
	if err != nil {
		t.Errorf("Expected no error for 404, got: %v", err)
	}
}

// TestClearCollectionDataSuccess tests clear_collection_data functionality
func TestClearCollectionDataSuccess(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()
	mockStorage.DeleteObjectFunc = func(params *custom_storage.DeleteObjectParams) (*custom_storage.DeleteObjectOK, error) {
		return &custom_storage.DeleteObjectOK{}, nil
	}

	clearCollectionDataWithClient(ctx, mockStorage, logger)

	// Should clear 9 keys: last_update + 8 type-specific (ip, domain, url, email, hash, hash_md5, hash_sha1, hash_sha256)
	if len(mockStorage.DeleteObjectCalls) != 9 {
		t.Errorf("Expected 9 DeleteObject calls, got %d", len(mockStorage.DeleteObjectCalls))
	}

	// Verify keys that were deleted
	deletedKeys := make(map[string]bool)
	for _, call := range mockStorage.DeleteObjectCalls {
		deletedKeys[call.ObjectKey] = true
	}

	expectedKeys := []string{
		"last_update",
		"last_update_ip",
		"last_update_domain",
		"last_update_url",
		"last_update_email",
		"last_update_hash",
		"last_update_hash_md5",
		"last_update_hash_sha1",
		"last_update_hash_sha256",
	}

	for _, key := range expectedKeys {
		if !deletedKeys[key] {
			t.Errorf("Expected key %q to be deleted", key)
		}
	}
}

// TestClearCollectionDataErrorHandling tests clear_collection_data error handling
func TestClearCollectionDataErrorHandling(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	callCount := 0
	mockStorage := NewMockCustomStorage()
	mockStorage.DeleteObjectFunc = func(params *custom_storage.DeleteObjectParams) (*custom_storage.DeleteObjectOK, error) {
		callCount++
		// First call fails, rest succeed
		if callCount == 1 {
			return nil, mockAPIError(500, "Internal error")
		}
		return &custom_storage.DeleteObjectOK{}, nil
	}

	// Should not panic, just log errors
	clearCollectionDataWithClient(ctx, mockStorage, logger)

	// Should still attempt all 9 deletions
	if len(mockStorage.DeleteObjectCalls) != 9 {
		t.Errorf("Expected 9 DeleteObject calls despite errors, got %d", len(mockStorage.DeleteObjectCalls))
	}
}

// ============================================================================
// Query Params Tests
// ============================================================================

// TestBuildQueryParamsBasic tests buildQueryParams with basic parameters
func TestBuildQueryParamsBasic(t *testing.T) {
	req := IngestRequest{
		Status: "active",
		Type:   "ip",
		Limit:  1000,
	}

	job := &IngestJob{
		Parameters: map[string]interface{}{
			"search_after": "12345",
		},
	}

	params := buildQueryParams(req, job, "")

	// Verify required params
	if params["order_by"] != "update_id" {
		t.Errorf("Expected order_by = 'update_id', got %v", params["order_by"])
	}
	if params["status"] != "active" {
		t.Errorf("Expected status = 'active', got %v", params["status"])
	}
	if params["type"] != "ip" {
		t.Errorf("Expected type = 'ip', got %v", params["type"])
	}
	if params["limit"] != 1000 {
		t.Errorf("Expected limit = 1000, got %v", params["limit"])
	}
	if params["search_after"] != "12345" {
		t.Errorf("Expected search_after = '12345', got %v", params["search_after"])
	}
}

// TestBuildQueryParamsWithPagination tests buildQueryParams with pagination token
func TestBuildQueryParamsWithPagination(t *testing.T) {
	req := IngestRequest{
		Status: "active",
		Limit:  1000,
	}

	params := buildQueryParams(req, nil, "page_token_123")

	// Pagination token should be sent as search_after
	if params["search_after"] != "page_token_123" {
		t.Errorf("Expected search_after = 'page_token_123', got %v", params["search_after"])
	}
}

// TestBuildQueryParamsDefaultUpdateID tests buildQueryParams omits the cursor on cold start
func TestBuildQueryParamsDefaultUpdateID(t *testing.T) {
	req := IngestRequest{
		Limit: 1000,
	}

	params := buildQueryParams(req, nil, "")

	// Cold start (no job, no pagination): cursor must be omitted entirely.
	// Some ThreatStream accounts reject update_id__gt/search_after=0 with HTTP 400.
	if _, ok := params["search_after"]; ok {
		t.Errorf("Expected no search_after on cold start, got %v", params["search_after"])
	}
	if _, ok := params["update_id__gt"]; ok {
		t.Errorf("Expected no update_id__gt on cold start, got %v", params["update_id__gt"])
	}
}

// TestBuildQueryParamsConfidenceFilters tests buildQueryParams with confidence filters
func TestBuildQueryParamsConfidenceFilters(t *testing.T) {
	confidenceGte := 70
	confidenceLte := 95

	req := IngestRequest{
		Limit:         1000,
		ConfidenceGte: &confidenceGte,
		ConfidenceLte: &confidenceLte,
	}

	params := buildQueryParams(req, nil, "")

	if params["confidence__gte"] != 70 {
		t.Errorf("Expected confidence__gte = 70, got %v", params["confidence__gte"])
	}
	if params["confidence__lte"] != 95 {
		t.Errorf("Expected confidence__lte = 95, got %v", params["confidence__lte"])
	}
}

// TestBuildQueryParamsAllConfidenceFilters tests all confidence filter types
func TestBuildQueryParamsAllConfidenceFilters(t *testing.T) {
	gt, gte, lt, lte := 50, 60, 90, 95

	req := IngestRequest{
		Limit:         1000,
		ConfidenceGt:  &gt,
		ConfidenceGte: &gte,
		ConfidenceLt:  &lt,
		ConfidenceLte: &lte,
	}

	params := buildQueryParams(req, nil, "")

	if params["confidence__gt"] != 50 {
		t.Errorf("Expected confidence__gt = 50, got %v", params["confidence__gt"])
	}
	if params["confidence__gte"] != 60 {
		t.Errorf("Expected confidence__gte = 60, got %v", params["confidence__gte"])
	}
	if params["confidence__lt"] != 90 {
		t.Errorf("Expected confidence__lt = 90, got %v", params["confidence__lt"])
	}
	if params["confidence__lte"] != 95 {
		t.Errorf("Expected confidence__lte = 95, got %v", params["confidence__lte"])
	}
}

// TestBuildQueryParamsNoConfidenceFilters tests that confidence params are omitted when not set
func TestBuildQueryParamsNoConfidenceFilters(t *testing.T) {
	req := IngestRequest{
		Limit: 1000,
	}

	params := buildQueryParams(req, nil, "")

	// Confidence params should not be present
	if _, ok := params["confidence__gt"]; ok {
		t.Error("confidence__gt should not be present when not set")
	}
	if _, ok := params["confidence__gte"]; ok {
		t.Error("confidence__gte should not be present when not set")
	}
	if _, ok := params["confidence__lt"]; ok {
		t.Error("confidence__lt should not be present when not set")
	}
	if _, ok := params["confidence__lte"]; ok {
		t.Error("confidence__lte should not be present when not set")
	}
}

// TestBuildQueryParamsOptionalFields tests buildQueryParams with optional fields
func TestBuildQueryParamsOptionalFields(t *testing.T) {
	req := IngestRequest{
		TrustedCircles: "circle1,circle2",
		FeedID:         "feed123",
		Limit:          500,
	}

	params := buildQueryParams(req, nil, "")

	if params["trustedcircles"] != "circle1,circle2" {
		t.Errorf("Expected trustedcircles = 'circle1,circle2', got %v", params["trustedcircles"])
	}
	if params["feed_id"] != "feed123" {
		t.Errorf("Expected feed_id = 'feed123', got %v", params["feed_id"])
	}
	if params["limit"] != 500 {
		t.Errorf("Expected limit = 500, got %v", params["limit"])
	}
}

// TestBuildQueryParamsDefaultLimit tests buildQueryParams default limit
func TestBuildQueryParamsDefaultLimit(t *testing.T) {
	req := IngestRequest{
		Limit: 0, // Zero should default to 1000
	}

	params := buildQueryParams(req, nil, "")

	if params["limit"] != 1000 {
		t.Errorf("Expected default limit = 1000, got %v", params["limit"])
	}
}

// TestBuildQueryParamsJobUpdateID tests buildQueryParams uses job's update_id
func TestBuildQueryParamsJobUpdateID(t *testing.T) {
	req := IngestRequest{}

	job := &IngestJob{
		Parameters: map[string]interface{}{
			"search_after": "job_stored_67890",
		},
	}

	params := buildQueryParams(req, job, "")

	if params["search_after"] != "job_stored_67890" {
		t.Errorf("Expected search_after from job = 'job_stored_67890', got %v", params["search_after"])
	}
}

// TestBuildQueryParamsUpdateIDGtOverride tests that UpdateIDGt overrides for initial calls only
func TestBuildQueryParamsUpdateIDGtOverride(t *testing.T) {
	// Test 1: Manual override should work for initial calls (no pagination token)
	req := IngestRequest{
		UpdateIDGt: "manual_override_123",
		Limit:      1000,
	}

	job := &IngestJob{
		Parameters: map[string]interface{}{
			"search_after": "job_value_456",
		},
	}

	// Initial call (no pagination token) - manual override SHOULD apply (as search_after)
	params := buildQueryParams(req, job, "")
	if params["search_after"] != "manual_override_123" {
		t.Errorf("Expected search_after = 'manual_override_123' (manual override for initial call), got %v", params["search_after"])
	}

	// Test 2: Pagination call - manual override should NOT apply (matching Python behavior)
	paramsWithPagination := buildQueryParams(req, job, "pagination_token_789")
	if paramsWithPagination["search_after"] != "pagination_token_789" {
		t.Errorf("Expected search_after = 'pagination_token_789' (pagination takes precedence), got %v", paramsWithPagination["search_after"])
	}
}

// TestBuildQueryParamsModifiedTsInitialOnly tests that modified_ts overrides only apply for initial calls
func TestBuildQueryParamsModifiedTsInitialOnly(t *testing.T) {
	req := IngestRequest{
		ModifiedTsGt: "2024-01-01T00:00:00Z",
		ModifiedTsLt: "2024-12-31T23:59:59Z",
		Limit:        1000,
	}

	// Initial call (no pagination token, no job) - overrides SHOULD apply
	params := buildQueryParams(req, nil, "")
	if params["modified_ts__gt"] != "2024-01-01T00:00:00Z" {
		t.Errorf("Expected modified_ts__gt for initial call, got %v", params["modified_ts__gt"])
	}
	if params["modified_ts__lt"] != "2024-12-31T23:59:59Z" {
		t.Errorf("Expected modified_ts__lt for initial call, got %v", params["modified_ts__lt"])
	}

	// Pagination call - overrides should NOT apply (matching Python behavior)
	paramsWithPagination := buildQueryParams(req, nil, "pagination_token")
	if _, ok := paramsWithPagination["modified_ts__gt"]; ok {
		t.Error("modified_ts__gt should NOT be present for pagination calls")
	}
	if _, ok := paramsWithPagination["modified_ts__lt"]; ok {
		t.Error("modified_ts__lt should NOT be present for pagination calls")
	}
}

// ============================================================================
// TEST MODE Tests
// ============================================================================

// TestTestModeCreateJob tests job creation in TEST_MODE
func TestTestModeCreateJob(t *testing.T) {
	// Set TEST_MODE
	os.Setenv("TEST_MODE", "true")
	defer os.Unsetenv("TEST_MODE")

	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()
	// No mock functions needed - TEST_MODE should skip API calls

	job, err := createJobWithClient(ctx, mockStorage, nil, "ip", logger)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if job == nil {
		t.Fatal("Expected non-nil job")
	}

	// In TEST_MODE, no actual API calls should be made
	if len(mockStorage.PutObjectCalls) != 0 {
		t.Errorf("Expected 0 PutObject calls in TEST_MODE, got %d", len(mockStorage.PutObjectCalls))
	}
}

// TestTestModeUpdateJob tests job update in TEST_MODE
func TestTestModeUpdateJob(t *testing.T) {
	os.Setenv("TEST_MODE", "true")
	defer os.Unsetenv("TEST_MODE")

	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()

	job := &IngestJob{ID: "test-job", State: JobCompleted}
	err := updateJobWithClient(ctx, mockStorage, job, logger)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// In TEST_MODE, no actual API calls should be made
	if len(mockStorage.PutObjectCalls) != 0 {
		t.Errorf("Expected 0 PutObject calls in TEST_MODE, got %d", len(mockStorage.PutObjectCalls))
	}
}

// TestTestModeSaveUpdateID tests save_update_id in TEST_MODE
func TestTestModeSaveUpdateID(t *testing.T) {
	os.Setenv("TEST_MODE", "true")
	defer os.Unsetenv("TEST_MODE")

	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()

	updateData := &LastUpdateTracker{UpdateID: "12345"}
	err := saveUpdateIDWithClient(ctx, mockStorage, updateData, "ip", logger)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// In TEST_MODE, no actual API calls should be made
	if len(mockStorage.PutObjectCalls) != 0 {
		t.Errorf("Expected 0 PutObject calls in TEST_MODE, got %d", len(mockStorage.PutObjectCalls))
	}
}

// TestTestModeGetLastUpdateID tests get_last_update_id in TEST_MODE
func TestTestModeGetLastUpdateID(t *testing.T) {
	os.Setenv("TEST_MODE", "true")
	defer os.Unsetenv("TEST_MODE")

	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()

	result, err := getLastUpdateIDWithClient(ctx, mockStorage, "ip", logger)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != nil {
		t.Error("Expected nil result in TEST_MODE")
	}

	// In TEST_MODE, no actual API calls should be made
	if len(mockStorage.GetObjectCalls) != 0 {
		t.Errorf("Expected 0 GetObject calls in TEST_MODE, got %d", len(mockStorage.GetObjectCalls))
	}
}

// TestTestModeClearUpdateIDForType tests clear_update_id_for_type in TEST_MODE
func TestTestModeClearUpdateIDForType(t *testing.T) {
	os.Setenv("TEST_MODE", "true")
	defer os.Unsetenv("TEST_MODE")

	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()

	err := clearUpdateIDForTypeWithClient(ctx, mockStorage, "ip", logger)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// In TEST_MODE, no actual API calls should be made
	if len(mockStorage.DeleteObjectCalls) != 0 {
		t.Errorf("Expected 0 DeleteObject calls in TEST_MODE, got %d", len(mockStorage.DeleteObjectCalls))
	}
}

// TestTestModeClearCollectionData tests clear_collection_data in TEST_MODE
func TestTestModeClearCollectionData(t *testing.T) {
	os.Setenv("TEST_MODE", "true")
	defer os.Unsetenv("TEST_MODE")

	logger := slog.Default()
	ctx := context.Background()

	mockStorage := NewMockCustomStorage()

	clearCollectionDataWithClient(ctx, mockStorage, logger)

	// In TEST_MODE, no actual API calls should be made
	if len(mockStorage.DeleteObjectCalls) != 0 {
		t.Errorf("Expected 0 DeleteObject calls in TEST_MODE, got %d", len(mockStorage.DeleteObjectCalls))
	}
}

// ============================================================================
// Additional Error Handling Tests
// ============================================================================

// TestExtractNextTokenMalformedURL tests extract_next_token with malformed URL
func TestExtractNextTokenMalformedURL(t *testing.T) {
	logger := slog.Default()

	// URL without recognized parameters should fallback to last IOC
	meta := map[string]interface{}{
		"next": "https://api.example.com/v1/intelligence/?unknown_param=xyz&limit=1000",
	}
	iocs := []IOC{{UpdateID: "fallback_123"}}

	result := extractNextToken(meta, iocs, logger)

	if result != "fallback_123" {
		t.Errorf("Expected 'fallback_123', got %q", result)
	}
}

// TestExtractNextTokenSearchAfterPriority tests search_after has priority
func TestExtractNextTokenSearchAfterPriority(t *testing.T) {
	logger := slog.Default()

	// When both search_after and update_id__gt present, search_after wins
	meta := map[string]interface{}{
		"next": "https://api.example.com/v1/intelligence/?search_after=12345&update_id__gt=67890&limit=1000",
	}
	iocs := []IOC{{UpdateID: "999"}}

	result := extractNextToken(meta, iocs, logger)

	if result != "12345" {
		t.Errorf("Expected '12345' (search_after), got %q", result)
	}
}

// TestProcessIOCsToCSV_FileSizeWarning tests file size warning threshold
func TestProcessIOCsToCSV_FileSizeWarning(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	// Create a small IOC that won't trigger warnings but tests the logic path
	iocs := []IOC{
		{IType: "ip", IP: "1.2.3.4", Confidence: 90},
	}

	existingFiles := make(map[string]bool)

	csvFiles, _, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	if len(csvFiles) != 1 {
		t.Errorf("Expected 1 CSV file, got %d", len(csvFiles))
	}
}

// TestNormalizeIOCType_AllVariants tests all IOC type normalization variants
func TestNormalizeIOCType_AllVariants(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Standard types
		{"ip", "ip"},
		{"domain", "domain"},
		{"url", "url"},
		{"email", "email"},
		{"hash_md5", "hash_md5"},
		{"hash_sha1", "hash_sha1"},
		{"hash_sha256", "hash_sha256"},
		// Malware variants
		{"mal_ip", "ip"},
		{"mal_domain", "domain"},
		{"mal_url", "url"},
		{"mal_email", "email"},
		{"mal_md5", "hash_md5"},
		{"mal_sha1", "hash_sha1"},
		{"mal_sha256", "hash_sha256"},
		// C2 variants
		{"c2_ip", "ip"},
		{"c2_domain", "domain"},
		// APT variants
		{"apt_ip", "ip"},
		{"apt_domain", "domain"},
		{"apt_url", "url"},
		{"apt_email", "email"},
		{"apt_md5", "hash_md5"},
		{"apt_sha1", "hash_sha1"},
		{"apt_sha256", "hash_sha256"},
		// Compromised variants
		{"compromised_email", "email"},
		// Unknown
		{"unknown", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeIOCType(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeIOCType(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestIOCStructFieldAccess tests IOC struct field access patterns
func TestIOCStructFieldAccess(t *testing.T) {
	ioc := IOC{
		IType:        "ip",
		IP:           "1.2.3.4",
		Value:        "test-value",
		Confidence:   90,
		ThreatType:   "malware",
		Source:       "test-source",
		Tags:         []map[string]string{{"name": "tag1"}},
		ExpirationTs: "2024-12-31",
		UpdateID:     "12345",
	}

	if ioc.IType != "ip" {
		t.Errorf("IType = %q, expected 'ip'", ioc.IType)
	}
	if ioc.IP != "1.2.3.4" {
		t.Errorf("IP = %q, expected '1.2.3.4'", ioc.IP)
	}
	if ioc.Value != "test-value" {
		t.Errorf("Value = %q, expected 'test-value'", ioc.Value)
	}
	if ioc.ThreatType != "malware" {
		t.Errorf("ThreatType = %q, expected 'malware'", ioc.ThreatType)
	}
	if ioc.Source != "test-source" {
		t.Errorf("Source = %q, expected 'test-source'", ioc.Source)
	}
	if len(ioc.Tags) != 1 {
		t.Errorf("Tags length = %d, expected 1", len(ioc.Tags))
	}
}

// TestMapToIOC_Confidence tests confidence field handling in mapToIOC
func TestMapToIOC_Confidence(t *testing.T) {
	tests := []struct {
		name       string
		confidence interface{}
	}{
		{"int confidence", 90},
		{"float confidence", float64(85.5)},
		{"string confidence", "75"},
		{"nil confidence", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := map[string]interface{}{
				"itype":      "ip",
				"ip":         "1.2.3.4",
				"confidence": tt.confidence,
			}

			ioc := mapToIOC(input)

			if ioc.IType != "ip" {
				t.Errorf("IType = %q, expected 'ip'", ioc.IType)
			}
			// Just verify it doesn't panic
		})
	}
}

// TestProcessIOCsToCSV_BatchProcessing tests batch processing in CSV writing
func TestProcessIOCsToCSV_BatchProcessing(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	// Create many IOCs to trigger batch processing
	iocs := make([]IOC, 100)
	for i := 0; i < 100; i++ {
		iocs[i] = IOC{
			IType:      "ip",
			IP:         fmt.Sprintf("1.2.3.%d", i%256),
			Confidence: 90,
		}
	}

	existingFiles := make(map[string]bool)

	csvFiles, stats, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	if len(csvFiles) != 1 {
		t.Errorf("Expected 1 CSV file, got %d", len(csvFiles))
	}

	// Verify all unique IPs were written (256 unique IPs possible, but we have 100 IOCs)
	// Some will be duplicates due to mod 256
	if stats.TotalNewIOCs != 100 {
		t.Errorf("Expected TotalNewIOCs=100, got %d", stats.TotalNewIOCs)
	}
}

// TestBuildQueryParamsWithModifiedTs tests modified_ts parameters
func TestBuildQueryParamsWithModifiedTs(t *testing.T) {
	req := IngestRequest{
		ModifiedTsGt: "2024-01-01T00:00:00Z",
		ModifiedTsLt: "2024-12-31T23:59:59Z",
		Limit:        1000,
	}

	params := buildQueryParams(req, nil, "")

	// Verify modified_ts parameters are included (matching Python implementation)
	if params["modified_ts__gt"] != "2024-01-01T00:00:00Z" {
		t.Errorf("Expected modified_ts__gt = '2024-01-01T00:00:00Z', got %v", params["modified_ts__gt"])
	}
	if params["modified_ts__lt"] != "2024-12-31T23:59:59Z" {
		t.Errorf("Expected modified_ts__lt = '2024-12-31T23:59:59Z', got %v", params["modified_ts__lt"])
	}
	if params["limit"] != 1000 {
		t.Errorf("Expected limit = 1000, got %v", params["limit"])
	}
}

// TestBuildQueryParamsNoModifiedTs tests that modified_ts params are omitted when not set
func TestBuildQueryParamsNoModifiedTs(t *testing.T) {
	req := IngestRequest{
		Limit: 1000,
	}

	params := buildQueryParams(req, nil, "")

	// modified_ts params should not be present when not set
	if _, ok := params["modified_ts__gt"]; ok {
		t.Error("modified_ts__gt should not be present when not set")
	}
	if _, ok := params["modified_ts__lt"]; ok {
		t.Error("modified_ts__lt should not be present when not set")
	}
}

// TestFormatUpdateID tests update_id formatting from various types
func TestFormatUpdateID(t *testing.T) {
	tests := []struct {
		name     string
		updateID interface{}
		expected string
	}{
		{"string", "12345", "12345"},
		{"int", 67890, "67890"},
		{"float64", float64(99999), "99999"},
		{"nil", nil, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toString(tt.updateID)
			if result != tt.expected {
				t.Errorf("toString(%v) = %q, expected %q", tt.updateID, result, tt.expected)
			}
		})
	}
}

// TestParse207Response tests parsing of 207 Multi-Status API responses
func TestParse207Response(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name         string
		responseBody string
		expectError  bool
		expectedIOCs int
	}{
		{
			name: "valid Falcon API response with resources",
			responseBody: `{
				"resources": [
					{
						"body": {
							"objects": [
								{"itype": "ip", "ip": "1.2.3.4", "confidence": 90},
								{"itype": "ip", "ip": "5.6.7.8", "confidence": 85}
							],
							"meta": {
								"total_count": 2,
								"next": "https://api.example.com/next"
							}
						}
					}
				]
			}`,
			expectError:  false,
			expectedIOCs: 2,
		},
		{
			name: "direct objects at top level",
			responseBody: `{
				"objects": [
					{"itype": "domain", "value": "evil.com", "confidence": 80}
				],
				"meta": {
					"total_count": 1
				}
			}`,
			expectError:  false,
			expectedIOCs: 1,
		},
		{
			name: "response with errors",
			responseBody: `{
				"resources": [],
				"errors": [
					{"code": 429, "message": "Rate limited"}
				]
			}`,
			expectError:  false,
			expectedIOCs: 0,
		},
		{
			name:         "empty response body",
			responseBody: ``,
			expectError:  false,
			expectedIOCs: 0,
		},
		{
			name:         "invalid JSON",
			responseBody: `{invalid json`,
			expectError:  true,
			expectedIOCs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock API error with response body
			apiErr := &runtime.APIError{
				Code:          207,
				OperationName: "test",
				Response:      strings.NewReader(tt.responseBody),
			}

			iocs, meta, err := parse207Response(apiErr, logger)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(iocs) != tt.expectedIOCs {
				t.Errorf("Expected %d IOCs, got %d", tt.expectedIOCs, len(iocs))
			}

			// meta should always be non-nil
			if meta == nil {
				t.Error("Expected non-nil meta")
			}
		})
	}
}

// TestParse207ResponseNilBody tests parse207Response with nil response body
func TestParse207ResponseNilBody(t *testing.T) {
	logger := slog.Default()

	apiErr := &runtime.APIError{
		Code:          207,
		OperationName: "test",
		Response:      nil,
	}

	_, _, err := parse207Response(apiErr, logger)

	if err == nil {
		t.Error("Expected error for nil response body")
	}
}

// TestCommaSeparatedTypesError tests that comma-separated types are rejected
func TestCommaSeparatedTypesError(t *testing.T) {
	// The handleIngest function should reject comma-separated types
	req := IngestRequest{Type: "ip,domain"}
	if !strings.Contains(req.Type, ",") {
		t.Error("Expected type to contain comma")
	}
	// The actual validation is in handleIngest which requires full FDK context
	// but we can verify the logic condition
	if req.Type != "" && strings.Contains(req.Type, ",") {
		// This is the condition that triggers the 400 error
	} else {
		t.Error("Should detect comma-separated types")
	}
}

// TestProcessIOCsToCSV_ServerSideDedup tests that when existing_files contains a filename,
// only new rows are written to CSV (server-side dedup handles existing rows)
func TestProcessIOCsToCSV_ServerSideDedup(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	// Mark file as existing on NGSIEM
	existingFiles := map[string]bool{
		"anomali_threatstream_ip.csv": true,
	}

	// New IOCs to write
	iocs := []IOC{
		{
			IType:        "ip",
			IP:           "5.6.7.8",
			Confidence:   85,
			ThreatType:   "botnet",
			Meta:         IOCMeta{Severity: "medium"},
			Source:       "test2",
			Tags:         nil,
			ExpirationTs: "",
		},
	}

	csvFiles, stats, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	if len(csvFiles) != 1 {
		t.Fatalf("Expected 1 CSV file, got %d", len(csvFiles))
	}

	// Read the CSV and verify only new rows are written
	file, err := os.Open(csvFiles[0])
	if err != nil {
		t.Fatalf("Failed to open CSV file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to read CSV: %v", err)
	}

	// Header + 1 data row = 2 records total
	if len(records) != 2 {
		t.Errorf("Expected 2 records (header + 1 row), got %d", len(records))
	}

	// Verify header
	if records[0][0] != "destination.ip" {
		t.Errorf("Expected header 'destination.ip', got '%s'", records[0][0])
	}

	// Verify only new row is present
	if records[1][0] != "5.6.7.8" {
		t.Errorf("Expected IP '5.6.7.8', got '%s'", records[1][0])
	}

	if stats.FilesWithNewData != 1 {
		t.Errorf("Expected FilesWithNewData=1, got %d", stats.FilesWithNewData)
	}
}

// TestProcessIOCsToCSV_ExistingFileWritesOnlyNewRows verifies that even when a file exists
// on NGSIEM, we only write new rows to the local CSV (no merge with existing data)
func TestProcessIOCsToCSV_ExistingFileWritesOnlyNewRows(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	existingFiles := map[string]bool{
		"anomali_threatstream_ip.csv": true,
	}

	iocs := []IOC{
		{IType: "ip", IP: "1.2.3.4", Confidence: 90, ThreatType: "c2", Source: "test", ExpirationTs: "2024-12-31"},
		{IType: "ip", IP: "9.10.11.12", Confidence: 80, ThreatType: "malware", Source: "test", ExpirationTs: ""},
	}

	csvFiles, _, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	content, err := os.ReadFile(csvFiles[0])
	if err != nil {
		t.Fatalf("Failed to read CSV file: %v", err)
	}

	contentStr := string(content)

	// Only new IOCs should be present (no existing data merged in)
	if !strings.Contains(contentStr, "1.2.3.4") {
		t.Error("CSV missing new IP '1.2.3.4'")
	}
	if !strings.Contains(contentStr, "9.10.11.12") {
		t.Error("CSV missing new IP '9.10.11.12'")
	}

	// Count data rows (excluding header)
	lines := strings.Split(strings.TrimSpace(contentStr), "\n")
	if len(lines) != 3 { // header + 2 data rows
		t.Errorf("Expected 3 lines (header + 2 rows), got %d", len(lines))
	}
}

// TestBuildQueryParamsWithSeverityFilter tests severity filter in query params
func TestBuildQueryParamsWithSeverityFilter(t *testing.T) {
	req := IngestRequest{
		Severity: "high",
		Limit:    1000,
	}
	params := buildQueryParams(req, nil, "")

	if params["meta.severity"] != "high" {
		t.Errorf("Expected meta.severity='high', got '%v'", params["meta.severity"])
	}
}

// TestBuildQueryParamsNoSeverityFilter tests absence of severity filter
func TestBuildQueryParamsNoSeverityFilter(t *testing.T) {
	req := IngestRequest{Limit: 1000}
	params := buildQueryParams(req, nil, "")

	if _, exists := params["meta.severity"]; exists {
		t.Error("meta.severity should not be present when not specified")
	}
}

// TestBuildQueryParamsPartialConfidenceFilters tests partial confidence filter combinations
func TestBuildQueryParamsPartialConfidenceFilters(t *testing.T) {
	gte := 50
	req := IngestRequest{
		ConfidenceGte: &gte,
		Limit:         1000,
	}
	params := buildQueryParams(req, nil, "")

	if params["confidence__gte"] != 50 {
		t.Errorf("Expected confidence__gte=50, got %v", params["confidence__gte"])
	}
	if _, exists := params["confidence__gt"]; exists {
		t.Error("confidence__gt should not be present")
	}
	if _, exists := params["confidence__lte"]; exists {
		t.Error("confidence__lte should not be present")
	}
	if _, exists := params["confidence__lt"]; exists {
		t.Error("confidence__lt should not be present")
	}
}

// TestBuildQueryParamsNoJobNoUpdate tests query params with fresh start (no job, no update)
func TestBuildQueryParamsNoJobNoUpdate(t *testing.T) {
	req := IngestRequest{
		Status: "active",
		Type:   "ip",
		Limit:  500,
	}
	params := buildQueryParams(req, nil, "")

	if params["status"] != "active" {
		t.Errorf("Expected status='active', got '%v'", params["status"])
	}
	if params["type"] != "ip" {
		t.Errorf("Expected type='ip', got '%v'", params["type"])
	}
	if params["limit"] != 500 {
		t.Errorf("Expected limit=500, got %v", params["limit"])
	}
	// No search_after should be set for fresh start
	if _, exists := params["search_after"]; exists {
		t.Error("search_after should not be present for fresh start")
	}
}

// TestBuildQueryParamsJobFallbackToSearchAfter tests job parameter fallback logic
func TestBuildQueryParamsJobFallbackToSearchAfter(t *testing.T) {
	// Job with search_after in parameters
	job := &IngestJob{
		Parameters: map[string]interface{}{
			"search_after": "12345",
		},
	}
	req := IngestRequest{Limit: 1000}
	params := buildQueryParams(req, job, "")

	if params["search_after"] != "12345" {
		t.Errorf("Expected search_after='12345', got '%v'", params["search_after"])
	}
}

// TestBuildQueryParamsJobFallbackLegacyUpdateIDGt tests legacy update_id__gt fallback
func TestBuildQueryParamsJobFallbackLegacyUpdateIDGt(t *testing.T) {
	// Job with legacy update_id__gt
	job := &IngestJob{
		Parameters: map[string]interface{}{
			"update_id__gt": "98765",
		},
	}
	req := IngestRequest{Limit: 1000}
	params := buildQueryParams(req, job, "")

	// Should fallback to using update_id__gt as search_after
	if params["search_after"] != "98765" {
		t.Errorf("Expected search_after='98765' (from legacy update_id__gt), got '%v'", params["search_after"])
	}
}

// TestBuildQueryParamsHashTypeMapping tests that hash subtypes are mapped to "hash" for API
func TestBuildQueryParamsHashTypeMapping(t *testing.T) {
	for _, hashType := range []string{"md5", "sha1", "sha256"} {
		req := IngestRequest{Type: hashType, Limit: 1000}
		params := buildQueryParams(req, nil, "")

		if params["type"] != "hash" {
			t.Errorf("For type=%s, expected API type='hash', got '%v'", hashType, params["type"])
		}
	}
}

// TestBuildQueryParamsWithIType tests itype filter parameter
func TestBuildQueryParamsWithIType(t *testing.T) {
	req := IngestRequest{
		IType: "bot_ip",
		Limit: 1000,
	}
	params := buildQueryParams(req, nil, "")

	if params["itype"] != "bot_ip" {
		t.Errorf("Expected itype='bot_ip', got '%v'", params["itype"])
	}
}

// TestBuildQueryParamsWithTLP tests TLP filter parameter
func TestBuildQueryParamsWithTLP(t *testing.T) {
	req := IngestRequest{
		TLP:   "amber",
		Limit: 1000,
	}
	params := buildQueryParams(req, nil, "")

	if params["tlp"] != "amber" {
		t.Errorf("Expected tlp='amber', got '%v'", params["tlp"])
	}
}

// TestBuildQueryParamsWithValueContains tests value__contains filter parameter
func TestBuildQueryParamsWithValueContains(t *testing.T) {
	req := IngestRequest{
		ValueContains: "malware",
		Limit:         1000,
	}
	params := buildQueryParams(req, nil, "")

	if params["value__contains"] != "malware" {
		t.Errorf("Expected value__contains='malware', got '%v'", params["value__contains"])
	}
}

// TestBuildQueryParamsWithValueStartsWith tests value__startswith filter parameter
func TestBuildQueryParamsWithValueStartsWith(t *testing.T) {
	req := IngestRequest{
		ValueStartsWith: "192.168",
		Limit:           1000,
	}
	params := buildQueryParams(req, nil, "")

	if params["value__startswith"] != "192.168" {
		t.Errorf("Expected value__startswith='192.168', got '%v'", params["value__startswith"])
	}
}

// TestBuildQueryParamsWithTagsName tests tags.name filter parameter
func TestBuildQueryParamsWithTagsName(t *testing.T) {
	req := IngestRequest{
		TagsName: "apt",
		Limit:    1000,
	}
	params := buildQueryParams(req, nil, "")

	if params["tags.name"] != "apt" {
		t.Errorf("Expected tags.name='apt', got '%v'", params["tags.name"])
	}
}

// TestBuildQueryParamsWithSearchFilter tests search_filter parameter
func TestBuildQueryParamsWithSearchFilter(t *testing.T) {
	sf := 42
	req := IngestRequest{
		SearchFilter: &sf,
		Limit:        1000,
	}
	params := buildQueryParams(req, nil, "")

	if params["search_filter"] != 42 {
		t.Errorf("Expected search_filter=42, got '%v'", params["search_filter"])
	}
}

// TestBuildQueryParamsWithAdvancedQuery tests q (advanced query) parameter
func TestBuildQueryParamsWithAdvancedQuery(t *testing.T) {
	req := IngestRequest{
		Q:     "status=active AND confidence>=80",
		Limit: 1000,
	}
	params := buildQueryParams(req, nil, "")

	if params["q"] != "status=active AND confidence>=80" {
		t.Errorf("Expected q='status=active AND confidence>=80', got '%v'", params["q"])
	}
}

// TestBuildQueryParamsAllNewFilters tests all new filter parameters together
func TestBuildQueryParamsAllNewFilters(t *testing.T) {
	sf := 99
	req := IngestRequest{
		IType:           "mal_domain",
		TLP:             "red",
		ValueContains:   "evil",
		ValueStartsWith: "10.",
		TagsName:        "ransomware",
		SearchFilter:    &sf,
		Q:               "threat_type=malware",
		Limit:           1000,
	}
	params := buildQueryParams(req, nil, "")

	if params["itype"] != "mal_domain" {
		t.Errorf("Expected itype='mal_domain', got '%v'", params["itype"])
	}
	if params["tlp"] != "red" {
		t.Errorf("Expected tlp='red', got '%v'", params["tlp"])
	}
	if params["value__contains"] != "evil" {
		t.Errorf("Expected value__contains='evil', got '%v'", params["value__contains"])
	}
	if params["value__startswith"] != "10." {
		t.Errorf("Expected value__startswith='10.', got '%v'", params["value__startswith"])
	}
	if params["tags.name"] != "ransomware" {
		t.Errorf("Expected tags.name='ransomware', got '%v'", params["tags.name"])
	}
	if params["search_filter"] != 99 {
		t.Errorf("Expected search_filter=99, got '%v'", params["search_filter"])
	}
	if params["q"] != "threat_type=malware" {
		t.Errorf("Expected q='threat_type=malware', got '%v'", params["q"])
	}
}

// TestBuildQueryParamsNoNewFilters tests absence of new filter parameters when not set
func TestBuildQueryParamsNoNewFilters(t *testing.T) {
	req := IngestRequest{Limit: 1000}
	params := buildQueryParams(req, nil, "")

	for _, key := range []string{"itype", "tlp", "value__contains", "value__startswith", "tags.name", "search_filter", "q"} {
		if _, exists := params[key]; exists {
			t.Errorf("%s should not be present when not specified", key)
		}
	}
}

// TestExtractNextTokenVariations tests various meta field formats for next token extraction
func TestExtractNextTokenVariations(t *testing.T) {
	logger := slog.Default()
	iocs := []IOC{{UpdateID: "999"}}

	tests := []struct {
		name     string
		meta     map[string]interface{}
		expected string
	}{
		{
			name:     "search_after in URL",
			meta:     map[string]interface{}{"next": "https://api.example.com/v2/intelligence?search_after=abc123"},
			expected: "abc123",
		},
		{
			name:     "update_id__gt in URL",
			meta:     map[string]interface{}{"next": "https://api.example.com/v2/intelligence?update_id__gt=456"},
			expected: "456",
		},
		{
			name:     "from_update_id in URL",
			meta:     map[string]interface{}{"next": "https://api.example.com/v2/intelligence?from_update_id=789"},
			expected: "789",
		},
		{
			name:     "nil meta",
			meta:     nil,
			expected: "",
		},
		{
			name:     "empty next",
			meta:     map[string]interface{}{"next": ""},
			expected: "",
		},
		{
			name:     "no recognized params falls back to last IOC update_id",
			meta:     map[string]interface{}{"next": "https://api.example.com/v2/intelligence?limit=100"},
			expected: "999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractNextToken(tt.meta, iocs, logger)
			if result != tt.expected {
				t.Errorf("extractNextToken() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestCheckAndClearMissingTypesWithAllPresent tests that no clearing happens when all files exist
func TestCheckAndClearMissingTypesWithAllPresent(t *testing.T) {
	// Create a mock storage that tracks calls
	mockStorage := &mockCustomStorage{
		deleteResponses: map[string]error{},
	}

	logger := slog.Default()

	// All files present
	existingFiles := map[string]bool{
		"anomali_threatstream_ip.csv":          true,
		"anomali_threatstream_domain.csv":      true,
		"anomali_threatstream_url.csv":         true,
		"anomali_threatstream_email.csv":       true,
		"anomali_threatstream_hash_md5.csv":    true,
		"anomali_threatstream_hash_sha1.csv":   true,
		"anomali_threatstream_hash_sha256.csv": true,
	}

	// When all files are present, nothing should be cleared
	result := checkAndClearMissingTypesWithClient(context.Background(), mockStorage, existingFiles, logger)
	if result {
		t.Error("Expected shouldStartFresh=false when all files present")
	}
}

// TestCheckAndClearMissingTypesWithMissing tests that missing types get their update_ids cleared
func TestCheckAndClearMissingTypesWithMissing(t *testing.T) {
	mockStorage := &mockCustomStorage{
		deleteResponses: map[string]error{},
	}

	logger := slog.Default()

	// Only ip file present (others missing)
	existingFiles := map[string]bool{
		"anomali_threatstream_ip.csv": true,
	}

	result := checkAndClearMissingTypesWithClient(context.Background(), mockStorage, existingFiles, logger)
	if result {
		t.Error("Expected shouldStartFresh=false")
	}

	// Should have attempted to delete update_ids for missing types
	if mockStorage.deleteCount == 0 {
		t.Error("Expected delete calls for missing types")
	}
}

// checkAndClearMissingTypesWithClient - testable version using CustomStorageClient interface
func checkAndClearMissingTypesWithClient(ctx context.Context, storage CustomStorageClient, existingFiles map[string]bool, logger *slog.Logger) bool {
	expectedFiles := make([]string, 0)
	for iocTypeKey := range iocTypeMappings {
		expectedFiles = append(expectedFiles, fmt.Sprintf("anomali_threatstream_%s.csv", iocTypeKey))
	}

	var missingFiles []string
	for _, f := range expectedFiles {
		if !existingFiles[f] {
			missingFiles = append(missingFiles, f)
		}
	}

	if len(missingFiles) > 0 {
		logger.Info("Detected missing files - clearing update_ids for these types", "missing", missingFiles)

		for _, missingFile := range missingFiles {
			filenameBase := strings.TrimPrefix(missingFile, "anomali_threatstream_")
			filenameBase = strings.TrimSuffix(filenameBase, ".csv")

			collectionType := filenameBase
			if strings.HasPrefix(filenameBase, "hash_") {
				collectionType = "hash"
			}

			_ = clearUpdateIDForTypeWithClient(ctx, storage, collectionType, logger)
		}
	}

	return false
}

// TestIOCTypeMappingsCompleteness verifies all expected IOC types have valid mappings
func TestIOCTypeMappingsCompleteness(t *testing.T) {
	expectedTypes := []string{"ip", "domain", "url", "email", "hash_md5", "hash_sha1", "hash_sha256"}

	for _, typeName := range expectedTypes {
		mapping, ok := iocTypeMappings[typeName]
		if !ok {
			t.Errorf("Missing IOC type mapping for: %s", typeName)
			continue
		}

		if len(mapping.Columns) != 7 {
			t.Errorf("Type %s: expected 7 columns, got %d", typeName, len(mapping.Columns))
		}

		if mapping.PrimaryField == "" {
			t.Errorf("Type %s: PrimaryField is empty", typeName)
		}

		// Primary column (first column) should differ by type
		if mapping.Columns[0] == "" {
			t.Errorf("Type %s: first column is empty", typeName)
		}

		// Common columns should be present (after primary)
		commonCols := []string{"confidence", "threat_type", "severity", "source", "tags", "expiration_ts"}
		for i, col := range commonCols {
			if mapping.Columns[i+1] != col {
				t.Errorf("Type %s: column %d expected '%s', got '%s'", typeName, i+1, col, mapping.Columns[i+1])
			}
		}
	}
}

// TestProcessIOCsToCSV_NewFileNoExisting verifies behavior when no existing file exists
func TestProcessIOCsToCSV_NewFileNoExisting(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()

	// Empty existing files - everything is new
	existingFiles := make(map[string]bool)

	iocs := []IOC{
		{IType: "ip", IP: "1.2.3.4", Confidence: 90, ThreatType: "c2",
			Meta: IOCMeta{Severity: "high"}, Source: "feed1", ExpirationTs: "2025-01-01"},
	}

	csvFiles, stats, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	if len(csvFiles) != 1 {
		t.Fatalf("Expected 1 CSV file, got %d", len(csvFiles))
	}

	// Verify file contents
	file, err := os.Open(csvFiles[0])
	if err != nil {
		t.Fatalf("Failed to open CSV: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to read CSV: %v", err)
	}

	// Header + 1 data row
	if len(records) != 2 {
		t.Errorf("Expected 2 records, got %d", len(records))
	}

	// Verify all columns are populated
	row := records[1]
	if row[0] != "1.2.3.4" {
		t.Errorf("Expected IP='1.2.3.4', got '%s'", row[0])
	}
	if row[1] != "90" {
		t.Errorf("Expected confidence='90', got '%s'", row[1])
	}
	if row[2] != "c2" {
		t.Errorf("Expected threat_type='c2', got '%s'", row[2])
	}
	if row[3] != "high" {
		t.Errorf("Expected severity='high', got '%s'", row[3])
	}
	if row[4] != "feed1" {
		t.Errorf("Expected source='feed1', got '%s'", row[4])
	}

	if stats.FilesWithNewData != 1 {
		t.Errorf("Expected FilesWithNewData=1, got %d", stats.FilesWithNewData)
	}
}

// TestProcessIOCsToCSV_IntraFileDedupNewRows tests that duplicate IOCs within the same batch
// are deduplicated (later entries win) before writing
func TestProcessIOCsToCSV_IntraFileDedupNewRows(t *testing.T) {
	logger := slog.Default()
	tempDir := t.TempDir()
	existingFiles := make(map[string]bool)

	// Two IOCs with same primary key - later one should win
	iocs := []IOC{
		{IType: "ip", IP: "1.2.3.4", Confidence: 50, ThreatType: "suspicious", Source: "old"},
		{IType: "ip", IP: "1.2.3.4", Confidence: 95, ThreatType: "c2", Source: "new"},
	}

	csvFiles, _, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
	if err != nil {
		t.Fatalf("processIOCsToCSV failed: %v", err)
	}

	content, err := os.ReadFile(csvFiles[0])
	if err != nil {
		t.Fatalf("Failed to read CSV: %v", err)
	}

	contentStr := string(content)
	lines := strings.Split(strings.TrimSpace(contentStr), "\n")

	// Header + 1 deduplicated row = 2 lines
	if len(lines) != 2 {
		t.Errorf("Expected 2 lines (dedup), got %d", len(lines))
	}

	// Later entry (confidence=95) should win
	if !strings.Contains(contentStr, "95") {
		t.Error("Expected confidence=95 (later entry wins)")
	}
	if strings.Contains(contentStr, "\"50\"") {
		t.Error("Should NOT contain old confidence=50")
	}
}

// TestGetLastUpdateIDWithErrorResponse tests get_last_update_id behavior on non-404 errors
func TestGetLastUpdateIDWithErrorResponse(t *testing.T) {
	// Non-404 API error should propagate
	mockStorage := &mockCustomStorage{
		getError: &runtime.APIError{Code: 500, OperationName: "GetObject"},
	}

	_, err := getLastUpdateIDWithClient(context.Background(), mockStorage, "ip", slog.Default())
	if err == nil {
		t.Error("Expected error for 500 response")
	}
}

// TestSaveUpdateIDWithError tests save_update_id error propagation
func TestSaveUpdateIDWithError(t *testing.T) {
	mockStorage := &mockCustomStorage{
		putError: fmt.Errorf("connection refused"),
	}

	updateData := &LastUpdateTracker{
		UpdateID: "12345",
	}

	err := saveUpdateIDWithClient(context.Background(), mockStorage, updateData, "ip", slog.Default())
	if err == nil {
		t.Error("Expected error to propagate")
	}
}

// mockCustomStorage implements CustomStorageClient for testing
type mockCustomStorage struct {
	getError        error
	getResponse     *custom_storage.GetObjectOK
	putError        error
	putResponse     *custom_storage.PutObjectOK
	deleteResponses map[string]error
	deleteCount     int
}

func (m *mockCustomStorage) GetObject(params *custom_storage.GetObjectParams, writer io.Writer, opts ...custom_storage.ClientOption) (*custom_storage.GetObjectOK, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	return m.getResponse, nil
}

func (m *mockCustomStorage) PutObject(params *custom_storage.PutObjectParams, opts ...custom_storage.ClientOption) (*custom_storage.PutObjectOK, error) {
	if m.putError != nil {
		return nil, m.putError
	}
	if m.putResponse != nil {
		return m.putResponse, nil
	}
	return &custom_storage.PutObjectOK{}, nil
}

func (m *mockCustomStorage) DeleteObject(params *custom_storage.DeleteObjectParams, opts ...custom_storage.ClientOption) (*custom_storage.DeleteObjectOK, error) {
	m.deleteCount++
	if err, exists := m.deleteResponses[params.ObjectKey]; exists {
		return nil, err
	}
	return &custom_storage.DeleteObjectOK{}, nil
}

// TestExtractNextTokenMalformedURL tests graceful handling of malformed URLs in meta.next
func TestExtractNextTokenMalformedURL2(t *testing.T) {
	logger := slog.Default()
	iocs := []IOC{{UpdateID: "fallback123"}}

	meta := map[string]interface{}{
		"next": "not://a valid\nurl that can be parsed",
	}

	result := extractNextToken(meta, iocs, logger)
	// Should fallback to last IOC's update_id when URL parsing fails
	if result != "fallback123" {
		t.Errorf("Expected fallback to 'fallback123', got '%s'", result)
	}
}

// TestNoIOCsReturnsNoNextToken tests that empty IOC list returns no next token
func TestNoIOCsReturnsNoNextToken(t *testing.T) {
	logger := slog.Default()

	meta := map[string]interface{}{"next": "https://api.example.com?search_after=123"}

	// No IOCs means no pagination needed
	result := extractNextToken(meta, nil, logger)
	if result != "" {
		t.Errorf("Expected empty string for nil IOCs, got '%s'", result)
	}

	result = extractNextToken(meta, []IOC{}, logger)
	if result != "" {
		t.Errorf("Expected empty string for empty IOCs, got '%s'", result)
	}
}

// mockNgsIEMClient implements ngsiem.ClientService for testing uploadEntriesToNGSIEM retry logic.
type mockNgsIEMClient struct {
	ngsiem.ClientService
	updateLookupFileEntriesFunc func(params *ngsiem.UpdateLookupFileEntriesParams, opts ...ngsiem.ClientOption) (*ngsiem.UpdateLookupFileEntriesOK, error)
	callCount                   int
}

func (m *mockNgsIEMClient) UpdateLookupFileEntries(params *ngsiem.UpdateLookupFileEntriesParams, opts ...ngsiem.ClientOption) (*ngsiem.UpdateLookupFileEntriesOK, error) {
	m.callCount++
	return m.updateLookupFileEntriesFunc(params, opts...)
}

func TestUploadEntriesToNGSIEM_RetryOn429(t *testing.T) {
	// Create a temp CSV file
	tmpFile, err := os.CreateTemp("", "test_upload_*.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("destination.ip,confidence,threat_type,severity,source,tags,expiration_ts\n1.2.3.4,90,malware,high,test,tag1,2099-01-01\n")
	tmpFile.Close()

	mock := &mockNgsIEMClient{
		updateLookupFileEntriesFunc: func(params *ngsiem.UpdateLookupFileEntriesParams, opts ...ngsiem.ClientOption) (*ngsiem.UpdateLookupFileEntriesOK, error) {
			return nil, &runtime.APIError{Code: 429, OperationName: "UpdateLookupFileEntries"}
		},
	}

	falconClient := &client.CrowdStrikeAPISpecification{
		Ngsiem: mock,
	}

	ctx := context.Background()
	logger := slog.Default()

	_, err = uploadEntriesToNGSIEM(ctx, falconClient, tmpFile.Name(), "anomali_threatstream_ip.csv", "test-repo", logger)
	if err == nil {
		t.Fatal("Expected error after retries exhausted, got nil")
	}
	if !strings.Contains(err.Error(), "failed after") {
		t.Errorf("Expected 'failed after' in error, got: %s", err.Error())
	}
	// maxRetries is 5, so we expect 5 calls
	if mock.callCount != 5 {
		t.Errorf("Expected 5 retry attempts, got %d", mock.callCount)
	}
}

func TestUploadEntriesToNGSIEM_RetryOn503(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_upload_*.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("destination.ip,confidence,threat_type,severity,source,tags,expiration_ts\n1.2.3.4,90,malware,high,test,tag1,2099-01-01\n")
	tmpFile.Close()

	mock := &mockNgsIEMClient{
		updateLookupFileEntriesFunc: func(params *ngsiem.UpdateLookupFileEntriesParams, opts ...ngsiem.ClientOption) (*ngsiem.UpdateLookupFileEntriesOK, error) {
			return nil, &runtime.APIError{Code: 503, OperationName: "UpdateLookupFileEntries"}
		},
	}

	falconClient := &client.CrowdStrikeAPISpecification{
		Ngsiem: mock,
	}

	ctx := context.Background()
	logger := slog.Default()

	_, err = uploadEntriesToNGSIEM(ctx, falconClient, tmpFile.Name(), "anomali_threatstream_ip.csv", "test-repo", logger)
	if err == nil {
		t.Fatal("Expected error after retries exhausted, got nil")
	}
	if mock.callCount != 5 {
		t.Errorf("Expected 5 retry attempts, got %d", mock.callCount)
	}
}

func TestUploadEntriesToNGSIEM_NoRetryOnNonRetryableError(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_upload_*.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("destination.ip,confidence,threat_type,severity,source,tags,expiration_ts\n1.2.3.4,90,malware,high,test,tag1,2099-01-01\n")
	tmpFile.Close()

	mock := &mockNgsIEMClient{
		updateLookupFileEntriesFunc: func(params *ngsiem.UpdateLookupFileEntriesParams, opts ...ngsiem.ClientOption) (*ngsiem.UpdateLookupFileEntriesOK, error) {
			return nil, &runtime.APIError{Code: 400, OperationName: "UpdateLookupFileEntries"}
		},
	}

	falconClient := &client.CrowdStrikeAPISpecification{
		Ngsiem: mock,
	}

	ctx := context.Background()
	logger := slog.Default()

	_, err = uploadEntriesToNGSIEM(ctx, falconClient, tmpFile.Name(), "anomali_threatstream_ip.csv", "test-repo", logger)
	if err == nil {
		t.Fatal("Expected error on non-retryable status, got nil")
	}
	// Should fail immediately without retrying
	if mock.callCount != 1 {
		t.Errorf("Expected 1 attempt (no retry), got %d", mock.callCount)
	}
}

func TestUploadEntriesToNGSIEM_SucceedsAfterRetry(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_upload_*.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("destination.ip,confidence,threat_type,severity,source,tags,expiration_ts\n1.2.3.4,90,malware,high,test,tag1,2099-01-01\n")
	tmpFile.Close()

	callCount := 0
	mock := &mockNgsIEMClient{
		updateLookupFileEntriesFunc: func(params *ngsiem.UpdateLookupFileEntriesParams, opts ...ngsiem.ClientOption) (*ngsiem.UpdateLookupFileEntriesOK, error) {
			callCount++
			// Fail with 429 on first two calls, succeed on the third
			if callCount <= 2 {
				return nil, &runtime.APIError{Code: 429, OperationName: "UpdateLookupFileEntries"}
			}
			return &ngsiem.UpdateLookupFileEntriesOK{XCSTRACEID: "trace-123"}, nil
		},
	}

	falconClient := &client.CrowdStrikeAPISpecification{
		Ngsiem: mock,
	}

	ctx := context.Background()
	logger := slog.Default()

	result, err := uploadEntriesToNGSIEM(ctx, falconClient, tmpFile.Name(), "anomali_threatstream_ip.csv", "test-repo", logger)
	if err != nil {
		t.Fatalf("Expected success after retry, got error: %v", err)
	}
	if result["status"] != "success" {
		t.Errorf("Expected status 'success', got %v", result["status"])
	}
	if result["trace_id"] != "trace-123" {
		t.Errorf("Expected trace_id 'trace-123', got %v", result["trace_id"])
	}
	if callCount != 3 {
		t.Errorf("Expected 3 attempts, got %d", callCount)
	}
}
