// Package main implements Anomali ThreatStream IOC ingestion for Falcon Next-Gen SIEM.
//
// This function fetches threat intelligence from Anomali ThreatStream and creates
// CSV lookup files for use in Falcon Next-Gen SIEM detection and hunting workflows.
//
// Key Features:
//   - Streaming CSV processing with minimal memory overhead
//   - Incremental sync using update_id tracking
//   - Support for all IOC types: IP, domain, URL, email, hash (MD5/SHA1/SHA256)
//   - Deduplication with temporal precedence (newer data takes precedence)
//   - Job tracking and state persistence via Falcon collections
//   - TEST_MODE support for local development
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	fdk "github.com/CrowdStrike/foundry-fn-go"
	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/api_integrations"
	"github.com/crowdstrike/gofalcon/falcon/client/custom_storage"
	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
)

// Constants
const (
	MaxUploadSizeBytes      = 200 * 1024 * 1024 // 200 MB
	WarningThresholdBytes   = 180 * 1024 * 1024 // 180 MB
	CollectionUpdateTracker = "update_id_tracker"
	CollectionIngestJobs    = "ingest_jobs"
	KeyLastUpdate           = "last_update"
	JobRunning              = "running"
	JobCompleted            = "completed"
	JobFailed               = "failed"
)

// CustomStorageClient interface for custom storage operations (enables mocking)
type CustomStorageClient interface {
	GetObject(params *custom_storage.GetObjectParams, writer io.Writer, opts ...custom_storage.ClientOption) (*custom_storage.GetObjectOK, error)
	PutObject(params *custom_storage.PutObjectParams, opts ...custom_storage.ClientOption) (*custom_storage.PutObjectOK, error)
	DeleteObject(params *custom_storage.DeleteObjectParams, opts ...custom_storage.ClientOption) (*custom_storage.DeleteObjectOK, error)
}

// IOCTypeMapping defines column mappings for each IOC type
type IOCTypeMapping struct {
	Columns      []string
	PrimaryField string
}

// IOC type mappings for CSV column headers
var iocTypeMappings = map[string]IOCTypeMapping{
	"ip": {
		Columns:      []string{"destination.ip", "confidence", "threat_type", "source", "tags", "expiration_ts"},
		PrimaryField: "ip",
	},
	"domain": {
		Columns:      []string{"dns.domain.name", "confidence", "threat_type", "source", "tags", "expiration_ts"},
		PrimaryField: "value",
	},
	"url": {
		Columns:      []string{"url.original", "confidence", "threat_type", "source", "tags", "expiration_ts"},
		PrimaryField: "value",
	},
	"email": {
		Columns:      []string{"email.sender.address", "confidence", "threat_type", "source", "tags", "expiration_ts"},
		PrimaryField: "value",
	},
	"hash_md5": {
		Columns:      []string{"file.hash.md5", "confidence", "threat_type", "source", "tags", "expiration_ts"},
		PrimaryField: "value",
	},
	"hash_sha1": {
		Columns:      []string{"file.hash.sha1", "confidence", "threat_type", "source", "tags", "expiration_ts"},
		PrimaryField: "value",
	},
	"hash_sha256": {
		Columns:      []string{"file.hash.sha256", "confidence", "threat_type", "source", "tags", "expiration_ts"},
		PrimaryField: "value",
	},
}

// IngestRequest represents the request payload for IOC ingestion
type IngestRequest struct {
	Repository      string `json:"repository"`
	Status          string `json:"status"`
	Type            string `json:"type"`
	TrustedCircles  string `json:"trustedcircles"`
	FeedID          string `json:"feed_id"`
	ModifiedTsGt    string `json:"modified_ts_gt"`
	ModifiedTsLt    string `json:"modified_ts_lt"`
	UpdateIDGt      string `json:"update_id_gt"`
	ConfidenceGt    *int   `json:"confidence_gt"`
	ConfidenceGte   *int   `json:"confidence_gte"`
	ConfidenceLt    *int   `json:"confidence_lt"`
	ConfidenceLte   *int   `json:"confidence_lte"`
	Limit           int    `json:"limit"`
	Next            string `json:"next"`
	FailFastEnabled bool   `json:"fail_fast_enabled"`
}

// IngestResponse represents the response payload
type IngestResponse struct {
	Message       string                   `json:"message"`
	TotalIOCs     int                      `json:"total_iocs"`
	FilesCreated  int                      `json:"files_created"`
	UploadResults []map[string]interface{} `json:"upload_results"`
	JobID         string                   `json:"job_id"`
	Meta          map[string]interface{}   `json:"meta,omitempty"`
	Next          string                   `json:"next,omitempty"`
	ProcessStats  map[string]interface{}   `json:"process_stats,omitempty"`
}

// IOC represents a single indicator of compromise from Anomali
type IOC struct {
	IType        string              `json:"itype"`
	IP           string              `json:"ip"`
	Value        string              `json:"value"`
	Confidence   interface{}         `json:"confidence"`
	ThreatType   string              `json:"threat_type"`
	Source       string              `json:"source"`
	Tags         []map[string]string `json:"tags"`
	ExpirationTs string              `json:"expiration_ts"`
	UpdateID     interface{}         `json:"update_id"`
}

// ProcessStats tracks statistics during CSV processing
type ProcessStats struct {
	TotalNewIOCs           int `json:"total_new_iocs"`
	TotalDuplicatesRemoved int `json:"total_duplicates_removed"`
	FilesWithNewData       int `json:"files_with_new_data"`
}

// LastUpdateTracker tracks the last update_id from Anomali API for incremental sync
type LastUpdateTracker struct {
	CreatedTimestamp string `json:"created_timestamp"`
	TotalCount       int64  `json:"total_count"`
	NextURL          string `json:"next_url"`
	UpdateID         string `json:"update_id"`
}

// IngestJob represents a job tracking record
type IngestJob struct {
	ID               string                 `json:"id"`
	CreatedTimestamp string                 `json:"created_timestamp"`
	Error            string                 `json:"error,omitempty"`
	State            string                 `json:"state"`
	IOCType          string                 `json:"ioc_type"`
	Parameters       map[string]interface{} `json:"parameters"`
}

func main() {
	fdk.Run(context.Background(), newHandler)
}

func newHandler(ctx context.Context, logger *slog.Logger, _ fdk.SkipCfg) fdk.Handler {
	m := fdk.NewMux()

	m.Post("/ingest", fdk.HandleFnOf(func(ctx context.Context, r fdk.RequestOf[IngestRequest]) fdk.Response {
		return handleIngest(ctx, r, logger)
	}))

	return m
}

// isTestMode checks if TEST_MODE environment variable is set
func isTestMode() bool {
	testMode := strings.ToLower(os.Getenv("TEST_MODE"))
	return testMode == "true" || testMode == "1" || testMode == "yes"
}

// estimateFinalFileSizes checks if any file will exceed the 200 MB limit based on first batch.
// This fail-fast check prevents wasting hours on pagination only to fail at the end.
// Only runs on first execution (no existing files).
func estimateFinalFileSizes(csvFiles []string, iocsInBatch int, totalCount int64, existingFilePaths map[string]string, logger *slog.Logger) error {
	// Only run this check on first execution (no existing files)
	if len(existingFilePaths) > 0 {
		return nil
	}

	// Need at least some IOCs to estimate
	if iocsInBatch == 0 || totalCount == 0 {
		return nil
	}

	type projection struct {
		filename         string
		projectedRecords int
		projectedSizeMB  float64
	}
	var projections []projection

	for _, fp := range csvFiles {
		filename := filepath.Base(fp)

		fileInfo, err := os.Stat(fp)
		if err != nil {
			continue
		}
		fileSize := fileInfo.Size()
		fileSizeMB := float64(fileSize) / (1024 * 1024)

		// Count records in this file (subtract 1 for header)
		file, err := os.Open(fp)
		if err != nil {
			continue
		}
		recordCount := 0
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			recordCount++
		}
		file.Close()
		recordCount-- // Subtract header

		if recordCount <= 0 {
			continue
		}

		// Calculate bytes per record for this file type
		bytesPerRecord := float64(fileSize) / float64(recordCount)

		// Calculate what percentage of the batch went to this file
		distributionPct := float64(recordCount) / float64(iocsInBatch)

		// Project total records for this file type
		projectedRecords := int(float64(totalCount) * distributionPct)

		// Project final file size
		projectedSize := float64(projectedRecords) * bytesPerRecord
		projectedSizeMB := projectedSize / (1024 * 1024)

		logger.Info("File size projection",
			"filename", filename,
			"current_records", recordCount,
			"current_size_mb", fileSizeMB,
			"distribution_pct", distributionPct,
			"projected_records", projectedRecords,
			"projected_size_mb", projectedSizeMB)

		if projectedSize > float64(MaxUploadSizeBytes) {
			projections = append(projections, projection{
				filename:         filename,
				projectedRecords: projectedRecords,
				projectedSizeMB:  projectedSizeMB,
			})
		}
	}

	if len(projections) > 0 {
		// Build error message for files that will exceed limit
		var fileDetails []string
		for _, p := range projections {
			fileDetails = append(fileDetails, fmt.Sprintf("%s (~%.0f MB with %d records)", p.filename, p.projectedSizeMB, p.projectedRecords))
		}
		return fmt.Errorf(
			"The estimated file size will exceed the 200 MB NGSIEM API upload limit. "+
				"Based on first batch distribution: %s. "+
				"Total IOCs matching query: %d. "+
				"To reduce dataset size, use filters: "+
				"1) Use 'feed_id' to limit ingestion to specific threat feeds, "+
				"2) Use 'confidence_gte' to filter low-confidence IOCs (e.g., confidence_gte: 70).",
			strings.Join(fileDetails, ", "), totalCount)
	}

	return nil
}

func handleIngest(ctx context.Context, r fdk.RequestOf[IngestRequest], logger *slog.Logger) fdk.Response {
	req := r.Body
	startTime := time.Now()

	// Set defaults
	repository := req.Repository
	if repository == "" {
		repository = "search-all"
	}
	repository = strings.TrimSpace(repository)

	limit := req.Limit
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}

	// Validate type filter
	if req.Type != "" && strings.Contains(req.Type, ",") {
		return fdk.ErrResp(fdk.APIError{
			Code:    400,
			Message: "Comma-delimited types not supported. Use no type filter to get all types, or specify a single type.",
		})
	}

	// Log all request parameters for debugging
	logger.Info("Starting IOC ingestion",
		"repository", repository,
		"type", req.Type,
		"next", req.Next,
		"limit", limit,
		"status_filter", req.Status,
		"feed_id", req.FeedID,
		"trusted_circles", req.TrustedCircles,
		"confidence_gte", req.ConfidenceGte,
		"confidence_gt", req.ConfidenceGt,
		"update_id_gt", req.UpdateIDGt,
		"fail_fast_enabled", req.FailFastEnabled,
	)

	// Create temp directory early for file downloads and processing
	tempDir, err := os.MkdirTemp("", "anomali-iocs-*")
	if err != nil {
		return fdk.ErrResp(fdk.APIError{
			Code:    500,
			Message: fmt.Sprintf("Failed to create temp directory: %v", err),
		})
	}
	defer os.RemoveAll(tempDir)

	// Create Falcon client
	falconClient, err := newFalconClient(ctx, r.AccessToken)
	if err != nil {
		logger.Error("Failed to create Falcon client", "error", err)
		return fdk.ErrResp(fdk.APIError{
			Code:    500,
			Message: fmt.Sprintf("Failed to create Falcon client: %v", err),
		})
	}

	// Check for existing files and handle missing file recovery
	downloadStartTime := time.Now()
	logger.Info("Phase 1: Checking for existing lookup files")
	shouldStartFresh, existingFilePaths, err := checkAndRecoverMissingFiles(ctx, falconClient, r.AccessToken, repository, req.Type, tempDir, logger)
	downloadDuration := time.Since(downloadStartTime)
	if err != nil {
		// CRITICAL: Do NOT swallow this error! If downloads failed, we must abort
		// to prevent data loss. The error message already says "aborting to prevent data loss"
		// so we must actually abort, not just log and continue.
		logger.Error("Failed to download existing files - aborting to prevent data loss",
			"error", err,
			"duration_seconds", downloadDuration.Seconds())
		return fdk.ErrResp(fdk.APIError{
			Code:    500,
			Message: fmt.Sprintf("Download failed: %v. Please retry later.", err),
		})
	}
	logger.Info("Phase 1 complete: Existing files checked",
		"files_downloaded", len(existingFilePaths),
		"should_start_fresh", shouldStartFresh,
		"duration_seconds", downloadDuration.Seconds())

	if shouldStartFresh {
		logger.Info("Starting completely fresh sync - clearing all collection data")
		clearCollectionData(ctx, falconClient, logger)
	}

	// Handle job creation for initial calls vs pagination calls
	var job *IngestJob
	if req.Next != "" {
		logger.Info("Pagination call detected", "next_token", req.Next)
		// No job needed for pagination calls
	} else {
		// Initial call - get type-specific update_id and create job
		logger.Info("Initial call - creating type-specific job")

		lastUpdate, err := getLastUpdateID(ctx, falconClient, req.Type, logger)
		if err != nil {
			logger.Warn("Error getting last update_id, starting fresh", "error", err)
		}

		// Safety check: if we have saved progress but couldn't download existing files,
		// we should not proceed as we would lose accumulated data by uploading a partial file.
		// This can happen if the file download times out or fails temporarily.
		if lastUpdate != nil && req.Type != "" && len(existingFilePaths) == 0 && !shouldStartFresh {
			logger.Error("Data integrity protection: have saved progress but cannot download existing files",
				"type", req.Type,
				"last_update_id", lastUpdate.UpdateID,
				"hint", "Existing lookup file may have failed to download. Retry later or check NGSIEM connectivity.")
			return fdk.ErrResp(fdk.APIError{
				Code:    500,
				Message: fmt.Sprintf("Cannot proceed: have saved progress (update_id=%s) for type '%s' but failed to download existing lookup file. This would cause data loss. Please retry or check NGSIEM connectivity.", lastUpdate.UpdateID, req.Type),
			})
		}

		job, err = createJob(ctx, falconClient, lastUpdate, req.Type, logger)
		if err != nil {
			logger.Error("Failed to create job", "error", err)
			return fdk.ErrResp(fdk.APIError{
				Code:    500,
				Message: fmt.Sprintf("Failed to create job: %v", err),
			})
		}
	}

	// Fetch IOCs from Anomali via API integration
	fetchStartTime := time.Now()
	logger.Info("Phase 2: Fetching IOCs from Anomali API")
	iocs, meta, err := fetchIOCsFromAnomali(ctx, falconClient, r, job, logger)
	fetchDuration := time.Since(fetchStartTime)
	if err != nil {
		logger.Error("Failed to fetch IOCs from Anomali",
			"error", err,
			"duration_seconds", fetchDuration.Seconds())
		if job != nil {
			job.State = JobFailed
			job.Error = err.Error()
			_ = updateJob(ctx, falconClient, job, logger)
		}
		return fdk.ErrResp(fdk.APIError{
			Code:    500,
			Message: fmt.Sprintf("Failed to fetch IOCs: %v", err),
		})
	}
	logger.Info("Phase 2 complete: IOCs fetched from Anomali",
		"ioc_count", len(iocs),
		"duration_seconds", fetchDuration.Seconds())

	if len(iocs) == 0 {
		// Mark job as completed even with no data
		if job != nil {
			job.State = JobCompleted
			_ = updateJob(ctx, falconClient, job, logger)
		}
		totalDuration := time.Since(startTime)
		logger.Info("Ingestion complete - no IOCs found",
			"total_duration_seconds", totalDuration.Seconds())

		return fdk.Response{
			Code: 200,
			Body: fdk.JSON(IngestResponse{
				Message:       "No IOCs found matching criteria",
				TotalIOCs:     0,
				FilesCreated:  0,
				UploadResults: []map[string]interface{}{},
				JobID:         getJobID(job),
				Meta:          map[string]interface{}{},
			}),
		}
	}

	// Process IOCs into CSV files (tempDir already created earlier)
	processStartTime := time.Now()
	logger.Info("Phase 3: Processing IOCs into CSV files")
	csvFiles, stats, err := processIOCsToCSV(iocs, tempDir, existingFilePaths, logger)
	processDuration := time.Since(processStartTime)
	if err != nil {
		logger.Error("Failed to process IOCs into CSV",
			"error", err,
			"duration_seconds", processDuration.Seconds())
		if job != nil {
			job.State = JobFailed
			job.Error = err.Error()
			_ = updateJob(ctx, falconClient, job, logger)
		}
		return fdk.ErrResp(fdk.APIError{
			Code:    500,
			Message: fmt.Sprintf("Failed to process IOCs: %v", err),
		})
	}
	logger.Info("Phase 3 complete: CSV files created",
		"files_created", len(csvFiles),
		"new_iocs", stats.TotalNewIOCs,
		"duplicates_updated", stats.TotalDuplicatesRemoved,
		"duration_seconds", processDuration.Seconds())

	// Fail-fast check: estimate final file sizes on first execution
	// This prevents wasting hours on pagination only to fail at the end
	if req.FailFastEnabled {
		totalCount := getMetaTotalCount(meta)
		if err := estimateFinalFileSizes(csvFiles, len(iocs), totalCount, existingFilePaths, logger); err != nil {
			logger.Error("File size projection exceeds limit", "error", err)
			if job != nil {
				job.State = JobFailed
				job.Error = err.Error()
				_ = updateJob(ctx, falconClient, job, logger)
			}
			return fdk.ErrResp(fdk.APIError{
				Code:    500,
				Message: err.Error(),
			})
		}
	}

	// Upload CSV files to NGSIEM
	uploadStartTime := time.Now()
	logger.Info("Phase 4: Uploading CSV files to NGSIEM")
	uploadResults, err := uploadCSVFilesToNGSIEM(ctx, falconClient, csvFiles, repository, logger)
	uploadDuration := time.Since(uploadStartTime)
	if err != nil {
		logger.Error("Failed to upload files",
			"error", err,
			"duration_seconds", uploadDuration.Seconds())
	} else {
		logger.Info("Phase 4 complete: Files uploaded to NGSIEM",
			"files_uploaded", len(uploadResults),
			"duration_seconds", uploadDuration.Seconds())
	}

	// Update collections with latest state
	if meta != nil && len(iocs) > 0 {
		maxUpdateID := getMaxUpdateID(iocs)
		updateData := &LastUpdateTracker{
			CreatedTimestamp: time.Now().UTC().Format(time.RFC3339),
			TotalCount:       getMetaTotalCount(meta),
			NextURL:          getMetaNextURL(meta),
			UpdateID:         maxUpdateID,
		}
		if err := saveUpdateID(ctx, falconClient, updateData, req.Type, logger); err != nil {
			logger.Error("Failed to save update_id", "error", err)
		} else {
			logger.Info("Saved update_id for incremental sync",
				"type", req.Type,
				"update_id", maxUpdateID)
		}
	}

	// Mark job as completed
	if job != nil {
		job.State = JobCompleted
		_ = updateJob(ctx, falconClient, job, logger)
	}

	// Calculate total duration and log summary
	totalDuration := time.Since(startTime)
	logger.Info("Ingestion complete - SUCCESS",
		"total_iocs_processed", len(iocs),
		"files_created", len(csvFiles),
		"new_iocs", stats.TotalNewIOCs,
		"duplicates_updated", stats.TotalDuplicatesRemoved,
		"total_duration_seconds", totalDuration.Seconds(),
		"download_duration_seconds", downloadDuration.Seconds(),
		"fetch_duration_seconds", fetchDuration.Seconds(),
		"process_duration_seconds", processDuration.Seconds(),
		"upload_duration_seconds", uploadDuration.Seconds())

	// Build response
	response := IngestResponse{
		Message:       fmt.Sprintf("Processed %d IOCs into %d lookup files", len(iocs), len(csvFiles)),
		TotalIOCs:     len(iocs),
		FilesCreated:  len(csvFiles),
		UploadResults: uploadResults,
		JobID:         getJobID(job),
		Meta:          meta,
		ProcessStats: map[string]interface{}{
			"total_new_iocs":           stats.TotalNewIOCs,
			"total_duplicates_removed": stats.TotalDuplicatesRemoved,
			"files_with_new_data":      stats.FilesWithNewData,
		},
	}

	// Extract next token if present
	if nextToken := extractNextToken(meta, iocs, logger); nextToken != "" {
		response.Next = nextToken
	}

	return fdk.Response{
		Code: 200,
		Body: fdk.JSON(response),
	}
}

// getJobID returns the job ID or a default value
func getJobID(job *IngestJob) string {
	if job != nil {
		return job.ID
	}
	return "pagination-call"
}

// getMaxUpdateID extracts the highest update_id from processed IOCs
func getMaxUpdateID(iocs []IOC) string {
	var maxID string
	var maxIDNum int64 = -1
	for _, ioc := range iocs {
		if ioc.UpdateID != nil {
			id := toString(ioc.UpdateID)
			// Try numeric comparison first (more accurate for numeric IDs)
			if num, err := strconv.ParseInt(id, 10, 64); err == nil {
				if num > maxIDNum {
					maxIDNum = num
					maxID = id
				}
			} else if id > maxID {
				// Fallback to string comparison for non-numeric IDs
				maxID = id
			}
		}
	}
	return maxID
}

// getMetaTotalCount extracts total_count from meta
func getMetaTotalCount(meta map[string]interface{}) int64 {
	if meta == nil {
		return 0
	}
	if tc, ok := meta["total_count"]; ok {
		switch v := tc.(type) {
		case float64:
			return int64(v)
		case int64:
			return v
		case int:
			return int64(v)
		case json.Number:
			if n, err := v.Int64(); err == nil {
				return n
			}
		case string:
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				return n
			}
		}
	}
	return 0
}

// getMetaNextURL extracts next URL from meta
func getMetaNextURL(meta map[string]interface{}) string {
	if meta == nil {
		return ""
	}
	if next, ok := meta["next"].(string); ok {
		return next
	}
	return ""
}

// newFalconClient creates a new Falcon API client
func newFalconClient(ctx context.Context, accessToken string) (*client.CrowdStrikeAPISpecification, error) {
	opts := fdk.FalconClientOpts()
	return falcon.NewClient(&falcon.ApiConfig{
		AccessToken:       accessToken,
		Cloud:             falcon.Cloud(opts.Cloud),
		Context:           ctx,
		UserAgentOverride: opts.UserAgent,
	})
}

// getLastUpdateID retrieves the last update_id from collections for incremental sync
func getLastUpdateID(ctx context.Context, falconClient *client.CrowdStrikeAPISpecification, iocType string, logger *slog.Logger) (*LastUpdateTracker, error) {
	if isTestMode() {
		logger.Info("TEST MODE: Returning nil for last update_id")
		return nil, nil
	}

	objectKey := KeyLastUpdate
	if iocType != "" {
		objectKey = fmt.Sprintf("%s_%s", KeyLastUpdate, iocType)
	}

	logger.Info("Fetching last update_id from collections", "key", objectKey)

	buf := new(bytes.Buffer)
	params := custom_storage.NewGetObjectParamsWithContext(ctx)
	params.CollectionName = CollectionUpdateTracker
	params.ObjectKey = objectKey

	resp, err := falconClient.CustomStorage.GetObject(params, buf)
	if err != nil {
		// Check if it's a 404 (not found)
		if apiErr, ok := err.(*runtime.APIError); ok && apiErr.Code == http.StatusNotFound {
			logger.Info("No previous update_id found, will fetch from beginning", "type", iocType)
			return nil, nil
		}
		return nil, err
	}

	if resp == nil {
		logger.Info("No previous update_id found, will fetch from beginning", "type", iocType)
		return nil, nil
	}

	data, err := io.ReadAll(buf)
	if err != nil {
		return nil, err
	}

	var tracker LastUpdateTracker
	if err := json.Unmarshal(data, &tracker); err != nil {
		return nil, err
	}

	logger.Info("Retrieved last update data", "type", iocType, "update_id", tracker.UpdateID)
	return &tracker, nil
}

// saveUpdateID saves the current update_id to collections
func saveUpdateID(ctx context.Context, falconClient *client.CrowdStrikeAPISpecification, updateData *LastUpdateTracker, iocType string, logger *slog.Logger) error {
	if isTestMode() {
		logger.Info("TEST MODE: Mock save update_id", "type", iocType, "update_id", updateData.UpdateID)
		return nil
	}

	objectKey := KeyLastUpdate
	if iocType != "" {
		objectKey = fmt.Sprintf("%s_%s", KeyLastUpdate, iocType)
	}

	logger.Info("Saving update_id to collections", "key", objectKey, "update_id", updateData.UpdateID)

	data, err := json.Marshal(updateData)
	if err != nil {
		return err
	}

	reader := io.NopCloser(bytes.NewReader(data))
	params := custom_storage.NewPutObjectParamsWithContext(ctx)
	params.Body = reader
	params.CollectionName = CollectionUpdateTracker
	params.ObjectKey = objectKey

	resp, err := falconClient.CustomStorage.PutObject(params)
	if err != nil {
		return err
	}

	if resp == nil {
		return fmt.Errorf("failed to save update_id: nil response")
	}

	logger.Info("Successfully saved update_id", "type", iocType)
	return nil
}

// createJob creates a new ingest job record
func createJob(ctx context.Context, falconClient *client.CrowdStrikeAPISpecification, lastUpdate *LastUpdateTracker, iocType string, logger *slog.Logger) (*IngestJob, error) {
	now := time.Now().UTC()
	baseID := fmt.Sprintf("%d", now.UnixNano())[:8]
	jobID := baseID
	if iocType != "" {
		jobID = fmt.Sprintf("%s_%s", baseID, iocType)
	}

	jobParams := map[string]interface{}{
		"status":   "active",
		"order_by": "update_id",
	}

	if iocType != "" {
		jobParams["type"] = iocType
	}

	if lastUpdate != nil {
		jobParams["update_id__gt"] = lastUpdate.UpdateID
		logger.Info("Incremental sync - resuming from last update_id", "type", iocType, "update_id", lastUpdate.UpdateID)
	} else {
		jobParams["update_id__gt"] = "0"
		logger.Info("Fresh start - no previous update_id found", "type", iocType)
	}

	job := &IngestJob{
		ID:               jobID,
		CreatedTimestamp: now.Format(time.RFC3339),
		State:            JobRunning,
		IOCType:          iocType,
		Parameters:       jobParams,
	}

	if isTestMode() {
		logger.Info("TEST MODE: Created mock job", "job_id", jobID)
		return job, nil
	}

	logger.Info("Creating job", "job_id", jobID)

	data, err := json.Marshal(job)
	if err != nil {
		return nil, err
	}

	reader := io.NopCloser(bytes.NewReader(data))
	params := custom_storage.NewPutObjectParamsWithContext(ctx)
	params.Body = reader
	params.CollectionName = CollectionIngestJobs
	params.ObjectKey = jobID

	resp, err := falconClient.CustomStorage.PutObject(params)
	if err != nil {
		return nil, err
	}

	if resp == nil {
		return nil, fmt.Errorf("failed to create job: nil response")
	}

	logger.Info("Successfully created job", "job_id", jobID)
	return job, nil
}

// updateJob updates job status in collections
func updateJob(ctx context.Context, falconClient *client.CrowdStrikeAPISpecification, job *IngestJob, logger *slog.Logger) error {
	if isTestMode() {
		logger.Info("TEST MODE: Mock job update", "job_id", job.ID, "state", job.State)
		return nil
	}

	logger.Info("Updating job", "job_id", job.ID, "state", job.State)

	data, err := json.Marshal(job)
	if err != nil {
		return err
	}

	reader := io.NopCloser(bytes.NewReader(data))
	params := custom_storage.NewPutObjectParamsWithContext(ctx)
	params.Body = reader
	params.CollectionName = CollectionIngestJobs
	params.ObjectKey = job.ID

	resp, err := falconClient.CustomStorage.PutObject(params)
	if err != nil {
		return err
	}

	if resp == nil {
		return fmt.Errorf("failed to update job: nil response")
	}

	logger.Info("Successfully updated job", "job_id", job.ID)
	return nil
}

// clearUpdateIDForType clears the update_id for a specific IOC type
func clearUpdateIDForType(ctx context.Context, falconClient *client.CrowdStrikeAPISpecification, iocType string, logger *slog.Logger) error {
	if isTestMode() {
		logger.Info("TEST MODE: Mock clear update_id", "type", iocType)
		return nil
	}

	objectKey := fmt.Sprintf("%s_%s", KeyLastUpdate, iocType)
	logger.Info("Clearing update_id for type", "type", iocType, "key", objectKey)

	params := custom_storage.NewDeleteObjectParamsWithContext(ctx)
	params.CollectionName = CollectionUpdateTracker
	params.ObjectKey = objectKey

	_, err := falconClient.CustomStorage.DeleteObject(params)
	if err != nil {
		// Ignore "not found" errors - expected if key doesn't exist
		if apiErr, ok := err.(*runtime.APIError); ok && apiErr.Code == http.StatusNotFound {
			logger.Info("No update_id to clear for type", "type", iocType)
			return nil
		}
		return err
	}

	logger.Info("Successfully cleared update_id for type", "type", iocType)
	return nil
}

// clearCollectionData clears collection data when starting from scratch
func clearCollectionData(ctx context.Context, falconClient *client.CrowdStrikeAPISpecification, logger *slog.Logger) {
	if isTestMode() {
		logger.Info("TEST MODE: Mock clear collection data")
		return
	}

	logger.Info("Clearing collection data for fresh start")

	// Clear the main update tracker and all type-specific trackers
	updateKeys := []string{KeyLastUpdate}
	for _, iocType := range []string{"ip", "domain", "url", "email", "hash", "hash_md5", "hash_sha1", "hash_sha256"} {
		updateKeys = append(updateKeys, fmt.Sprintf("%s_%s", KeyLastUpdate, iocType))
	}

	for _, key := range updateKeys {
		params := custom_storage.NewDeleteObjectParamsWithContext(ctx)
		params.CollectionName = CollectionUpdateTracker
		params.ObjectKey = key

		_, err := falconClient.CustomStorage.DeleteObject(params)
		if err != nil {
			logger.Info("No update tracker data to clear", "key", key)
		} else {
			logger.Info("Cleared update tracker data", "key", key)
		}
	}
}

// checkAndRecoverMissingFiles checks for existing lookup files and handles missing file recovery
// Returns file paths (not contents) to support streaming large files
func checkAndRecoverMissingFiles(ctx context.Context, falconClient *client.CrowdStrikeAPISpecification, accessToken, repository, iocType, tempDir string, logger *slog.Logger) (bool, map[string]string, error) {
	shouldStartFresh := false
	var existingFilePaths map[string]string
	var err error

	if iocType == "" {
		// No type specified - check if any Anomali files exist
		logger.Info("No type filter specified - checking for any existing Anomali lookup files")
		existingFilePaths, err = downloadExistingLookupFiles(ctx, accessToken, repository, "", tempDir, logger)
		if err != nil {
			return false, nil, err
		}

		if len(existingFilePaths) == 0 {
			logger.Info("No existing Anomali lookup files found - starting completely fresh")
			shouldStartFresh = true
		} else {
			logger.Info("Found existing Anomali lookup files", "count", len(existingFilePaths))

			// Check for missing specific type files and clear their update_ids
			expectedFiles := make([]string, 0)
			for iocTypeKey := range iocTypeMappings {
				expectedFiles = append(expectedFiles, fmt.Sprintf("anomali_threatstream_%s.csv", iocTypeKey))
			}

			var missingFiles []string
			for _, f := range expectedFiles {
				if _, exists := existingFilePaths[f]; !exists {
					missingFiles = append(missingFiles, f)
				}
			}

			if len(missingFiles) > 0 {
				logger.Info("Detected missing files - clearing update_ids for these types", "missing", missingFiles)

				for _, missingFile := range missingFiles {
					// Extract type from filename
					filenameBase := strings.TrimPrefix(missingFile, "anomali_threatstream_")
					filenameBase = strings.TrimSuffix(filenameBase, ".csv")

					// Map filename back to collection key
					collectionType := filenameBase
					if strings.HasPrefix(filenameBase, "hash_") {
						collectionType = "hash"
					}

					_ = clearUpdateIDForType(ctx, falconClient, collectionType, logger)
				}

				// Also clear the main last_update key
				logger.Info("Clearing main last_update key to ensure fresh start for missing file types")
				deleteParams := custom_storage.NewDeleteObjectParamsWithContext(ctx)
				deleteParams.CollectionName = CollectionUpdateTracker
				deleteParams.ObjectKey = KeyLastUpdate
				_, _ = falconClient.CustomStorage.DeleteObject(deleteParams)
			}
		}
	} else {
		// Type filter specified - download existing files for that type
		logger.Info("Checking for existing files for type", "type", iocType)
		existingFilePaths, err = downloadExistingLookupFiles(ctx, accessToken, repository, iocType, tempDir, logger)
		if err != nil {
			return false, nil, err
		}

		if len(existingFilePaths) == 0 {
			// Note: We intentionally do NOT clear the update_id here.
			// The update_id tracks API pagination progress, not file existence.
			// Clearing it would cause us to re-fetch all data from the beginning,
			// resulting in file size regression (shrinking instead of growing).
			// If files don't exist, new ones will be created with fresh data.
			logger.Info("No existing files found for type - will create new file", "type", iocType)
		} else {
			logger.Info("Found existing files for type - will merge with existing data", "type", iocType)
		}
	}

	return shouldStartFresh, existingFilePaths, nil
}

// downloadExistingLookupFiles downloads existing lookup files from NGSIEM to temp files
// Returns a map of filename -> temp file path (to avoid loading large files into memory)
func downloadExistingLookupFiles(ctx context.Context, accessToken, repository, iocType string, tempDir string, logger *slog.Logger) (map[string]string, error) {
	if isTestMode() {
		return downloadExistingLookupFilesLocally(repository, iocType, logger)
	}

	existingFilePaths := make(map[string]string)

	knownFilenames := []string{
		"anomali_threatstream_ip.csv",
		"anomali_threatstream_domain.csv",
		"anomali_threatstream_url.csv",
		"anomali_threatstream_email.csv",
		"anomali_threatstream_hash_md5.csv",
		"anomali_threatstream_hash_sha1.csv",
		"anomali_threatstream_hash_sha256.csv",
	}

	// Filter by type if specified
	if iocType != "" {
		typeFilter := iocType
		switch iocType {
		case "md5":
			typeFilter = "hash_md5"
		case "sha1":
			typeFilter = "hash_sha1"
		case "sha256":
			typeFilter = "hash_sha256"
		case "hash":
			// Download all hash types
			filtered := []string{}
			for _, f := range knownFilenames {
				if strings.Contains(f, "hash_") {
					filtered = append(filtered, f)
				}
			}
			knownFilenames = filtered
			typeFilter = ""
		}
		if typeFilter != "" {
			filtered := []string{}
			for _, f := range knownFilenames {
				if strings.Contains(f, typeFilter) {
					filtered = append(filtered, f)
				}
			}
			knownFilenames = filtered
		}
	}

	logger.Info("Attempting to download existing lookup files", "count", len(knownFilenames))

	// Get the API host from cloud configuration
	opts := fdk.FalconClientOpts()
	apiHost := falcon.Cloud(opts.Cloud).Host()

	// Create HTTP client for direct API calls
	// Use 10-minute timeout: 200MB at 350KB/s = 9.5 minutes (worst case)
	httpClient := &http.Client{
		Timeout: 10 * time.Minute,
	}

	// Track files that existed but failed to download (to prevent data loss)
	failedDownloads := []string{}
	// Increase retries to 5 for large files that may fail with network issues
	// Backoff: 5s, 10s, 20s, 40s, 60s (capped) - total wait up to 135s between attempts
	const maxRetries = 5

	for _, filename := range knownFilenames {
		// Build the URL for the lookup file endpoint
		fileURL := fmt.Sprintf("https://%s/humio/api/v1/repositories/%s/files/%s",
			apiHost,
			url.PathEscape(repository),
			url.PathEscape(filename))

		logger.Debug("Downloading lookup file", "filename", filename, "url", fileURL)

		// Retry logic: try up to 5 times for transient network errors
		// Note: We use GET directly instead of HEAD because NGSIEM returns 405 for HEAD requests
		var lastErr error
		var downloaded bool
		var fileNotFound bool

		for attempt := 1; attempt <= maxRetries; attempt++ {
			if attempt > 1 {
				// Wait before retry with exponential backoff (5s, 10s, 20s, 40s, 60s cap)
				// Longer backoffs give network infrastructure time to recover
				backoffSeconds := 5 * (1 << uint(attempt-2)) // 5, 10, 20, 40...
				if backoffSeconds > 60 {
					backoffSeconds = 60 // Cap at 60 seconds
				}
				backoff := time.Duration(backoffSeconds) * time.Second
				logger.Info("Retrying download after backoff",
					"filename", filename,
					"attempt", attempt,
					"max_attempts", maxRetries,
					"backoff_seconds", backoffSeconds)
				time.Sleep(backoff)
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
			if err != nil {
				lastErr = fmt.Errorf("failed to create request: %w", err)
				continue
			}

			req.Header.Set("Authorization", "Bearer "+accessToken)
			req.Header.Set("Accept", "application/octet-stream")

			resp, err := httpClient.Do(req)
			if err != nil {
				lastErr = fmt.Errorf("HTTP request failed: %w", err)
				logger.Warn("Download attempt failed",
					"filename", filename,
					"attempt", attempt,
					"error", err)
				continue
			}

			// Handle 404 - file doesn't exist (not an error, just means new file will be created)
			if resp.StatusCode == http.StatusNotFound {
				resp.Body.Close()
				logger.Debug("Lookup file not found (will be created)", "filename", filename)
				fileNotFound = true
				break // Exit retry loop - no need to retry for non-existent files
			}

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
				logger.Warn("Download attempt failed with HTTP error",
					"filename", filename,
					"attempt", attempt,
					"status", resp.StatusCode)
				continue
			}

			// Get expected size from Content-Length header for verification
			expectedSize := resp.ContentLength
			logger.Info("File exists, starting download",
				"filename", filename,
				"expected_size_bytes", expectedSize,
				"expected_size_mb", float64(expectedSize)/(1024*1024),
				"attempt", attempt,
				"max_attempts", maxRetries)

			// Stream file content directly to disk
			tempFilePath := filepath.Join(tempDir, "existing_"+filename)
			tempFile, err := os.Create(tempFilePath)
			if err != nil {
				resp.Body.Close()
				lastErr = fmt.Errorf("failed to create temp file: %w", err)
				continue
			}

			// Use progress reader for large files (>10MB) to track download progress
			// This helps diagnose "unexpected EOF" issues by showing where downloads stall
			var reader io.Reader = resp.Body
			if expectedSize > 10*1024*1024 {
				reader = newProgressReader(resp.Body, expectedSize, filename, logger)
			}

			// Use buffered copy to stream efficiently
			bytesWritten, err := io.Copy(tempFile, reader)
			resp.Body.Close()
			tempFile.Close()

			if err != nil {
				os.Remove(tempFilePath)
				percentComplete := float64(0)
				if expectedSize > 0 {
					percentComplete = float64(bytesWritten) / float64(expectedSize) * 100
				}
				lastErr = fmt.Errorf("stream failed after %d bytes (%.1f%%): %w", bytesWritten, percentComplete, err)
				logger.Warn("Download stream failed",
					"filename", filename,
					"attempt", attempt,
					"bytes_written", bytesWritten,
					"expected_bytes", expectedSize,
					"percent_complete", fmt.Sprintf("%.1f%%", percentComplete),
					"error", err)
				continue
			}

			// Verify downloaded size matches expected size (if known)
			if expectedSize > 0 && bytesWritten != expectedSize {
				os.Remove(tempFilePath)
				lastErr = fmt.Errorf("size mismatch: got %d bytes, expected %d bytes", bytesWritten, expectedSize)
				logger.Warn("Download size mismatch",
					"filename", filename,
					"attempt", attempt,
					"bytes_written", bytesWritten,
					"expected_bytes", expectedSize)
				continue
			}

			// Success!
			existingFilePaths[filename] = tempFilePath
			logger.Info("Downloaded existing lookup file to disk",
				"filename", filename,
				"temp_path", tempFilePath,
				"size_bytes", bytesWritten,
				"size_mb", float64(bytesWritten)/(1024*1024),
				"attempts", attempt)
			downloaded = true
			break
		}

		// Skip files that don't exist - no data loss risk
		if fileNotFound {
			continue
		}

		// File existed but all retries failed - this is a data loss risk
		if !downloaded {
			logger.Error("Failed to download existing lookup file after all retries",
				"filename", filename,
				"max_retries", maxRetries,
				"error", lastErr)
			failedDownloads = append(failedDownloads, filename)
		}
	}

	// If any existing files failed to download, abort to prevent data loss
	if len(failedDownloads) > 0 {
		return nil, fmt.Errorf("download failed for %d existing file(s) after %d retries each: %v - aborting to prevent data loss",
			len(failedDownloads), maxRetries, failedDownloads)
	}

	return existingFilePaths, nil
}

// downloadExistingLookupFilesLocally returns paths to existing lookup files from local test directory
// Returns a map of filename -> file path (consistent with downloadExistingLookupFiles)
func downloadExistingLookupFilesLocally(repository, iocType string, logger *slog.Logger) (map[string]string, error) {
	existingFilePaths := make(map[string]string)

	testDir := filepath.Join(".", "test_output", repository)
	logger.Info("TEST MODE: Checking for existing lookup files", "dir", testDir)

	knownFilenames := []string{
		"anomali_threatstream_ip.csv",
		"anomali_threatstream_domain.csv",
		"anomali_threatstream_url.csv",
		"anomali_threatstream_email.csv",
		"anomali_threatstream_hash_md5.csv",
		"anomali_threatstream_hash_sha1.csv",
		"anomali_threatstream_hash_sha256.csv",
	}

	// Filter by type if specified
	if iocType != "" {
		typeFilter := iocType
		switch iocType {
		case "md5":
			typeFilter = "hash_md5"
		case "sha1":
			typeFilter = "hash_sha1"
		case "sha256":
			typeFilter = "hash_sha256"
		case "hash":
			filtered := []string{}
			for _, f := range knownFilenames {
				if strings.Contains(f, "hash_") {
					filtered = append(filtered, f)
				}
			}
			knownFilenames = filtered
			typeFilter = ""
		}
		if typeFilter != "" {
			filtered := []string{}
			for _, f := range knownFilenames {
				if strings.Contains(f, typeFilter) {
					filtered = append(filtered, f)
				}
			}
			knownFilenames = filtered
		}
	}

	for _, filename := range knownFilenames {
		filePath := filepath.Join(testDir, filename)
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				logger.Info("TEST MODE: File not found (expected for new files)", "filename", filename)
			} else {
				logger.Warn("TEST MODE: Error checking file", "filename", filename, "error", err)
			}
			continue
		}
		existingFilePaths[filename] = filePath
		logger.Info("TEST MODE: Found existing lookup file", "filename", filename, "size_bytes", fileInfo.Size())
	}

	return existingFilePaths, nil
}

// fetchIOCsFromAnomali fetches IOCs from the Anomali ThreatStream API via API Integration
func fetchIOCsFromAnomali(ctx context.Context, falconClient *client.CrowdStrikeAPISpecification, r fdk.RequestOf[IngestRequest], job *IngestJob, logger *slog.Logger) ([]IOC, map[string]interface{}, error) {
	req := r.Body
	maxRetries := 5

	// Build query parameters using shared function
	queryParams := buildQueryParams(req, job, req.Next)

	// API Integration name from manifest.yml (use name, not ID)
	apiIntegrationName := "Anomali API"
	operationID := "Intelligence"

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Check for context cancellation before each attempt
		select {
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("context cancelled: %w", ctx.Err())
		default:
		}

		logger.Info("Calling Anomali API", "attempt", attempt+1, "params", queryParams)

		// Use ExecuteCommandProxy to call the API integration
		response, err := falconClient.APIIntegrations.ExecuteCommandProxy(&api_integrations.ExecuteCommandProxyParams{
			Body: &models.DomainExecuteCommandRequestV1{
				Resources: []*models.DomainExecuteCommandV1{
					{
						DefinitionID: &apiIntegrationName,
						OperationID:  &operationID,
						Request: &models.DomainRequest{
							Params: &models.DomainParams{
								Query: queryParams,
							},
						},
					},
				},
			},
			Context: ctx,
		})
		if err != nil {
			// Log the error details for debugging
			logger.Info("API call returned error", "error_type", fmt.Sprintf("%T", err), "error", err.Error())

			// Check for API errors that might contain valid response data
			if apiErr, ok := err.(*runtime.APIError); ok {
				logger.Info("API error details", "code", apiErr.Code, "operation", apiErr.OperationName, "response_type", fmt.Sprintf("%T", apiErr.Response))

				// Handle 207 Multi-Status - this is a valid response in the Falcon API
				// The gofalcon SDK treats non-2xx as errors, but 207 contains valid data
				if apiErr.Code == 207 {
					logger.Info("Received 207 Multi-Status response, parsing response body")
					// Extract IOCs from the 207 response
					iocs, meta, parseErr := parse207Response(apiErr, logger)
					if parseErr != nil {
						// 207 parsing failed - this is not retryable, just return empty result
						// The API returned a valid 207 but with unexpected format
						logger.Warn("Failed to parse 207 response, returning empty result", "error", parseErr)
						return []IOC{}, map[string]interface{}{}, nil
					}
					// Successfully parsed 207 - check for embedded errors
					{
						// Check for embedded 429 rate limit errors
						if meta != nil {
							if errors, ok := meta["errors"].([]interface{}); ok {
								for _, errItem := range errors {
									if errMap, ok := errItem.(map[string]interface{}); ok {
										if code, ok := errMap["code"].(float64); ok && int(code) == http.StatusTooManyRequests {
											if attempt < maxRetries {
												backoffBase := 5 * (1 << uint(attempt))
												retryAfter := float64(backoffBase) + rand.Float64()*2
												logger.Warn("Rate limited (207 Multi-Status), retrying", "retry_after", retryAfter)
												select {
												case <-ctx.Done():
													return nil, nil, fmt.Errorf("context cancelled during 207 retry backoff: %w", ctx.Err())
												case <-time.After(time.Duration(retryAfter * float64(time.Second))):
												}
												continue
											}
											return nil, nil, fmt.Errorf("rate limit exceeded (207 Multi-Status) after %d retries", maxRetries)
										}
									}
								}
							}
						}
						// Successfully parsed 207 response with IOC data
						return iocs, meta, nil
					}
				}

				// Check for rate limiting (429) errors - use exponential backoff
				if apiErr.Code == http.StatusTooManyRequests {
					if attempt < maxRetries {
						backoffBase := 5 * (1 << uint(attempt))
						retryAfter := float64(backoffBase) + rand.Float64()*2
						logger.Warn("Rate limited, retrying", "error", err, "retry_after", retryAfter, "attempt", attempt+1)
						select {
						case <-ctx.Done():
							return nil, nil, fmt.Errorf("context cancelled during retry backoff: %w", ctx.Err())
						case <-time.After(time.Duration(retryAfter * float64(time.Second))):
						}
						continue
					}
					return nil, nil, fmt.Errorf("rate limit exceeded after %d retries: %w", maxRetries, err)
				}
			}

			// For other errors, retry with backoff
			if attempt < maxRetries {
				backoffBase := 5 * (1 << uint(attempt))
				retryAfter := float64(backoffBase) + rand.Float64()*2
				logger.Warn("API call failed, retrying", "error", err, "retry_after", retryAfter)
				select {
				case <-ctx.Done():
					return nil, nil, fmt.Errorf("context cancelled during retry backoff: %w", ctx.Err())
				case <-time.After(time.Duration(retryAfter * float64(time.Second))):
				}
				continue
			}
			return nil, nil, fmt.Errorf("API call failed after %d retries: %w", maxRetries, err)
		}

		// Parse response - ExecuteCommandProxy returns the API response directly
		if response.Payload == nil {
			return []IOC{}, map[string]interface{}{}, nil
		}

		// Check for 207 Multi-Status with embedded 429 errors
		if m, ok := response.Payload.(map[string]interface{}); ok {
			if errors, ok := m["errors"].([]interface{}); ok {
				for _, errItem := range errors {
					if errMap, ok := errItem.(map[string]interface{}); ok {
						if code, ok := errMap["code"].(float64); ok && int(code) == http.StatusTooManyRequests {
							if attempt < maxRetries {
								backoffBase := 5 * (1 << uint(attempt))
								retryAfter := float64(backoffBase) + rand.Float64()*2
								logger.Warn("Rate limited (207 Multi-Status), retrying", "retry_after", retryAfter)
								// Context-aware sleep - allows cancellation during backoff
								select {
								case <-ctx.Done():
									return nil, nil, fmt.Errorf("context cancelled during 207 retry backoff: %w", ctx.Err())
								case <-time.After(time.Duration(retryAfter * float64(time.Second))):
								}
								continue
							}
							return nil, nil, fmt.Errorf("rate limit exceeded (207 Multi-Status) after %d retries", maxRetries)
						}
					}
				}
			}
		}

		// Extract IOCs from proxied response
		var iocs []IOC
		meta := make(map[string]interface{})

		if m, ok := response.Payload.(map[string]interface{}); ok {
			// Extract objects array directly from response body
			if objects, ok := m["objects"]; ok {
				if objArray, ok := objects.([]interface{}); ok {
					for _, obj := range objArray {
						if objMap, ok := obj.(map[string]interface{}); ok {
							ioc := mapToIOC(objMap)
							iocs = append(iocs, ioc)
						}
					}
				}
			}
			// Extract meta
			if metaData, ok := m["meta"]; ok {
				if metaMap, ok := metaData.(map[string]interface{}); ok {
					meta = metaMap
				}
			}
		}

		logger.Info("Fetched IOCs from Anomali", "count", len(iocs))
		return iocs, meta, nil
	}

	return nil, nil, fmt.Errorf("max retries exceeded")
}

// parse207Response extracts IOC data from a 207 Multi-Status API error response
// The gofalcon SDK treats 207 as an error, but it often contains valid IOC data
func parse207Response(apiErr *runtime.APIError, logger *slog.Logger) ([]IOC, map[string]interface{}, error) {
	// The API error response should contain the actual response body
	// Try to extract it from the error's response field
	if apiErr.Response == nil {
		logger.Info("207 response body is nil")
		return nil, nil, fmt.Errorf("207 response has no body")
	}

	logger.Info("Parsing 207 response", "response_type", fmt.Sprintf("%T", apiErr.Response))

	// Handle different response types - the go-openapi runtime can return various types
	var bodyBytes []byte
	var err error

	switch resp := apiErr.Response.(type) {
	case io.Reader:
		logger.Info("Response is io.Reader")
		bodyBytes, err = io.ReadAll(resp)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read 207 response body: %w", err)
		}
	case []byte:
		logger.Info("Response is []byte", "length", len(resp))
		bodyBytes = resp
	case string:
		logger.Info("Response is string", "length", len(resp))
		bodyBytes = []byte(resp)
	case map[string]interface{}:
		logger.Info("Response is map[string]interface{}")
		// Response is already parsed JSON - marshal it back to bytes
		bodyBytes, err = json.Marshal(resp)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal 207 response: %w", err)
		}
	default:
		// Try to convert to string as last resort
		bodyBytes = []byte(fmt.Sprintf("%v", resp))
		previewLen := len(bodyBytes)
		if previewLen > 100 {
			previewLen = 100
		}
		logger.Warn("207 response has unexpected type", "type", fmt.Sprintf("%T", resp), "value_preview", string(bodyBytes[:previewLen]))
	}

	logger.Info("Response body bytes", "length", len(bodyBytes))

	if len(bodyBytes) == 0 {
		logger.Info("207 response body is empty, returning empty result")
		return []IOC{}, map[string]interface{}{}, nil
	}

	// Parse the JSON response
	var responseData map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &responseData); err != nil {
		return nil, nil, fmt.Errorf("failed to parse 207 response JSON: %w", err)
	}

	// Extract IOCs from the response
	var iocs []IOC
	meta := make(map[string]interface{})

	// Check for resources array (Falcon API structure)
	if resources, ok := responseData["resources"].([]interface{}); ok && len(resources) > 0 {
		// Get the first resource which should contain the proxied response
		if resource, ok := resources[0].(map[string]interface{}); ok {
			// The proxied response body is in the "body" field
			if body, ok := resource["body"].(map[string]interface{}); ok {
				// Extract objects (IOCs) from body
				if objects, ok := body["objects"].([]interface{}); ok {
					for _, obj := range objects {
						if objMap, ok := obj.(map[string]interface{}); ok {
							ioc := mapToIOC(objMap)
							iocs = append(iocs, ioc)
						}
					}
				}
				// Extract meta from body
				if metaData, ok := body["meta"].(map[string]interface{}); ok {
					meta = metaData
				}
			}
		}
	}

	// Also check for direct "objects" at top level (alternative structure)
	if len(iocs) == 0 {
		if objects, ok := responseData["objects"].([]interface{}); ok {
			for _, obj := range objects {
				if objMap, ok := obj.(map[string]interface{}); ok {
					ioc := mapToIOC(objMap)
					iocs = append(iocs, ioc)
				}
			}
		}
		if metaData, ok := responseData["meta"].(map[string]interface{}); ok {
			meta = metaData
		}
	}

	// Copy errors to meta for rate limit checking
	if errors, ok := responseData["errors"]; ok {
		meta["errors"] = errors
	}

	logger.Info("Parsed 207 response", "iocs_count", len(iocs))
	return iocs, meta, nil
}

// mapToIOC converts a map to an IOC struct
func mapToIOC(m map[string]interface{}) IOC {
	ioc := IOC{}

	if v, ok := m["itype"].(string); ok {
		ioc.IType = v
	}
	if v, ok := m["ip"].(string); ok {
		ioc.IP = v
	}
	if v, ok := m["value"].(string); ok {
		ioc.Value = v
	}
	if v, ok := m["confidence"]; ok {
		ioc.Confidence = v
	}
	if v, ok := m["threat_type"].(string); ok {
		ioc.ThreatType = v
	}
	if v, ok := m["source"].(string); ok {
		ioc.Source = v
	}
	if v, ok := m["expiration_ts"].(string); ok {
		ioc.ExpirationTs = v
	}
	if v, ok := m["update_id"]; ok {
		ioc.UpdateID = v
	}

	// Handle tags array
	if tags, ok := m["tags"].([]interface{}); ok {
		for _, tag := range tags {
			if tagMap, ok := tag.(map[string]interface{}); ok {
				tagEntry := make(map[string]string)
				for k, v := range tagMap {
					if strVal, ok := v.(string); ok {
						tagEntry[k] = strVal
					}
				}
				ioc.Tags = append(ioc.Tags, tagEntry)
			}
		}
	}

	return ioc
}

// processIOCsToCSV processes IOCs into CSV files with streaming for memory efficiency
// existingFilePaths maps filename -> temp file path (or empty string if no existing file)
func processIOCsToCSV(iocs []IOC, tempDir string, existingFilePaths map[string]string, logger *slog.Logger) ([]string, ProcessStats, error) {
	stats := ProcessStats{
		TotalNewIOCs: len(iocs),
	}

	// Group IOCs by type
	iocsByType := make(map[string][]IOC)
	for _, ioc := range iocs {
		iocType := normalizeIOCType(ioc.IType)
		if iocType == "" {
			continue
		}
		iocsByType[iocType] = append(iocsByType[iocType], ioc)
	}

	logger.Info("IOCs grouped by type", "types", len(iocsByType))

	var createdFiles []string

	for iocType, typeIOCs := range iocsByType {
		mapping, ok := iocTypeMappings[iocType]
		if !ok {
			logger.Warn("Unknown IOC type, skipping", "type", iocType, "count", len(typeIOCs))
			continue
		}

		filename := fmt.Sprintf("anomali_threatstream_%s.csv", iocType)
		filePath := filepath.Join(tempDir, filename)
		primaryCol := mapping.Columns[0]

		// Build new IOC rows with deduplication (later entries win)
		newRows := make(map[string][]string)
		for _, ioc := range typeIOCs {
			primaryValue := getPrimaryValue(ioc, mapping.PrimaryField)
			if primaryValue == "" {
				continue
			}

			tags := extractTags(ioc.Tags)
			row := []string{
				primaryValue,
				toString(ioc.Confidence),
				ioc.ThreatType,
				ioc.Source,
				tags,
				ioc.ExpirationTs,
			}
			newRows[primaryValue] = row
		}

		newKeys := make(map[string]bool)
		for k := range newRows {
			newKeys[k] = true
		}

		logger.Info("Prepared new IOCs", "type", iocType, "count", len(newRows))

		// Get existing file path (if any)
		existingFilePath := existingFilePaths[filename]

		// Process with streaming CSV
		var originalCount, duplicatesUpdated, rowsWritten int

		file, err := os.Create(filePath)
		if err != nil {
			return nil, stats, fmt.Errorf("failed to create file %s: %w", filename, err)
		}

		// Use buffered writer for performance
		bufWriter := bufio.NewWriterSize(file, 1024*1024) // 1MB buffer
		writer := csv.NewWriter(bufWriter)

		// Write header
		if err := writer.Write(mapping.Columns); err != nil {
			file.Close()
			return nil, stats, fmt.Errorf("failed to write header: %w", err)
		}

		// Stream existing data from file, filtering out rows that will be replaced
		if existingFilePath != "" {
			existingFile, err := os.Open(existingFilePath)
			if err != nil {
				logger.Warn("Error opening existing file, starting fresh", "filename", filename, "error", err)
			} else {
				defer existingFile.Close()
				reader := csv.NewReader(bufio.NewReaderSize(existingFile, 1024*1024)) // 1MB read buffer

				// Read and verify header
				header, err := reader.Read()
				if err != nil {
					logger.Warn("Error reading existing file header, starting fresh", "filename", filename, "error", err)
				} else if len(header) > 0 && header[0] != primaryCol {
					logger.Warn("Existing file has incompatible columns, starting fresh",
						"filename", filename, "expected", primaryCol, "got", header[0])
				} else {
					// Batch processing for performance
					batch := make([][]string, 0, 10000)

					for {
						row, err := reader.Read()
						if err == io.EOF {
							break
						}
						if err != nil {
							logger.Warn("Error reading row, skipping", "error", err)
							continue
						}

						originalCount++
						if len(row) > 0 && !newKeys[row[0]] {
							batch = append(batch, row)
							rowsWritten++

							if len(batch) >= 10000 {
								if err := writer.WriteAll(batch); err != nil {
									file.Close()
									return nil, stats, fmt.Errorf("failed to write batch: %w", err)
								}
								batch = batch[:0]
							}
						} else {
							duplicatesUpdated++
						}
					}

					// Write remaining batch
					if len(batch) > 0 {
						if err := writer.WriteAll(batch); err != nil {
							file.Close()
							return nil, stats, fmt.Errorf("failed to write final batch: %w", err)
						}
					}

					logger.Info("Streamed existing records", "filename", filename, "count", originalCount)
				}
			}
		}

		// Write new rows
		newRowsList := make([][]string, 0, len(newRows))
		for _, row := range newRows {
			newRowsList = append(newRowsList, row)
		}
		if err := writer.WriteAll(newRowsList); err != nil {
			file.Close()
			return nil, stats, fmt.Errorf("failed to write new rows: %w", err)
		}
		rowsWritten += len(newRows)

		writer.Flush()
		if err := writer.Error(); err != nil {
			file.Close()
			return nil, stats, fmt.Errorf("csv writer error: %w", err)
		}

		if err := bufWriter.Flush(); err != nil {
			file.Close()
			return nil, stats, fmt.Errorf("buffer flush error: %w", err)
		}

		file.Close()

		// Check file size
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			return nil, stats, fmt.Errorf("failed to stat file: %w", err)
		}

		fileSize := fileInfo.Size()
		fileSizeMB := float64(fileSize) / (1024 * 1024)

		// SAFETY CHECK: If existing file was present, verify new file isn't dramatically smaller
		// This prevents data loss if something went wrong during download or processing
		if existingFilePath != "" {
			existingFileInfo, err := os.Stat(existingFilePath)
			if err == nil {
				existingSize := existingFileInfo.Size()
				// If new file is less than 10% of existing file size, something is wrong
				// (unless existing file was tiny, i.e., < 10KB)
				if existingSize > 10*1024 && fileSize < existingSize/10 {
					return nil, stats, fmt.Errorf(
						"SAFETY CHECK FAILED: new file %s (%.2f MB, %d records) is dramatically smaller than "+
							"existing file (%.2f MB). This likely indicates data loss. "+
							"Aborting to protect existing data. Check download logs for errors",
						filename, fileSizeMB, rowsWritten,
						float64(existingSize)/(1024*1024))
				}
			}
		}

		if fileSize > MaxUploadSizeBytes {
			return nil, stats, fmt.Errorf(
				"file %s (%.1f MB) exceeds the NGSIEM upload limit of 200 MB. "+
					"The file contains %d IOC records. "+
					"To reduce file size, use filters: "+
					"1) Use 'feed_id' to limit ingestion to specific threat feeds, "+
					"2) Use 'confidence_gte' to filter low-confidence IOCs (e.g., confidence_gte: 70), "+
					"3) Use 'type' parameter to ingest specific IOC types separately.",
				filename, fileSizeMB, rowsWritten)
		}

		if fileSize > WarningThresholdBytes {
			logger.Warn("File approaching upload limit",
				"filename", filename,
				"size_mb", fileSizeMB)
		}

		// Update statistics
		newUniqueAdded := len(newRows) - duplicatesUpdated
		stats.TotalDuplicatesRemoved += duplicatesUpdated

		if newUniqueAdded > 0 || (existingFilePath == "" && len(newRows) > 0) {
			stats.FilesWithNewData++
		}

		if existingFilePath != "" {
			logger.Info("Merged records",
				"filename", filename,
				"existing", originalCount,
				"new", len(newRows),
				"total", rowsWritten,
				"net_new", newUniqueAdded,
				"updated", duplicatesUpdated)
		} else {
			logger.Info("Created new file",
				"filename", filename,
				"records", rowsWritten,
				"size_mb", fileSizeMB)
		}

		createdFiles = append(createdFiles, filePath)
	}

	return createdFiles, stats, nil
}

// normalizeIOCType normalizes IOC type strings to standard types
func normalizeIOCType(itype string) string {
	switch itype {
	case "mal_ip", "c2_ip", "apt_ip":
		return "ip"
	case "mal_domain", "c2_domain", "apt_domain":
		return "domain"
	case "mal_url", "apt_url":
		return "url"
	case "apt_email", "mal_email":
		return "email"
	case "apt_md5", "mal_md5":
		return "hash_md5"
	case "apt_sha1", "mal_sha1":
		return "hash_sha1"
	case "apt_sha256", "mal_sha256":
		return "hash_sha256"
	case "ip", "domain", "url", "email", "hash_md5", "hash_sha1", "hash_sha256":
		return itype
	default:
		return ""
	}
}

// getPrimaryValue extracts the primary value from an IOC based on the field name
func getPrimaryValue(ioc IOC, field string) string {
	switch field {
	case "ip":
		return ioc.IP
	case "value":
		return ioc.Value
	default:
		return ""
	}
}

// extractTags extracts tag names from IOC tags array
func extractTags(tags []map[string]string) string {
	if len(tags) == 0 {
		return ""
	}
	var names []string
	for _, tag := range tags {
		if name, ok := tag["name"]; ok && name != "" {
			names = append(names, name)
		}
	}
	return strings.Join(names, ",")
}

// toString converts various types to string
func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// namedFile wraps an os.File to implement runtime.NamedReadCloser
type namedFile struct {
	*os.File
	name string
}

func (f *namedFile) Name() string {
	return f.name
}

// progressReader wraps an io.Reader to track and log download progress
type progressReader struct {
	reader       io.Reader
	totalBytes   int64
	readBytes    int64
	lastLogBytes int64
	filename     string
	logger       *slog.Logger
	logInterval  int64 // Log every N bytes (e.g., 10MB)
}

func newProgressReader(r io.Reader, total int64, filename string, logger *slog.Logger) *progressReader {
	return &progressReader{
		reader:      r,
		totalBytes:  total,
		filename:    filename,
		logger:      logger,
		logInterval: 10 * 1024 * 1024, // Log every 10MB
	}
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.readBytes += int64(n)

	// Log progress every 10MB
	if pr.readBytes-pr.lastLogBytes >= pr.logInterval {
		percentComplete := float64(pr.readBytes) / float64(pr.totalBytes) * 100
		pr.logger.Info("Download progress",
			"filename", pr.filename,
			"bytes_downloaded", pr.readBytes,
			"total_bytes", pr.totalBytes,
			"percent_complete", fmt.Sprintf("%.1f%%", percentComplete),
			"mb_downloaded", float64(pr.readBytes)/(1024*1024))
		pr.lastLogBytes = pr.readBytes
	}

	return n, err
}

// uploadCSVFilesToNGSIEM uploads CSV files to Falcon Next-Gen SIEM as lookup files
func uploadCSVFilesToNGSIEM(ctx context.Context, falconClient *client.CrowdStrikeAPISpecification, csvFiles []string, repository string, logger *slog.Logger) ([]map[string]interface{}, error) {
	var results []map[string]interface{}

	for _, csvFile := range csvFiles {
		filename := filepath.Base(csvFile)

		// Open the file for upload
		file, err := os.Open(csvFile)
		if err != nil {
			logger.Error("Failed to open file for upload", "filename", filename, "error", err)
			results = append(results, map[string]interface{}{
				"file":    filename,
				"status":  "error",
				"message": fmt.Sprintf("Failed to open file: %v", err),
			})
			continue
		}

		// Get file size for logging
		fileInfo, err := file.Stat()
		if err != nil {
			file.Close()
			logger.Error("Failed to stat file", "filename", filename, "error", err)
			results = append(results, map[string]interface{}{
				"file":    filename,
				"status":  "error",
				"message": fmt.Sprintf("Failed to stat file: %v", err),
			})
			continue
		}

		logger.Info("Uploading file to NGSIEM",
			"filename", filename,
			"repository", repository,
			"size_bytes", fileInfo.Size(),
			"size_mb", float64(fileInfo.Size())/(1024*1024))

		// Create named file wrapper for the upload
		namedF := &namedFile{File: file, name: filename}

		// Upload using gofalcon NGSIEM client
		response, err := falconClient.Ngsiem.UploadLookupV1(&ngsiem.UploadLookupV1Params{
			File:       namedF,
			Repository: repository,
			Context:    ctx,
		})

		// Close the file after upload attempt
		file.Close()

		if err != nil {
			logger.Error("Failed to upload file to NGSIEM", "filename", filename, "error", err)
			results = append(results, map[string]interface{}{
				"file":    filename,
				"status":  "error",
				"message": fmt.Sprintf("Upload failed: %s", err.Error()),
			})
			continue
		}

		// Log success
		logger.Info("Successfully uploaded file to NGSIEM", "filename", filename, "repository", repository)

		result := map[string]interface{}{
			"file":    filename,
			"status":  "success",
			"message": "File uploaded successfully",
		}

		// Add trace ID if available for debugging
		if response != nil && response.XCSTRACEID != "" {
			result["trace_id"] = response.XCSTRACEID
		}

		results = append(results, result)
	}

	return results, nil
}

// extractNextToken extracts the next pagination token from API response metadata
func extractNextToken(meta map[string]interface{}, iocs []IOC, logger *slog.Logger) string {
	if meta == nil || len(iocs) == 0 {
		return ""
	}

	// Check for next URL in meta
	if nextURL, ok := meta["next"].(string); ok && nextURL != "" {
		// Parse the URL to extract pagination parameters
		parsed, err := url.Parse(nextURL)
		if err != nil {
			logger.Warn("Failed to parse next URL", "url", nextURL, "error", err)
			// Fallback to last IOC's update_id
			return getLastUpdateIDFromIOCs(iocs)
		}

		query := parsed.Query()

		// Try search_after first (the actual next boundary), then update_id__gt, then from_update_id
		if searchAfter := query.Get("search_after"); searchAfter != "" {
			logger.Info("More data available - next pagination token (search_after)", "token", searchAfter)
			return searchAfter
		}
		if updateIDGt := query.Get("update_id__gt"); updateIDGt != "" {
			logger.Info("More data available - next pagination token (update_id__gt)", "token", updateIDGt)
			return updateIDGt
		}
		if fromUpdateID := query.Get("from_update_id"); fromUpdateID != "" {
			logger.Info("More data available - next pagination token (from_update_id)", "token", fromUpdateID)
			return fromUpdateID
		}

		// Fallback to last IOC's update_id
		return getLastUpdateIDFromIOCs(iocs)
	}

	return ""
}

// getLastUpdateIDFromIOCs extracts the update_id from the last IOC in the list
func getLastUpdateIDFromIOCs(iocs []IOC) string {
	if len(iocs) == 0 {
		return ""
	}
	lastIOC := iocs[len(iocs)-1]
	return toString(lastIOC.UpdateID)
}

// getLastUpdateIDWithClient retrieves the last update_id from collections using provided client
func getLastUpdateIDWithClient(ctx context.Context, storage CustomStorageClient, iocType string, logger *slog.Logger) (*LastUpdateTracker, error) {
	if isTestMode() {
		logger.Info("TEST MODE: Returning nil for last update_id")
		return nil, nil
	}

	objectKey := KeyLastUpdate
	if iocType != "" {
		objectKey = fmt.Sprintf("%s_%s", KeyLastUpdate, iocType)
	}

	logger.Info("Fetching last update_id from collections", "key", objectKey)

	buf := new(bytes.Buffer)
	params := custom_storage.NewGetObjectParamsWithContext(ctx)
	params.CollectionName = CollectionUpdateTracker
	params.ObjectKey = objectKey

	resp, err := storage.GetObject(params, buf)
	if err != nil {
		// Check if it's a 404 (not found)
		if apiErr, ok := err.(*runtime.APIError); ok && apiErr.Code == http.StatusNotFound {
			logger.Info("No previous update_id found, will fetch from beginning", "type", iocType)
			return nil, nil
		}
		return nil, err
	}

	if resp == nil {
		logger.Info("No previous update_id found, will fetch from beginning", "type", iocType)
		return nil, nil
	}

	data, err := io.ReadAll(buf)
	if err != nil {
		return nil, err
	}

	var tracker LastUpdateTracker
	if err := json.Unmarshal(data, &tracker); err != nil {
		return nil, err
	}

	logger.Info("Retrieved last update data", "type", iocType, "update_id", tracker.UpdateID)
	return &tracker, nil
}

// saveUpdateIDWithClient saves the current update_id to collections using provided client
func saveUpdateIDWithClient(ctx context.Context, storage CustomStorageClient, updateData *LastUpdateTracker, iocType string, logger *slog.Logger) error {
	if isTestMode() {
		logger.Info("TEST MODE: Mock save update_id", "type", iocType, "update_id", updateData.UpdateID)
		return nil
	}

	objectKey := KeyLastUpdate
	if iocType != "" {
		objectKey = fmt.Sprintf("%s_%s", KeyLastUpdate, iocType)
	}

	logger.Info("Saving update_id to collections", "key", objectKey, "update_id", updateData.UpdateID)

	data, err := json.Marshal(updateData)
	if err != nil {
		return err
	}

	reader := io.NopCloser(bytes.NewReader(data))
	params := custom_storage.NewPutObjectParamsWithContext(ctx)
	params.Body = reader
	params.CollectionName = CollectionUpdateTracker
	params.ObjectKey = objectKey

	resp, err := storage.PutObject(params)
	if err != nil {
		return err
	}

	if resp == nil {
		return fmt.Errorf("failed to save update_id: nil response")
	}

	logger.Info("Successfully saved update_id", "type", iocType)
	return nil
}

// createJobWithClient creates a new ingest job record using provided client
func createJobWithClient(ctx context.Context, storage CustomStorageClient, lastUpdate *LastUpdateTracker, iocType string, logger *slog.Logger) (*IngestJob, error) {
	now := time.Now().UTC()
	baseID := fmt.Sprintf("%d", now.UnixNano())[:8]
	jobID := baseID
	if iocType != "" {
		jobID = fmt.Sprintf("%s_%s", baseID, iocType)
	}

	jobParams := map[string]interface{}{
		"status":   "active",
		"order_by": "update_id",
	}

	if iocType != "" {
		jobParams["type"] = iocType
	}

	if lastUpdate != nil {
		jobParams["update_id__gt"] = lastUpdate.UpdateID
		logger.Info("Incremental sync - resuming from last update_id", "type", iocType, "update_id", lastUpdate.UpdateID)
	} else {
		jobParams["update_id__gt"] = "0"
		logger.Info("Fresh start - no previous update_id found", "type", iocType)
	}

	job := &IngestJob{
		ID:               jobID,
		CreatedTimestamp: now.Format(time.RFC3339),
		State:            JobRunning,
		IOCType:          iocType,
		Parameters:       jobParams,
	}

	if isTestMode() {
		logger.Info("TEST MODE: Created mock job", "job_id", jobID)
		return job, nil
	}

	logger.Info("Creating job", "job_id", jobID)

	data, err := json.Marshal(job)
	if err != nil {
		return nil, err
	}

	reader := io.NopCloser(bytes.NewReader(data))
	params := custom_storage.NewPutObjectParamsWithContext(ctx)
	params.Body = reader
	params.CollectionName = CollectionIngestJobs
	params.ObjectKey = jobID

	resp, err := storage.PutObject(params)
	if err != nil {
		return nil, err
	}

	if resp == nil {
		return nil, fmt.Errorf("failed to create job: nil response")
	}

	logger.Info("Successfully created job", "job_id", jobID)
	return job, nil
}

// updateJobWithClient updates job status in collections using provided client
func updateJobWithClient(ctx context.Context, storage CustomStorageClient, job *IngestJob, logger *slog.Logger) error {
	if isTestMode() {
		logger.Info("TEST MODE: Mock job update", "job_id", job.ID, "state", job.State)
		return nil
	}

	logger.Info("Updating job", "job_id", job.ID, "state", job.State)

	data, err := json.Marshal(job)
	if err != nil {
		return err
	}

	reader := io.NopCloser(bytes.NewReader(data))
	params := custom_storage.NewPutObjectParamsWithContext(ctx)
	params.Body = reader
	params.CollectionName = CollectionIngestJobs
	params.ObjectKey = job.ID

	resp, err := storage.PutObject(params)
	if err != nil {
		return err
	}

	if resp == nil {
		return fmt.Errorf("failed to update job: nil response")
	}

	logger.Info("Successfully updated job", "job_id", job.ID)
	return nil
}

// clearUpdateIDForTypeWithClient clears the update_id for a specific IOC type using provided client
func clearUpdateIDForTypeWithClient(ctx context.Context, storage CustomStorageClient, iocType string, logger *slog.Logger) error {
	if isTestMode() {
		logger.Info("TEST MODE: Mock clear update_id", "type", iocType)
		return nil
	}

	objectKey := fmt.Sprintf("%s_%s", KeyLastUpdate, iocType)
	logger.Info("Clearing update_id for type", "type", iocType, "key", objectKey)

	params := custom_storage.NewDeleteObjectParamsWithContext(ctx)
	params.CollectionName = CollectionUpdateTracker
	params.ObjectKey = objectKey

	_, err := storage.DeleteObject(params)
	if err != nil {
		// Ignore "not found" errors - expected if key doesn't exist
		if apiErr, ok := err.(*runtime.APIError); ok && apiErr.Code == http.StatusNotFound {
			logger.Info("No update_id to clear for type", "type", iocType)
			return nil
		}
		return err
	}

	logger.Info("Successfully cleared update_id for type", "type", iocType)
	return nil
}

// clearCollectionDataWithClient clears collection data when starting from scratch using provided client
func clearCollectionDataWithClient(ctx context.Context, storage CustomStorageClient, logger *slog.Logger) {
	if isTestMode() {
		logger.Info("TEST MODE: Mock clear collection data")
		return
	}

	logger.Info("Clearing collection data for fresh start")

	// Clear the main update tracker and all type-specific trackers
	updateKeys := []string{KeyLastUpdate}
	for _, iocType := range []string{"ip", "domain", "url", "email", "hash", "hash_md5", "hash_sha1", "hash_sha256"} {
		updateKeys = append(updateKeys, fmt.Sprintf("%s_%s", KeyLastUpdate, iocType))
	}

	for _, key := range updateKeys {
		params := custom_storage.NewDeleteObjectParamsWithContext(ctx)
		params.CollectionName = CollectionUpdateTracker
		params.ObjectKey = key

		_, err := storage.DeleteObject(params)
		if err != nil {
			logger.Info("No update tracker data to clear", "key", key)
		} else {
			logger.Info("Cleared update tracker data", "key", key)
		}
	}
}

// buildQueryParams builds query parameters for the Anomali API call
func buildQueryParams(req IngestRequest, job *IngestJob, nextToken string) map[string]interface{} {
	queryParams := make(map[string]interface{})

	// Set order_by for consistent pagination
	queryParams["order_by"] = "update_id"

	if req.Status != "" {
		queryParams["status"] = req.Status
	}
	// Use "type" parameter for IOC type filtering (API accepts both "type" and "itype")
	if req.Type != "" {
		queryParams["type"] = req.Type
	}
	if req.TrustedCircles != "" {
		queryParams["trustedcircles"] = req.TrustedCircles
	}
	if req.FeedID != "" {
		queryParams["feed_id"] = req.FeedID
	}
	// Use update_id__gt for pagination (cursor-based, not offset-based)
	if nextToken != "" {
		queryParams["update_id__gt"] = nextToken
	} else if job != nil {
		// Use job parameters for initial call
		if updateIDGt, ok := job.Parameters["update_id__gt"].(string); ok {
			queryParams["update_id__gt"] = updateIDGt
		} else {
			queryParams["update_id__gt"] = "0"
		}

		// Allow manual overrides for initial calls only
		if req.UpdateIDGt != "" {
			queryParams["update_id__gt"] = req.UpdateIDGt
		}
		if req.ModifiedTsGt != "" {
			queryParams["modified_ts__gt"] = req.ModifiedTsGt
		}
		if req.ModifiedTsLt != "" {
			queryParams["modified_ts__lt"] = req.ModifiedTsLt
		}
	} else {
		queryParams["update_id__gt"] = "0"

		// Allow manual overrides for initial calls only
		if req.UpdateIDGt != "" {
			queryParams["update_id__gt"] = req.UpdateIDGt
		}
		if req.ModifiedTsGt != "" {
			queryParams["modified_ts__gt"] = req.ModifiedTsGt
		}
		if req.ModifiedTsLt != "" {
			queryParams["modified_ts__lt"] = req.ModifiedTsLt
		}
	}
	if req.Limit > 0 {
		queryParams["limit"] = req.Limit
	} else {
		queryParams["limit"] = 1000
	}
	if req.ConfidenceGte != nil {
		queryParams["confidence__gte"] = *req.ConfidenceGte
	}
	if req.ConfidenceGt != nil {
		queryParams["confidence__gt"] = *req.ConfidenceGt
	}
	if req.ConfidenceLte != nil {
		queryParams["confidence__lte"] = *req.ConfidenceLte
	}
	if req.ConfidenceLt != nil {
		queryParams["confidence__lt"] = *req.ConfidenceLt
	}

	return queryParams
}
