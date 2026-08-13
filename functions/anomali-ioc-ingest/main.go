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

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/api_integrations"
	"github.com/crowdstrike/gofalcon/falcon/client/custom_storage"
	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"

	fdk "github.com/CrowdStrike/foundry-fn-go"
)

// Constants
const (
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
		Columns:      []string{"destination.ip", "confidence", "threat_type", "severity", "source", "tags", "expiration_ts"},
		PrimaryField: "ip",
	},
	"domain": {
		Columns:      []string{"dns.domain.name", "confidence", "threat_type", "severity", "source", "tags", "expiration_ts"},
		PrimaryField: "value",
	},
	"url": {
		Columns:      []string{"url.original", "confidence", "threat_type", "severity", "source", "tags", "expiration_ts"},
		PrimaryField: "value",
	},
	"email": {
		Columns:      []string{"email.sender.address", "confidence", "threat_type", "severity", "source", "tags", "expiration_ts"},
		PrimaryField: "value",
	},
	"hash_md5": {
		Columns:      []string{"file.hash.md5", "confidence", "threat_type", "severity", "source", "tags", "expiration_ts"},
		PrimaryField: "value",
	},
	"hash_sha1": {
		Columns:      []string{"file.hash.sha1", "confidence", "threat_type", "severity", "source", "tags", "expiration_ts"},
		PrimaryField: "value",
	},
	"hash_sha256": {
		Columns:      []string{"file.hash.sha256", "confidence", "threat_type", "severity", "source", "tags", "expiration_ts"},
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
	Severity        string `json:"severity"`
	Limit           int    `json:"limit"`
	Next            string `json:"next"`
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

// IOCMeta represents the meta object nested within an IOC response
type IOCMeta struct {
	Severity string `json:"severity"`
}

// IOC represents a single indicator of compromise from Anomali
type IOC struct {
	IType        string              `json:"itype"`
	IP           string              `json:"ip"`
	Value        string              `json:"value"`
	Confidence   interface{}         `json:"confidence"`
	ThreatType   string              `json:"threat_type"`
	Meta         IOCMeta             `json:"meta"`
	Source       string              `json:"source"`
	Tags         []map[string]string `json:"tags"`
	ExpirationTs string              `json:"expiration_ts"`
	UpdateID     interface{}         `json:"update_id"`
}

// ProcessStats tracks statistics during CSV processing
type ProcessStats struct {
	TotalNewIOCs     int `json:"total_new_iocs"`
	FilesWithNewData int `json:"files_with_new_data"`
}

// ProcessStats tracks statistics during CSV processing

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

// isRetryableError checks if an API error is transient and should be retried.
// Retryable: 429 (rate limited), 500 (internal/proxy error), 503 (service unavailable).
func isRetryableError(err error) bool {
	if apiErr, ok := err.(*runtime.APIError); ok {
		switch apiErr.Code {
		case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable:
			return true
		}
	}
	return false
}

// callWithRetry executes an API call with retry logic for transient errors.
// It retries on 429, 500, and 503 errors with exponential backoff.
func callWithRetry[T any](ctx context.Context, logger *slog.Logger, description string, maxRetries int, fn func() (T, error)) (T, error) {
	var zero T
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			backoffSeconds := 5 * (1 << uint(attempt-2))
			if backoffSeconds > 60 {
				backoffSeconds = 60
			}
			backoff := time.Duration(backoffSeconds) * time.Second
			logger.Warn("Retrying after transient error",
				"description", description,
				"attempt", attempt,
				"backoff_seconds", backoffSeconds)
			select {
			case <-ctx.Done():
				return zero, fmt.Errorf("context cancelled during retry for %s: %w", description, ctx.Err())
			case <-time.After(backoff):
			}
		}

		result, err := fn()
		if err == nil {
			return result, nil
		}

		if !isRetryableError(err) {
			return zero, err
		}

		logger.Warn("Retryable error",
			"description", description,
			"attempt", attempt,
			"max_retries", maxRetries,
			"error", err)

		if attempt == maxRetries {
			return zero, fmt.Errorf("%s failed after %d retries: %w", description, maxRetries, err)
		}
	}
	return zero, fmt.Errorf("%s failed after %d retries", description, maxRetries)
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
		"severity", req.Severity,
		"update_id_gt", req.UpdateIDGt,
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
	logger.Info("Phase 1: Checking existing lookup files...")
	shouldStartFresh, existingFiles, err := checkAndRecoverMissingFiles(ctx, falconClient, repository, req.Type, logger)
	downloadDuration := time.Since(downloadStartTime)
	if err != nil {
		logger.Error("Failed to check existing files - aborting",
			"error", err,
			"duration_seconds", downloadDuration.Seconds())
		return fdk.ErrResp(fdk.APIError{
			Code:    500,
			Message: fmt.Sprintf("Metadata check failed: %v. Please retry later.", err),
		})
	}
	logger.Info("Phase 1 complete: Existing files checked",
		"files_found", len(existingFiles),
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
		if lastUpdate != nil && req.Type != "" && len(existingFiles) == 0 && !shouldStartFresh {
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
	csvFiles, stats, err := processIOCsToCSV(iocs, tempDir, existingFiles, logger)
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
		"duration_seconds", processDuration.Seconds())

	// Upload CSV files to NGSIEM
	uploadStartTime := time.Now()
	logger.Info("Phase 4: Uploading CSV files to NGSIEM")
	uploadResults, err := uploadCSVFilesToNGSIEM(ctx, falconClient, csvFiles, repository, existingFiles, logger)
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
			"total_new_iocs":      stats.TotalNewIOCs,
			"files_with_new_data": stats.FilesWithNewData,
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

	_, err = callWithRetry(ctx, logger, fmt.Sprintf("saving update_id for %s", iocType), 5, func() (*custom_storage.PutObjectOK, error) {
		reader := io.NopCloser(bytes.NewReader(data))
		params := custom_storage.NewPutObjectParamsWithContext(ctx)
		params.Body = reader
		params.CollectionName = CollectionUpdateTracker
		params.ObjectKey = objectKey
		return falconClient.CustomStorage.PutObject(params)
	})
	if err != nil {
		return err
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
		// Use search_after as the incremental cursor. Anomali's native pagination
		// returns search_after in meta.next, and it accepts a plain update_id value.
		// Avoid update_id__gt: some ThreatStream accounts reject it with HTTP 400.
		jobParams["search_after"] = lastUpdate.UpdateID
		logger.Info("Incremental sync - resuming from last update_id", "type", iocType, "update_id", lastUpdate.UpdateID)
	} else {
		// Fresh start: omit the cursor entirely so Anomali returns from the beginning.
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

// checkAndRecoverMissingFiles checks for existing lookup files and handles missing file recovery.
// Returns a set of filenames that exist in NGSIEM.
func checkAndRecoverMissingFiles(ctx context.Context, falconClient *client.CrowdStrikeAPISpecification, repository, iocType string, logger *slog.Logger) (bool, map[string]bool, error) {
	shouldStartFresh := false
	var existingFiles map[string]bool
	var err error

	if iocType == "" {
		logger.Info("No type filter specified - checking metadata for existing Anomali lookup files")
		existingFiles, err = checkExistingFileMetadata(ctx, falconClient, repository, "", logger)
	} else {
		logger.Info("Checking metadata for existing files for type", "type", iocType)
		existingFiles, err = checkExistingFileMetadata(ctx, falconClient, repository, iocType, logger)
	}
	if err != nil {
		return false, nil, err
	}

	if iocType == "" {
		if len(existingFiles) == 0 {
			logger.Info("No existing Anomali lookup files found - starting completely fresh")
			shouldStartFresh = true
		} else {
			logger.Info("Found existing Anomali lookup files", "count", len(existingFiles))
			shouldStartFresh = checkAndClearMissingTypes(ctx, falconClient, existingFiles, logger)
		}
	} else {
		if len(existingFiles) == 0 {
			logger.Info("No existing files found for type - will create new file", "type", iocType)
		} else {
			logger.Info("Found existing files for type", "type", iocType)
		}
	}

	return shouldStartFresh, existingFiles, nil
}

// checkAndClearMissingTypes checks for missing IOC type files and clears their update_ids.
// Returns true if shouldStartFresh (currently always false from this helper).
func checkAndClearMissingTypes(ctx context.Context, falconClient *client.CrowdStrikeAPISpecification, existingFiles map[string]bool, logger *slog.Logger) bool {
	expectedFiles := make([]string, 0)
	for iocTypeKey := range iocTypeMappings {
		expectedFiles = append(expectedFiles, fmt.Sprintf("anomali_threatstream_%s.csv", iocTypeKey))
	}

	var missingFiles []string
	for _, f := range expectedFiles {
		if _, exists := existingFiles[f]; !exists {
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

			_ = clearUpdateIDForType(ctx, falconClient, collectionType, logger)
		}

		logger.Info("Clearing main last_update key to ensure fresh start for missing file types")
		deleteParams := custom_storage.NewDeleteObjectParamsWithContext(ctx)
		deleteParams.CollectionName = CollectionUpdateTracker
		deleteParams.ObjectKey = KeyLastUpdate
		_, _ = falconClient.CustomStorage.DeleteObject(deleteParams)
	}

	return false
}

// checkExistingFileMetadata checks which lookup files exist in NGSIEM without downloading.
// Returns a set of filenames that exist. Uses retry logic with 5 attempts and exponential backoff.
func checkExistingFileMetadata(ctx context.Context, falconClient *client.CrowdStrikeAPISpecification, repository, iocType string, logger *slog.Logger) (map[string]bool, error) {
	existingFiles := make(map[string]bool)

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

	logger.Info("Checking existing lookup file metadata (no download)", "count", len(knownFilenames))

	for _, filename := range knownFilenames {
		resp, err := callWithRetry(ctx, logger, fmt.Sprintf("metadata check for %s", filename), 5, func() (*ngsiem.ListLookupFilesOK, error) {
			filter := fmt.Sprintf("name:~'%s'", filename)
			params := ngsiem.NewListLookupFilesParamsWithContext(ctx)
			params.Filter = &filter
			params.SearchDomain = &repository
			return falconClient.Ngsiem.ListLookupFiles(params)
		})
		if err != nil {
			logger.Error("Failed to check file metadata after all retries",
				"filename", filename,
				"error", err)
			return nil, fmt.Errorf("metadata check failed for %s: %v", filename, err)
		}

		// Check if filename is in the response resources
		found := false
		for _, resource := range resp.Payload.Resources {
			if resource == filename {
				found = true
				break
			}
		}

		if !found {
			logger.Info("File not found (will be created)", "filename", filename)
		} else {
			existingFiles[filename] = true
			logger.Info("File exists", "filename", filename)
		}
	}

	return existingFiles, nil
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
						Config: &models.DomainConfigData{
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
					// Successfully parsed 207 - check for embedded 429 rate limit errors
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

// processIOCsToCSV processes IOCs into CSV files with streaming for memory efficiency.
// In test mode (TempPath set), merges from local disk. In production mode (ContentLen set), stream-merges from NGSIEM.
func processIOCsToCSV(iocs []IOC, tempDir string, existingFiles map[string]bool, logger *slog.Logger) ([]string, ProcessStats, error) {
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
				ioc.Meta.Severity,
				ioc.Source,
				tags,
				ioc.ExpirationTs,
			}
			newRows[primaryValue] = row
		}

		logger.Info("Prepared new IOCs", "type", iocType, "count", len(newRows))

		// Check if file already exists in NGSIEM
		fileExists := existingFiles[filename]

		if fileExists {
			logger.Info("Writing new rows for server-side dedup",
				"filename", filename,
				"new_rows", len(newRows),
				"existing_file_present", true)
		} else {
			logger.Info("Writing new rows for new file", "filename", filename, "new_rows", len(newRows))
		}

		// Always write only new rows; server-side dedup handles merging for existing files
		file, err := os.Create(filePath)
		if err != nil {
			return nil, stats, fmt.Errorf("failed to create file %s: %w", filename, err)
		}

		writer := csv.NewWriter(file)
		if err := writer.Write(mapping.Columns); err != nil {
			file.Close()
			return nil, stats, fmt.Errorf("failed to write header: %w", err)
		}

		newRowsList := make([][]string, 0, len(newRows))
		for _, row := range newRows {
			newRowsList = append(newRowsList, row)
		}
		if err := writer.WriteAll(newRowsList); err != nil {
			file.Close()
			return nil, stats, fmt.Errorf("failed to write new rows: %w", err)
		}

		writer.Flush()
		if err := writer.Error(); err != nil {
			file.Close()
			return nil, stats, fmt.Errorf("csv writer error: %w", err)
		}
		file.Close()

		rowsWritten := len(newRows)

		// Check file size
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			return nil, stats, fmt.Errorf("failed to stat file: %w", err)
		}

		fileSize := fileInfo.Size()
		fileSizeMB := float64(fileSize) / (1024 * 1024)

		// Update statistics
		if len(newRows) > 0 {
			stats.FilesWithNewData++
		}

		if fileExists {
			logger.Info("Prepared new rows for server-side update",
				"filename", filename,
				"new_rows", rowsWritten,
				"size_mb", fileSizeMB)
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
	case "apt_email", "mal_email", "compromised_email":
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

// uploadCSVFilesToNGSIEM uploads CSV files to Falcon Next-Gen SIEM as lookup files.
// When existingFiles contains a filename, uses update_lookup_file_entries() for
// server-side deduplication instead of uploading full merged files.
func uploadCSVFilesToNGSIEM(ctx context.Context, falconClient *client.CrowdStrikeAPISpecification, csvFiles []string, repository string, existingFiles map[string]bool, logger *slog.Logger) ([]map[string]interface{}, error) {
	var results []map[string]interface{}

	for _, csvFile := range csvFiles {
		filename := filepath.Base(csvFile)

		// Determine if this file has existing data on NGSIEM (server-side update path)
		if existingFiles[filename] {
			// Use UpdateLookupFileEntries API for server-side dedup
			result, err := uploadEntriesToNGSIEM(ctx, falconClient, csvFile, filename, repository, logger)
			if err != nil {
				logger.Error("Failed to update file entries in NGSIEM", "filename", filename, "error", err)
				results = append(results, map[string]interface{}{
					"file":    filename,
					"status":  "error",
					"message": fmt.Sprintf("Update entries failed: %s", err.Error()),
				})
				continue
			}
			results = append(results, result)
			continue
		}

		// New file: use UploadLookupV1 (full upload) with retry
		response, err := callWithRetry(ctx, logger, fmt.Sprintf("uploading %s", filename), 5, func() (*ngsiem.UploadLookupV1OK, error) {
			file, openErr := os.Open(csvFile)
			if openErr != nil {
				return nil, fmt.Errorf("failed to open file: %w", openErr)
			}

			fileInfo, statErr := file.Stat()
			if statErr != nil {
				file.Close()
				return nil, fmt.Errorf("failed to stat file: %w", statErr)
			}

			logger.Info("Uploading file to NGSIEM",
				"filename", filename,
				"repository", repository,
				"size_bytes", fileInfo.Size(),
				"size_mb", float64(fileInfo.Size())/(1024*1024))

			namedF := &namedFile{File: file, name: filename}
			resp, uploadErr := falconClient.Ngsiem.UploadLookupV1(&ngsiem.UploadLookupV1Params{
				File:       namedF,
				Repository: repository,
				Context:    ctx,
			})
			file.Close()
			return resp, uploadErr
		})

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

// uploadEntriesToNGSIEM uploads a CSV file using the UpdateLookupFileEntries API for server-side dedup.
// For existing files, it uses update_mode="update" with key_columns set to the primary column.
func uploadEntriesToNGSIEM(ctx context.Context, falconClient *client.CrowdStrikeAPISpecification, csvFile, filename, repository string, logger *slog.Logger) (map[string]interface{}, error) {
	// Determine primary key column from filename
	iocType := strings.TrimPrefix(strings.TrimSuffix(filename, ".csv"), "anomali_threatstream_")
	mapping, ok := iocTypeMappings[iocType]
	if !ok {
		return nil, fmt.Errorf("unknown IOC type from filename: %s", filename)
	}
	keyColumn := mapping.Columns[0]

	updateMode := "update"
	ignoreCase := "false"

	response, err := callWithRetry(ctx, logger, fmt.Sprintf("uploading %s", filename), 5, func() (*ngsiem.UpdateLookupFileEntriesOK, error) {
		file, err := os.Open(csvFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %w", err)
		}

		fileInfo, err := file.Stat()
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to stat file: %w", err)
		}

		logger.Info("Updating lookup file entries via API",
			"filename", filename,
			"repository", repository,
			"update_mode", updateMode,
			"key_columns", keyColumn,
			"size_bytes", fileInfo.Size())

		namedF := &namedFile{File: file, name: filename}

		params := &ngsiem.UpdateLookupFileEntriesParams{
			File:         namedF,
			Filename:     &filename,
			UpdateMode:   &updateMode,
			KeyColumns:   &keyColumn,
			IgnoreCase:   &ignoreCase,
			SearchDomain: &repository,
			Context:      ctx,
		}

		resp, apiErr := falconClient.Ngsiem.UpdateLookupFileEntries(params)
		file.Close()
		return resp, apiErr
	})
	if err != nil {
		return nil, err
	}

	logger.Info("Successfully updated lookup file entries",
		"filename", filename,
		"repository", repository)

	result := map[string]interface{}{
		"file":        filename,
		"status":      "success",
		"message":     "File entries updated successfully (server-side dedup)",
		"update_mode": updateMode,
	}

	if response != nil && response.XCSTRACEID != "" {
		result["trace_id"] = response.XCSTRACEID
	}

	return result, nil
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

	_, err = callWithRetry(ctx, logger, fmt.Sprintf("saving update_id for %s", iocType), 5, func() (*custom_storage.PutObjectOK, error) {
		reader := io.NopCloser(bytes.NewReader(data))
		params := custom_storage.NewPutObjectParamsWithContext(ctx)
		params.Body = reader
		params.CollectionName = CollectionUpdateTracker
		params.ObjectKey = objectKey
		return storage.PutObject(params)
	})
	if err != nil {
		return err
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
		// Use search_after as the incremental cursor. Anomali's native pagination
		// returns search_after in meta.next, and it accepts a plain update_id value.
		// Avoid update_id__gt: some ThreatStream accounts reject it with HTTP 400.
		jobParams["search_after"] = lastUpdate.UpdateID
		logger.Info("Incremental sync - resuming from last update_id", "type", iocType, "update_id", lastUpdate.UpdateID)
	} else {
		// Fresh start: omit the cursor entirely so Anomali returns from the beginning.
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
	// Use "type" parameter for IOC type filtering
	// Map hash subtypes (md5, sha1, sha256) to "hash" for the Anomali API
	if req.Type != "" {
		apiType := req.Type
		if req.Type == "md5" || req.Type == "sha1" || req.Type == "sha256" {
			apiType = "hash"
		}
		queryParams["type"] = apiType
	}
	if req.TrustedCircles != "" {
		queryParams["trustedcircles"] = req.TrustedCircles
	}
	if req.FeedID != "" {
		queryParams["feed_id"] = req.FeedID
	}
	// Use search_after for pagination. This is Anomali's native cursor (returned in
	// meta.next) and works on all accounts. update_id__gt is avoided because some
	// ThreatStream accounts reject it with HTTP 400.
	if nextToken != "" {
		queryParams["search_after"] = nextToken
	} else if job != nil {
		// Use job's stored cursor for the initial call. Support both the new
		// search_after key and the legacy update_id__gt key for in-flight jobs.
		if searchAfter, ok := job.Parameters["search_after"].(string); ok {
			queryParams["search_after"] = searchAfter
		} else if updateIDGt, ok := job.Parameters["update_id__gt"].(string); ok && updateIDGt != "0" {
			queryParams["search_after"] = updateIDGt
		}
		// Fresh start (no stored cursor): omit search_after so Anomali returns from the beginning.

		// Allow manual overrides for initial calls only
		if req.UpdateIDGt != "" {
			queryParams["search_after"] = req.UpdateIDGt
		}
		if req.ModifiedTsGt != "" {
			queryParams["modified_ts__gt"] = req.ModifiedTsGt
		}
		if req.ModifiedTsLt != "" {
			queryParams["modified_ts__lt"] = req.ModifiedTsLt
		}
	} else {
		// Fresh start: omit search_after so Anomali returns from the beginning.

		// Allow manual overrides for initial calls only
		if req.UpdateIDGt != "" {
			queryParams["search_after"] = req.UpdateIDGt
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
	if req.Severity != "" {
		queryParams["meta.severity"] = req.Severity
	}

	return queryParams
}
