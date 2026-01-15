package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/crowdstrike/gofalcon/falcon/client/custom_storage"
	"github.com/go-openapi/runtime"
)

// MockCustomStorage implements custom storage operations for testing
type MockCustomStorage struct {
	GetObjectFunc    func(params *custom_storage.GetObjectParams, writer io.Writer) (*custom_storage.GetObjectOK, error)
	PutObjectFunc    func(params *custom_storage.PutObjectParams) (*custom_storage.PutObjectOK, error)
	DeleteObjectFunc func(params *custom_storage.DeleteObjectParams) (*custom_storage.DeleteObjectOK, error)

	// Track calls for assertions
	GetObjectCalls    []*custom_storage.GetObjectParams
	PutObjectCalls    []*custom_storage.PutObjectParams
	DeleteObjectCalls []*custom_storage.DeleteObjectParams
}

func (m *MockCustomStorage) GetObject(params *custom_storage.GetObjectParams, writer io.Writer, opts ...custom_storage.ClientOption) (*custom_storage.GetObjectOK, error) {
	m.GetObjectCalls = append(m.GetObjectCalls, params)
	if m.GetObjectFunc != nil {
		return m.GetObjectFunc(params, writer)
	}
	return nil, fmt.Errorf("GetObject not implemented")
}

func (m *MockCustomStorage) PutObject(params *custom_storage.PutObjectParams, opts ...custom_storage.ClientOption) (*custom_storage.PutObjectOK, error) {
	m.PutObjectCalls = append(m.PutObjectCalls, params)
	if m.PutObjectFunc != nil {
		return m.PutObjectFunc(params)
	}
	return nil, fmt.Errorf("PutObject not implemented")
}

func (m *MockCustomStorage) DeleteObject(params *custom_storage.DeleteObjectParams, opts ...custom_storage.ClientOption) (*custom_storage.DeleteObjectOK, error) {
	m.DeleteObjectCalls = append(m.DeleteObjectCalls, params)
	if m.DeleteObjectFunc != nil {
		return m.DeleteObjectFunc(params)
	}
	return nil, fmt.Errorf("DeleteObject not implemented")
}

// MockHTTPClient implements HTTP client operations for testing
type MockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)

	// Track calls for assertions
	DoCalls []*http.Request
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.DoCalls = append(m.DoCalls, req)
	if m.DoFunc != nil {
		return m.DoFunc(req)
	}
	return nil, fmt.Errorf("Do not implemented")
}

// Helper to create a mock HTTP response
func mockHTTPResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

// Helper to create a mock API error
func mockAPIError(code int, message string) *runtime.APIError {
	return &runtime.APIError{
		Code:          code,
		OperationName: "test",
	}
}

// Helper to create LastUpdateTracker JSON bytes
func marshalUpdateTracker(tracker *LastUpdateTracker) []byte {
	data, _ := json.Marshal(tracker)
	return data
}

// Helper to create IngestJob JSON bytes
func marshalJob(job *IngestJob) []byte {
	data, _ := json.Marshal(job)
	return data
}

// NewMockCustomStorage creates a new mock with default implementations
func NewMockCustomStorage() *MockCustomStorage {
	return &MockCustomStorage{
		GetObjectCalls:    make([]*custom_storage.GetObjectParams, 0),
		PutObjectCalls:    make([]*custom_storage.PutObjectParams, 0),
		DeleteObjectCalls: make([]*custom_storage.DeleteObjectParams, 0),
	}
}

// NewMockHTTPClient creates a new mock with default implementations
func NewMockHTTPClient() *MockHTTPClient {
	return &MockHTTPClient{
		DoCalls: make([]*http.Request, 0),
	}
}

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	testModeKey contextKey = "testMode"
)

// withTestMode returns a context with test mode enabled
func withTestMode(ctx context.Context) context.Context {
	return context.WithValue(ctx, testModeKey, true)
}
