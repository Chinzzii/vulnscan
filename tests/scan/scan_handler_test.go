package scan

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/Chinzzii/vulnscan/handlers"
	"github.com/Chinzzii/vulnscan/storage"
)

// Mock for FetchFileContent
type MockFile struct {
	mock.Mock
}

// FetchFileContent mocks the FetchFileContent method
func (m *MockFile) FetchFileContent(repo, filePath string) ([]byte, error) {
	args := m.Called(repo, filePath)
	return args.Get(0).([]byte), args.Error(1)
}

// setupTestDB initializes an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *sqlx.DB {
	// Using mode=memory with shared cache
	db, err := sqlx.Open("sqlite3", "file::memory:?mode=memory&cache=shared&_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(3)    // Allow multiple concurrent connections
	db.SetMaxIdleConns(3)    // Allow multiple idle connections
	db.SetConnMaxLifetime(0) // Connections will not be closed

	// Create tables
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			repo TEXT,
			file_path TEXT,
			scan_time DATETIME,
			scan_id TEXT,
			timestamp DATETIME
		);
		CREATE TABLE IF NOT EXISTS vulnerabilities (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id TEXT,
			cve_id TEXT,
			severity TEXT,
			cvss REAL,
			status TEXT,
			package_name TEXT,
			current_version TEXT,
			fixed_version TEXT,
			description TEXT,
			published_date DATETIME,
			link TEXT,
			risk_factors TEXT CHECK(json_valid(risk_factors)),
			FOREIGN KEY(scan_id) REFERENCES scans(id)
		);
	`)
	if err != nil {
		t.Fatal(err)
	}

	storage.DB = db
	return db
}

const repoURL = "https://github.com/velancio/vulnerability_scans"

// setupMock sets up the mock responses for FetchFileContent
func setupMock(mockFile *MockFile, files map[string]interface{}) {
	for file, content := range files {
		switch v := content.(type) {
		case []byte:
			mockFile.On("FetchFileContent", repoURL, file).Return(v, nil)
		case error:
			mockFile.On("FetchFileContent", repoURL, file).Return(nil, v)
		}
	}
}

// TestScanHandler tests the /scan endpoint handler
func TestScanHandler(t *testing.T) {
	// Initialize database once for all tests
	db := setupTestDB(t)
	defer db.Close()

	// Test cases
	tests := []struct {
		name         string                 // Test case name
		requestBody  handlers.ScanRequest   // Request body
		mockFiles    map[string]interface{} // Map of file content or error
		expectedCode int                    // Expected HTTP status code
		expectedBody handlers.ScanResponse  // Expected response body
	}{
		{
			name: "Scanning one valid file",
			requestBody: handlers.ScanRequest{
				Repo:  repoURL,
				Files: []string{"vulnscan16.json"},
			},
			mockFiles: map[string]interface{}{
				"vulnscan16.json": []byte(`{"scanResults":{}}`),
			},
			expectedCode: http.StatusOK,
			expectedBody: handlers.ScanResponse{
				Success: []string{"vulnscan16.json"},
				Failed:  []handlers.FileError(nil),
			},
		},
		{
			name: "Scanning less than three valid files",
			requestBody: handlers.ScanRequest{
				Repo:  repoURL,
				Files: []string{"vulnscan15.json", "vulnscan19.json"},
			},
			mockFiles: map[string]interface{}{
				"vulnscan15.json": []byte(`{"scanResults":{}}`),
				"vulnscan19.json": []byte(`{"scanResults":{}}`),
			},
			expectedCode: http.StatusOK,
			expectedBody: handlers.ScanResponse{
				Success: []string{"vulnscan15.json", "vulnscan19.json"},
				Failed:  []handlers.FileError(nil),
			},
		},
		{
			name: "Scanning more than three valid files",
			requestBody: handlers.ScanRequest{
				Repo:  repoURL,
				Files: []string{"vulnscan15.json", "vulnscan16.json", "vulnscan18.json", "vulnscan19.json"},
			},
			mockFiles: map[string]interface{}{
				"vulnscan15.json": []byte(`{"scanResults":{}}`),
				"vulnscan16.json": []byte(`{"scanResults":{}}`),
				"vulnscan18.json": []byte(`{"scanResults":{}}`),
				"vulnscan19.json": []byte(`{"scanResults":{}}`),
			},
			expectedCode: http.StatusOK,
			expectedBody: handlers.ScanResponse{
				Success: []string{"vulnscan15.json", "vulnscan16.json", "vulnscan18.json", "vulnscan19.json"},
				Failed:  []handlers.FileError(nil),
			},
		},
		{
			name: "Scanning one invalid file",
			requestBody: handlers.ScanRequest{
				Repo:  repoURL,
				Files: []string{"vulnscan17.json"},
			},
			mockFiles: map[string]interface{}{
				"vulnscan17.json": []byte(`{"scanResults":{}}`),
			},
			expectedCode: http.StatusOK,
			expectedBody: handlers.ScanResponse{
				Success: []string{},
				Failed: []handlers.FileError{
					{
						File:  "vulnscan17.json",
						Error: "fetch failed: failed after 2 attempts: HTTP status 404",
					},
				},
			},
		},
		{
			name: "Scanning less than three invalid file",
			requestBody: handlers.ScanRequest{
				Repo:  repoURL,
				Files: []string{"vulnscan17.json", "vulnscan20.json"},
			},
			mockFiles: map[string]interface{}{
				"vulnscan17.json": []byte(`{"scanResults":{}}`),
				"vulnscan20.json": []byte(`{"scanResults":{}}`),
			},
			expectedCode: http.StatusOK,
			expectedBody: handlers.ScanResponse{
				Success: []string{},
				Failed: []handlers.FileError{
					{
						File:  "vulnscan17.json",
						Error: "fetch failed: failed after 2 attempts: HTTP status 404",
					},
					{
						File:  "vulnscan20.json",
						Error: "fetch failed: failed after 2 attempts: HTTP status 404",
					},
				},
			},
		},
		{
			name: "Scanning more than three invalid file",
			requestBody: handlers.ScanRequest{
				Repo:  repoURL,
				Files: []string{"vulnscan17.json", "vulnscan20.json", "vulnscan21.json"},
			},
			mockFiles: map[string]interface{}{
				"vulnscan17.json": []byte(`{"scanResults":{}}`),
				"vulnscan20.json": []byte(`{"scanResults":{}}`),
				"vulnscan21.json": []byte(`{"scanResults":{}}`),
			},
			expectedCode: http.StatusOK,
			expectedBody: handlers.ScanResponse{
				Success: []string{},
				Failed: []handlers.FileError{
					{
						File:  "vulnscan17.json",
						Error: "fetch failed: failed after 2 attempts: HTTP status 404",
					},
					{
						File:  "vulnscan20.json",
						Error: "fetch failed: failed after 2 attempts: HTTP status 404",
					},
					{
						File:  "vulnscan21.json",
						Error: "fetch failed: failed after 2 attempts: HTTP status 404",
					},
				},
			},
		},
		{
			name: "Scanning less than three mixed files",
			requestBody: handlers.ScanRequest{
				Repo:  repoURL,
				Files: []string{"vulnscan16.json", "vulnscan17.json"},
			},
			mockFiles: map[string]interface{}{
				"vulnscan16.json": []byte(`{"scanResults":{}}`),
				"vulnscan17.json": errors.New("file not found"),
			},
			expectedCode: http.StatusOK,
			expectedBody: handlers.ScanResponse{
				Success: []string{"vulnscan16.json"},
				Failed: []handlers.FileError{
					{
						File:  "vulnscan17.json",
						Error: "fetch failed: failed after 2 attempts: HTTP status 404",
					},
				},
			},
		},
		{
			name: "Scanning more than 3 mixed files",
			requestBody: handlers.ScanRequest{
				Repo:  repoURL,
				Files: []string{"vulnscan15.json", "vulnscan16.json", "vulnscan17.json", "vulnscan18.json"},
			},
			mockFiles: map[string]interface{}{
				"vulnscan15.json": []byte(`{"scanResults":{}}`),
				"vulnscan16.json": []byte(`{"scanResults":{}}`),
				"vulnscan17.json": []byte(`{"scanResults":{}}`),
				"vulnscan18.json": []byte(`{"scanResults":{}}`),
			},
			expectedCode: http.StatusOK,
			expectedBody: handlers.ScanResponse{
				Success: []string{"vulnscan15.json", "vulnscan16.json", "vulnscan18.json"},
				Failed: []handlers.FileError{
					{
						File:  "vulnscan17.json",
						Error: "fetch failed: failed after 2 attempts: HTTP status 404",
					},
				},
			},
		},
		{
			name: "Scanning all valid files in repo",
			requestBody: handlers.ScanRequest{
				Repo: repoURL,
				Files: []string{
					"vulnscan1011.json", "vulnscan1213.json", "vulnscan15.json", "vulnscan16.json",
					"vulnscan18.json", "vulnscan19.json", "vulnscan456.json", "vulnscan789.json", "vulscan123.json",
				},
			},
			mockFiles: map[string]interface{}{
				"vulnscan1011.json": []byte(`{"scanResults":{}}`),
				"vulnscan1213.json": []byte(`{"scanResults":{}}`),
				"vulnscan15.json":   []byte(`{"scanResults":{}}`),
				"vulnscan16.json":   []byte(`{"scanResults":{}}`),
				"vulnscan18.json":   []byte(`{"scanResults":{}}`),
				"vulnscan19.json":   []byte(`{"scanResults":{}}`),
				"vulnscan456.json":  []byte(`{"scanResults":{}}`),
				"vulnscan789.json":  []byte(`{"scanResults":{}}`),
				"vulscan123.json":   []byte(`{"scanResults":{}}`),
			},
			expectedCode: http.StatusOK,
			expectedBody: handlers.ScanResponse{
				Success: []string{
					"vulnscan1011.json", "vulnscan1213.json", "vulnscan15.json", "vulnscan16.json",
					"vulnscan18.json", "vulnscan19.json", "vulnscan456.json", "vulnscan789.json", "vulscan123.json",
				},
				Failed: []handlers.FileError(nil),
			},
		},
	}

	// Run tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Create fresh mock for each test
			mockFile := new(MockFile)

			// Setup mock responses
			setupMock(mockFile, tt.mockFiles)

			// Create request body
			reqBody, _ := json.Marshal(tt.requestBody)
			req, err := http.NewRequest("POST", "/scan", bytes.NewReader(reqBody))
			assert.NoError(t, err)

			// Mock HTTP response recorder
			recorder := httptest.NewRecorder()
			http.HandlerFunc(handlers.ScanHandler).ServeHTTP(recorder, req)

			// Verify response code
			assert.Equal(t, tt.expectedCode, recorder.Code)

			// Verify response body
			if recorder.Code == http.StatusOK {
				var response handlers.ScanResponse
				json.Unmarshal(recorder.Body.Bytes(), &response)
				assert.ElementsMatch(t, tt.expectedBody.Success, response.Success)
				assert.ElementsMatch(t, tt.expectedBody.Failed, response.Failed)
			}
		})
	}
}
