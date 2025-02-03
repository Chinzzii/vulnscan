package query

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Chinzzii/vulnscan/handlers"
	"github.com/Chinzzii/vulnscan/models"
	"github.com/Chinzzii/vulnscan/storage"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
)

const repoURL = "https://github.com/velancio/vulnerability_scans"

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *sqlx.DB {
	db, err := sqlx.Open("sqlite3", "file::memory:?cache=shared&_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}

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

// TestQueryHandler tests the QueryHandler with test data in the database
func TestQueryHandler(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// First insert test data into the database
	insertTestData(t, db)

	// Test cases
	tests := []struct {
		name             string
		queryRequest     handlers.QueryRequest
		expectedCode     int
		expectedResponse []models.Vulnerability
	}{
		{
			name: "Filter high severity - exact match",
			queryRequest: handlers.QueryRequest{
				Filters: struct {
					Severity string `json:"severity"`
				}{
					Severity: "high",
				},
			},
			expectedCode: http.StatusOK,
			expectedResponse: []models.Vulnerability{
				{
					CVEID:          "CVE-2024-1234",
					Severity:       "high",
					CVSS:           8.5,
					Status:         "fixed",
					PackageName:    "openssl",
					CurrentVersion: "1.1.1t-r0",
					FixedVersion:   "1.1.1u-r0",
					Description:    "Buffer overflow vulnerability in OpenSSL",
					PublishedDate:  time.Date(2024, time.January, 15, 0, 0, 0, 0, time.UTC),
					Link:           "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
					RiskFactors:    []string{"Remote Code Execution", "High CVSS Score", "Public Exploit Available"},
				},
				{
					CVEID:          "CVE-2024-8902",
					Severity:       "high",
					CVSS:           8.2,
					Status:         "fixed",
					PackageName:    "openldap",
					CurrentVersion: "2.4.57",
					FixedVersion:   "2.4.58",
					Description:    "Authentication bypass vulnerability in OpenLDAP",
					PublishedDate:  time.Date(2024, time.January, 21, 0, 0, 0, 0, time.UTC),
					Link:           "https://nvd.nist.gov/vuln/detail/CVE-2024-8902",
					RiskFactors:    []string{"Authentication Bypass", "High CVSS Score"},
				},
			},
		},
		{
			name: "No matching severity",
			queryRequest: handlers.QueryRequest{
				Filters: struct {
					Severity string `json:"severity"`
				}{
					Severity: "extreme",
				},
			},
			expectedCode:     http.StatusOK,
			expectedResponse: []models.Vulnerability{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearDatabase(t, db)
			insertTestData(t, db)

			// Send query request
			reqBody, _ := json.Marshal(tt.queryRequest)
			req, _ := http.NewRequest("POST", "/query", bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")

			// Record HTTP response
			rr := httptest.NewRecorder()
			http.HandlerFunc(handlers.QueryHandler).ServeHTTP(rr, req)

			// Check response status code
			assert.Equal(t, tt.expectedCode, rr.Code)

			// Check response body
			var response []models.Vulnerability
			err := json.NewDecoder(rr.Body).Decode(&response)
			assert.NoError(t, err)

			if len(tt.expectedResponse) == 0 {
				assert.Empty(t, response)
				return
			}

			// Check number of vulnerabilities
			assert.Equal(t, len(tt.expectedResponse), len(response), "Number of vulnerabilities mismatch")

			// Compare each vulnerability
			for i := range tt.expectedResponse {
				expected := tt.expectedResponse[i]
				actual := response[i]

				// Normalize timestamps for comparison
				assert.True(t, expected.PublishedDate.Equal(actual.PublishedDate),
					"PublishedDate mismatch: expected %v, got %v",
					expected.PublishedDate, actual.PublishedDate)

				// Compare other fields
				assert.Equal(t, expected.CVEID, actual.CVEID)
				assert.Equal(t, expected.Severity, actual.Severity)
				assert.Equal(t, expected.CVSS, actual.CVSS)
				assert.Equal(t, expected.Status, actual.Status)
				assert.Equal(t, expected.PackageName, actual.PackageName)
				assert.Equal(t, expected.CurrentVersion, actual.CurrentVersion)
				assert.Equal(t, expected.FixedVersion, actual.FixedVersion)
				assert.Equal(t, expected.Description, actual.Description)
				assert.Equal(t, expected.Link, actual.Link)
				assert.ElementsMatch(t, expected.RiskFactors, actual.RiskFactors)
			}
		})
	}
}

// insertTestData inserts test vulnerabilities directly into the database
func insertTestData(t *testing.T, db *sqlx.DB) {
	// First insert a scan record
	scanID := "test-scan-id"
	_, err := db.Exec(`
		INSERT INTO scans (repo, file_path, scan_time, scan_id, timestamp)
		VALUES (?, ?, ?, ?, ?)
	`, repoURL, "vulnscan16.json", time.Now(), scanID, time.Now())
	assert.NoError(t, err)

	// Insert test vulnerabilities
	vulnerabilities := []models.Vulnerability{
		{
			CVEID:          "CVE-2024-1234",
			Severity:       "high",
			CVSS:           8.5,
			Status:         "fixed",
			PackageName:    "openssl",
			CurrentVersion: "1.1.1t-r0",
			FixedVersion:   "1.1.1u-r0",
			Description:    "Buffer overflow vulnerability in OpenSSL",
			PublishedDate:  time.Date(2024, time.January, 15, 0, 0, 0, 0, time.UTC),
			Link:           "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
			RiskFactors:    []string{"Remote Code Execution", "High CVSS Score", "Public Exploit Available"},
		},
		{
			CVEID:          "CVE-2024-8902",
			Severity:       "high",
			CVSS:           8.2,
			Status:         "fixed",
			PackageName:    "openldap",
			CurrentVersion: "2.4.57",
			FixedVersion:   "2.4.58",
			Description:    "Authentication bypass vulnerability in OpenLDAP",
			PublishedDate:  time.Date(2024, time.January, 21, 0, 0, 0, 0, time.UTC),
			Link:           "https://nvd.nist.gov/vuln/detail/CVE-2024-8902",
			RiskFactors:    []string{"Authentication Bypass", "High CVSS Score"},
		},
	}

	for _, vuln := range vulnerabilities {
		riskFactorsJSON, err := json.Marshal(vuln.RiskFactors)
		assert.NoError(t, err)

		_, err = db.Exec(`
			INSERT INTO vulnerabilities (
				scan_id, cve_id, severity, cvss, status, 
				package_name, current_version, fixed_version,
				description, published_date, link, risk_factors
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			scanID, vuln.CVEID, vuln.Severity, vuln.CVSS, vuln.Status,
			vuln.PackageName, vuln.CurrentVersion, vuln.FixedVersion,
			vuln.Description, vuln.PublishedDate, vuln.Link, riskFactorsJSON,
		)
		assert.NoError(t, err)
	}
}

func clearDatabase(t *testing.T, db *sqlx.DB) {
	_, err := db.Exec("DELETE FROM vulnerabilities")
	assert.NoError(t, err)
	_, err = db.Exec("DELETE FROM scans")
	assert.NoError(t, err)
}
