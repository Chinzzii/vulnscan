package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Chinzzii/vulnscan/models"
	"github.com/Chinzzii/vulnscan/storage"
	"github.com/jmoiron/sqlx"
)

// ScanRequest defines the expected request structure for /scan endpoint
type ScanRequest struct {
	Repo  string   `json:"repo"`  // GitHub repository URL
	Files []string `json:"files"` // List of JSON files to process
}

// FileError tracks processing failures for individual files
type FileError struct {
	File  string `json:"file"`  // Failed file path
	Error string `json:"error"` // Error description
}

// ScanResponse defines the response structure for /scan endpoint
type ScanResponse struct {
	Success []string    `json:"success"` // List of successfully processed files
	Failed  []FileError `json:"failed"`  // List of files that failed processing
}

// ScanHandler handles incoming scan requests
func ScanHandler(w http.ResponseWriter, r *http.Request) {
	// Decode and validate request body
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Concurrency control structures
	var (
		wg      sync.WaitGroup           // Tracks active goroutines
		mu      sync.Mutex               // Protects shared data structures
		success []string                 // Track successful files
		failed  []FileError              // Track failed files
		sem     = make(chan struct{}, 3) // Semaphore for limiting concurrency
	)

	// Process each file concurrently
	for _, file := range req.Files {
		wg.Add(1)
		go func(f string) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire semaphore slot
			defer func() { <-sem }() // Release semaphore slot

			// Process file and update success/failed lists
			if err := processFile(req.Repo, f); err != nil {
				mu.Lock()
				failed = append(failed, FileError{File: f, Error: err.Error()})
				mu.Unlock()
			} else {
				mu.Lock()
				success = append(success, f)
				mu.Unlock()
			}
		}(file)
	}

	wg.Wait() // Wait for all goroutines to finish

	// Return response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ScanResponse{Success: success, Failed: failed})
}

// processFile handles individual file processing pipeline with retries
func processFile(repo, filePath string) error {
	const maxRetries = 2
	var lastErr error

	// Retry loop with maxRetries attempts
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
		}
		
		err := processFileWithRetry(repo, filePath)
		if err == nil {
			return nil
		}

		// Check for lock errors and retry
		if isLockError(err) {
			lastErr = err
			continue
		}
		return err
	}

	return fmt.Errorf("failed after %d attempts: %v", maxRetries, lastErr)
}

// processFileWithRetry handles individual file processing pipeline
func processFileWithRetry(repo, filePath string) error {
	content, err := FetchFileContent(repo, filePath)
	if err != nil {
		return fmt.Errorf("fetch failed: %v", err)
	}

	// Unmarshal JSON content
	var scanFiles []models.ScanFile
	if err := json.Unmarshal(content, &scanFiles); err != nil {
		return fmt.Errorf("invalid JSON: %v", err)
	}

	// Insert scan results into database
	return executeInTransaction(func(tx *sqlx.Tx) error {
		scanTime := time.Now().UTC()

		for _, sf := range scanFiles {
			sr := sf.ScanResults

			res, err := tx.Exec(
				"INSERT INTO scans (repo, file_path, scan_time, scan_id, timestamp) VALUES (?, ?, ?, ?, ?)",
				repo, filePath, scanTime, sr.ScanID, sr.Timestamp,
			)
			if err != nil {
				return fmt.Errorf("insert scan failed: %v", err)
			}

			scanID, err := res.LastInsertId()
			if err != nil {
				return fmt.Errorf("get scan ID failed: %v", err)
			}

			for _, vuln := range sr.Vulnerabilities {
				_, err := tx.Exec(`INSERT INTO vulnerabilities (
					scan_id, cve_id, severity, cvss, status, package_name, 
					current_version, fixed_version, description, 
					published_date, link, risk_factors
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					scanID, vuln.CVEID, vuln.Severity, vuln.CVSS, vuln.Status,
					vuln.PackageName, vuln.CurrentVersion, vuln.FixedVersion,
					vuln.Description, vuln.PublishedDate, vuln.Link, vuln.RiskFactors,
				)
				if err != nil {
					return fmt.Errorf("insert vulnerability failed: %v", err)
				}
			}
		}
		return nil
	})
}

// executeInTransaction executes a function within a database transaction
func executeInTransaction(fn func(*sqlx.Tx) error) error {
	// Start transaction
	tx, err := storage.DB.Beginx()
	if err != nil {
		return fmt.Errorf("db transaction failed: %v", err)
	}

	// Rollback transaction on panic
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()

	// Execute function within transaction
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit failed: %v", err)
	}
	return nil
}

// isLockError checks if the error is due to database lock contention
func isLockError(err error) bool {
	return strings.Contains(err.Error(), "locked") ||
		strings.Contains(err.Error(), "busy")
}

// FetchFileContent retrieves file contents from GitHub with retries
func FetchFileContent(repo, filePath string) ([]byte, error) {

	// Convert GitHub repository URL to raw content URL
	repo = strings.TrimSuffix(repo, "/")
	rawURL := strings.Replace(repo, "github.com", "raw.githubusercontent.com", 1) + "/main/" + filePath

	var body []byte
	var err error

	// Retry loop with 2 attempts
	for attempt := 0; attempt < 2; attempt++ {
		var resp *http.Response
		resp, err = http.Get(rawURL)
		if err != nil {
			time.Sleep(time.Second * time.Duration(attempt+1))
			continue
		}
		defer resp.Body.Close()

		// Check for valid response
		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("HTTP status %d", resp.StatusCode)
			time.Sleep(time.Second * time.Duration(attempt+1))
			continue
		}

		// Read response body
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			time.Sleep(time.Second * time.Duration(attempt+1))
			continue
		}
		return body, nil
	}
	return nil, fmt.Errorf("failed after 2 attempts: %v", err)
}
