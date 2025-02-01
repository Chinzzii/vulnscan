package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Chinzzii/vulnscan/github"
	"github.com/Chinzzii/vulnscan/models"
	"github.com/Chinzzii/vulnscan/storage"
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

// processFile handles individual file processing pipeline
func processFile(repo, filePath string) error {
	// Step 1: Fetch file content from GitHub with retries
	content, err := github.FetchFileContent(repo, filePath)
	if err != nil {
		return fmt.Errorf("fetch failed: %v", err)
	}

	// Step 2: Parse JSON content into structured data
	var scanFiles []models.ScanFile
	if err := json.Unmarshal(content, &scanFiles); err != nil {
		return fmt.Errorf("invalid JSON: %v", err)
	}

	// Step 3: Begin database transaction
	tx, err := storage.DB.Beginx()
	if err != nil {
		return fmt.Errorf("db transaction failed: %v", err)
	}
	defer tx.Rollback() // Rollback transaction if not committed

	scanTime := time.Now().UTC()

	// Step 4: Process each scan result in the file
	for _, sf := range scanFiles {
		sr := sf.ScanResults

		// Insert scan metadata
		res, err := tx.Exec(
			"INSERT INTO scans (repo, file_path, scan_time, scan_id, timestamp) VALUES (?, ?, ?, ?, ?)",
			repo, filePath, scanTime, sr.ScanID, sr.Timestamp,
		)
		if err != nil {
			return fmt.Errorf("insert scan failed: %v", err)
		}

		// Get auto-generated scan ID
		scanID, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("get scan ID failed: %v", err)
		}

		// Insert vulnerabilities
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

	// Step 5: Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit failed: %v", err)
	}
	return nil
}
