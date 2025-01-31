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

type ScanRequest struct {
	Repo  string   `json:"repo"`
	Files []string `json:"files"`
}

type FileError struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

type ScanResponse struct {
	Success []string    `json:"success"`
	Failed  []FileError `json:"failed"`
}

func ScanHandler(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		success []string
		failed  []FileError
		sem     = make(chan struct{}, 3)
	)

	for _, file := range req.Files {
		wg.Add(1)
		go func(f string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

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

	wg.Wait()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ScanResponse{Success: success, Failed: failed})
}

func processFile(repo, filePath string) error {
	content, err := github.FetchFileContent(repo, filePath)
	if err != nil {
		return fmt.Errorf("fetch failed: %v", err)
	}

	var scanFiles []models.ScanFile
	if err := json.Unmarshal(content, &scanFiles); err != nil {
		return fmt.Errorf("invalid JSON: %v", err)
	}

	tx, err := storage.DB.Beginx()
	if err != nil {
		return fmt.Errorf("db transaction failed: %v", err)
	}
	defer tx.Rollback()

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

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit failed: %v", err)
	}
	return nil
}
