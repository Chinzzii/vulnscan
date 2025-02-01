package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Chinzzii/vulnscan/models"
	"github.com/Chinzzii/vulnscan/storage"
)

// QueryRequest defines the expected request structure for /query endpoint
type QueryRequest struct {
	Filters struct {
		Severity string `json:"severity"` // Severity filter value
	} `json:"filters"`
}

// QueryHandler processes the query request and returns the matching vulnerabilities
func QueryHandler(w http.ResponseWriter, r *http.Request) {
	// Decode and validate request body
	var req QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Filters.Severity == "" {
		http.Error(w, "Severity filter is required", http.StatusBadRequest)
		return
	}

	// Query the database for vulnerabilities matching the severity
	var vulns []models.Vulnerability
	query := `SELECT 
		cve_id, severity, cvss, status, package_name, current_version, 
		fixed_version, description, published_date, link, risk_factors 
		FROM vulnerabilities WHERE severity = ?`

	if err := storage.DB.Select(&vulns, query, req.Filters.Severity); err != nil {
		http.Error(w, "Query failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the list of vulnerabilities as JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vulns)
}
