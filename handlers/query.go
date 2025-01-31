package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Chinzzii/vulnscan/models"
	"github.com/Chinzzii/vulnscan/storage"
)

type QueryRequest struct {
	Filters struct {
		Severity string `json:"severity"`
	} `json:"filters"`
}

func QueryHandler(w http.ResponseWriter, r *http.Request) {
	var req QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Filters.Severity == "" {
		http.Error(w, "Severity filter is required", http.StatusBadRequest)
		return
	}

	var vulns []models.Vulnerability
	query := `SELECT 
		cve_id, severity, cvss, status, package_name, current_version, 
		fixed_version, description, published_date, link, risk_factors 
		FROM vulnerabilities WHERE severity = ?`

	if err := storage.DB.Select(&vulns, query, req.Filters.Severity); err != nil {
		http.Error(w, "Query failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vulns)
}
