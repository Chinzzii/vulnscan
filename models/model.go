package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"
)

// RiskFactors represents a list of risk factors for a vulnerability
type RiskFactors []string

// Scan implements sql.Scanner interface for database read
func (rf *RiskFactors) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("invalid type for risk_factors")
	}
	return json.Unmarshal(bytes, rf)
}

// Value implements driver.Valuer interface for database write
func (rf RiskFactors) Value() (driver.Value, error) {
	return json.Marshal(rf)
}

// ScanFile represents the root JSON structure
type ScanFile struct {
	ScanResults ScanResult `json:"scanResults"` 	// Main scan data container
}


// ScanResult contains vulnerability findings and metadata
type ScanResult struct {
	ScanID          string          `json:"scan_id"` 			// Unique scan identifier
	Timestamp       time.Time       `json:"timestamp"`			// Scan execution time
	ScanStatus      string          `json:"scan_status"`		// Scan status
	ResourceType    string          `json:"resource_type"`		// Type of resource scanned
	ResourceName    string          `json:"resource_name"`		// Name of resource scanned
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`	// List of vulnerabilities found
}

// Vulnerability represents a single vulnerability finding
type Vulnerability struct {
	CVEID          string      `db:"cve_id" json:"id"`							// CVE identifier
	Severity       string      `db:"severity" json:"severity"`					// Severity level
	CVSS           float64     `db:"cvss" json:"cvss"`							// CVSS score
	Status         string      `db:"status" json:"status"`						// Status of the vulnerability
	PackageName    string      `db:"package_name" json:"package_name"`			// Affected package
	CurrentVersion string      `db:"current_version" json:"current_version"`	// Current package version
	FixedVersion   string      `db:"fixed_version" json:"fixed_version"`		// Patched version
	Description    string      `db:"description" json:"description"`			// Vulnerability description
	PublishedDate  time.Time   `db:"published_date" json:"published_date"`		// Date of publication
	Link           string      `db:"link" json:"link"`							// Reference link
	RiskFactors    RiskFactors `db:"risk_factors" json:"risk_factors"`			// Associated risk factors
}
