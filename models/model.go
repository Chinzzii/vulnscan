package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"
)

type RiskFactors []string

func (rf *RiskFactors) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("invalid type for risk_factors")
	}
	return json.Unmarshal(bytes, rf)
}

func (rf RiskFactors) Value() (driver.Value, error) {
	return json.Marshal(rf)
}

type ScanFile struct {
	ScanResults ScanResult `json:"scanResults"`
}

type ScanResult struct {
	ScanID          string          `json:"scan_id"`
	Timestamp       time.Time       `json:"timestamp"`
	ScanStatus      string          `json:"scan_status"`
	ResourceType    string          `json:"resource_type"`
	ResourceName    string          `json:"resource_name"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	CVEID          string      `db:"cve_id" json:"id"`
	Severity       string      `db:"severity" json:"severity"`
	CVSS           float64     `db:"cvss" json:"cvss"`
	Status         string      `db:"status" json:"status"`
	PackageName    string      `db:"package_name" json:"package_name"`
	CurrentVersion string      `db:"current_version" json:"current_version"`
	FixedVersion   string      `db:"fixed_version" json:"fixed_version"`
	Description    string      `db:"description" json:"description"`
	PublishedDate  time.Time   `db:"published_date" json:"published_date"`
	Link           string      `db:"link" json:"link"`
	RiskFactors    RiskFactors `db:"risk_factors" json:"risk_factors"`
}
