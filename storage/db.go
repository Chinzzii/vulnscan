package storage

import (
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

// DB is the global database connection handle
var DB *sqlx.DB

// InitDB initializes the SQLite database connection and schema
func InitDB() error {
	// Open database connection with Write-Ahead Logging for better concurrency
	db, err := sqlx.Open("sqlite3", "vulnerabilities.db?_journal=WAL")
	if err != nil {
		return err
	}

	// Create tables if they do not exist
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
		return err
	}

	DB = db
	return nil
}
