# Vulnerability Scan API

A Go service for scanning GitHub repositories for vulnerability reports and querying stored data via REST APIs.



## Features

- Scan GitHub repositories for JSON vulnerability reports
- Store vulnerability data with metadata
- Query vulnerabilities by severity level
- Concurrent file processing (up to 3 files simultaneously)
- SQLite database backend
- Docker support



## Project Structure

```
vulnscan/
├── handlers/       # API endpoint handlers
│ ├── scan.go       # Scan endpoint implementation
│ └── query.go      # Query endpoint implementation
├── models/         # Data models and database schema
│ └── models.go
├── storage/        # Database initialization and management
│ └── db.go
├── tests/          # Unit tests for handlers
│ └── query
│   └── query_handler_test.go
│ └── scan
│   └── scan_handler_test.go
├── main.go         # Application entry point
├── go.mod          # Go module dependencies
├── go.sum          # Dependency checksums
└── Dockerfile      # Containerization configuration
```



## API Endpoints

#### 1. Scan Endpoint

**POST /scan**: Scan a GitHub repository for vulnerability reports

**Example**:

Request:
```json
{
  "repo": "https://github.com/velancio/vulnerability_scans",
  "files": ["filename1.json", "filename2.json", ...]
}
```

Response:
```json
{
  "success": ["filename1.json"],
  "failed": [{"file": "filename2.json", "error": "fetch failed"}]
}
```

#### 2. Query Endpoint

**POST /query**: Query stored vulnerabilities by severity level

**Example**:

Request:
```json
{
  "filters": {
    "severity": "HIGH"
  }
}
```

Response:
```json
[
  {
    "id": "CVE-2024-1234",
    "severity": "HIGH",
    "cvss": 8.5,
    "status": "fixed",
    "package_name": "openssl",
    ...
  },
  {
    "id": "CVE-2024-8902",
    "severity": "HIGH",
    "cvss": 8.2,
    "status": "fixed",
    "package_name": "openldap",
    ...
  },
  .
  .
  .
]
```



## Prerequisites

- Go 1.16+
- SQLite3
- Git
- Docker (optional)



## Setup & Installation

1. Clone the repository:
```bash
git clone https://github.com/Chinzzii/vulnscan.git
cd vulnscan
```

2. Install dependencies:
```bash
go mod download
```

3. Build the application:
```bash
go build -o vulnscan
```



## Running the Service

#### Local Development

```bash
# Start the server
./vulnscan

# Or with CGO enabled if needed
CGO_ENABLED=1 go run main.go
```

The service will be available at ```http://localhost:8080```

#### Docker

```bash
# Build the image
docker build -t vulnscan .

# Run the container
docker run -p 8080:8080 vulnscan
```



## Testing

#### Automated Testing

```bash
# Run all tests with verbose output
go test -v ./tests/...

# Run specific test suites
go test -v ./tests/scan/scan_handler_test.go    # Scan endpoint unit tests
go test -v ./tests/query/query_handler_test.go  # Query endpoint unit tests

# Run with coverage report
go test -v -coverprofile=coverage.out ./tests/...
go tool cover -html=coverage.out -o coverage.html
```

#### Manual Test

Follow these steps to verify the service functionality:

1. Start the Service
```bash
# Using Go
go run main.go

# Or using Docker
docker run -p 8080:8080 vulnscan
```

2. Test Scan Endpoint
```bash
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{
    "repo": "https://github.com/velancio/vulnerability_scans",
    "files": ["vulnscan16.json"]
  }'
```

```bash
# Expected Response:
{
  "success": ["vulnscan16.json"],
  "failed": []
}
```

3. Test Query Endpoint
```bash
curl -X POST http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d '{
    "filters": {
      "severity": "HIGH"
    }
  }'
```

```bash
# Expected Response:
[
  {
    "id": "CVE-2024-1234",
    "severity": "HIGH",
    "cvss": 8.5,
    "status": "fixed",
    "package_name": "openssl",
    "current_version": "1.1.1t-r0",
    "fixed_version": "1.1.1u-r0",
    "description": "Buffer overflow vulnerability in OpenSSL",
    "published_date": "2024-01-15T00:00:00Z",
    "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
    "risk_factors": [
      "Remote Code Execution",
      "High CVSS Score",
      "Public Exploit Available"
    ]
  },
  {
    "id": "CVE-2024-8902",
    "severity": "HIGH",
    "cvss": 8.2,
    "status": "fixed",
    "package_name": "openldap",
    "current_version": "2.4.57",
    "fixed_version": "2.4.58",
    "description": "Authentication bypass vulnerability in OpenLDAP",
    "published_date": "2024-01-21T00:00:00Z",
    "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-8902",
    "risk_factors": [
      "Authentication Bypass",
      "High CVSS Score"
    ]
  }
]
```

## Contributing

1. Fork the repository

2. Create your feature branch (```git checkout -b feature/your-feature```)

3. Commit your changes (```git commit -am 'Add some feature'```)

4. Push to the branch (```git push origin feature/your-feature```)

5. Open a Pull Request
