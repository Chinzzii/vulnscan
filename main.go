package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/Chinzzii/vulnscan/handlers"
	"github.com/Chinzzii/vulnscan/storage"
)

func main() {
	// Initialize SQLite database connection
	if err := storage.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Register API endpoints
	http.HandleFunc("/scan", handlers.ScanHandler)   // Vulnerability scan API Endpoint
	http.HandleFunc("/query", handlers.QueryHandler) // Vulnerability query API Endpoint

	// Start HTTP server
	fmt.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
