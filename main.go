package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/Chinzzii/vulnscan/handlers"
	"github.com/Chinzzii/vulnscan/storage"
)

func main() {
	if err := storage.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	http.HandleFunc("/scan", handlers.ScanHandler)
	http.HandleFunc("/query", handlers.QueryHandler)

	fmt.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
