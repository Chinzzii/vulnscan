package github

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FetchFileContent retrieves file contents from GitHub with retries
func FetchFileContent(repo, filePath string) ([]byte, error) {
	rawURL := repoToRawURL(repo, filePath)
	var body []byte
	var err error

	// Retry loop with 2 attempts
	for attempt := 0; attempt < 2; attempt++ {
		var resp *http.Response
		resp, err = http.Get(rawURL)
		if err != nil {
			time.Sleep(time.Second * time.Duration(attempt+1))
			continue
		}
		defer resp.Body.Close()

		// Check for valid response
		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("HTTP status %d", resp.StatusCode)
			time.Sleep(time.Second * time.Duration(attempt+1))
			continue
		}

		// Read response body
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			time.Sleep(time.Second * time.Duration(attempt+1))
			continue
		}
		return body, nil
	}
	return nil, fmt.Errorf("failed after 2 attempts: %v", err)
}

// repoToRawURL converts GitHub repository URL to raw content URL
func repoToRawURL(repo, filePath string) string {
	repo = strings.TrimSuffix(repo, "/")
	return strings.Replace(repo, "github.com", "raw.githubusercontent.com", 1) + "/main/" + filePath
}
