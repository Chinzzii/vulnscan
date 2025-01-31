package github

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func FetchFileContent(repo, filePath string) ([]byte, error) {
	rawURL := repoToRawURL(repo, filePath)
	var body []byte
	var err error

	for attempt := 0; attempt < 2; attempt++ {
		var resp *http.Response
		resp, err = http.Get(rawURL)
		if err != nil {
			time.Sleep(time.Second * time.Duration(attempt+1))
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("HTTP status %d", resp.StatusCode)
			time.Sleep(time.Second * time.Duration(attempt+1))
			continue
		}

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			time.Sleep(time.Second * time.Duration(attempt+1))
			continue
		}
		return body, nil
	}
	return nil, fmt.Errorf("failed after 2 attempts: %v", err)
}

func repoToRawURL(repo, filePath string) string {
	repo = strings.TrimSuffix(repo, "/")
	return strings.Replace(repo, "github.com", "raw.githubusercontent.com", 1) + "/main/" + filePath
}
