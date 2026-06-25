// push_sbom uploads a CycloneDX SBOM to Sonatype IQ SBOM Manager.
//
// Usage:
//
//	go run push_sbom.go <app_name> <app_version>
//
// Required env vars: USER_CODE, PASSCODE
// The SBOM file is expected at ./bom.cdx.json
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	pollEvery = 5 * time.Second
	maxPolls  = 24
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: push_sbom <app_name> <app_version> <sbom_filename>")
		os.Exit(1)
	}

	userCode := getEnv("USER_CODE")
	passcode := getEnv("PASSCODE")
	baseURL := getEnv("SBOM_MANAGER_BASE_URL")
	publicID := os.Args[1]
	appVersion := os.Args[2]
	sbomFilename := os.Args[3]

	sbomVersion := appVersion
	fmt.Printf("app_name=%s  sbom_version=%s\n", publicID, sbomVersion)

	client := &http.Client{Timeout: 30 * time.Second}

	appID, err := resolveAppID(client, userCode, passcode, baseURL, publicID)
	handleError(err)
	fmt.Printf("applicationId=%s\n", appID)

	handleError(keepOnlyLastSbomVersion(client, userCode, passcode, baseURL, appID, sbomVersion))

	statusURL, err := uploadSBOM(client, userCode, passcode, baseURL, appID, sbomVersion, sbomFilename)
	handleError(err)
	fmt.Printf("polling status at %s\n", statusURL)

	handleError(pollUntilDone(client, userCode, passcode, statusURL))
	fmt.Println("SBOM import completed successfully.")
}

// resolveAppID looks up the internal application ID for the given publicID.
func resolveAppID(client *http.Client, userCode, passcode, baseURL, publicID string) (string, error) {
	url := fmt.Sprintf("%s/api/v2/applications?publicId=%s", baseURL, publicID)
	body, err := get(client, userCode, passcode, url)
	if err != nil {
		return "", fmt.Errorf("resolve app ID: %w", err)
	}

	var resp struct {
		Applications []struct {
			ID string `json:"id"`
		} `json:"applications"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || len(resp.Applications) == 0 {
		return "", fmt.Errorf("resolve app ID: unexpected response: %s", body)
	}
	return resp.Applications[0].ID, nil
}

// keepOnlyLastSbomVersion deletes all existing versions of the same kind as sbomVersion
// (semver or non-semver), so that after the upload SBOM Manager holds at most one semver
// and one non-semver version.
func keepOnlyLastSbomVersion(client *http.Client, userCode, passcode, baseURL, appID, sbomVersion string) error {
	url := fmt.Sprintf("%s/api/v2/sbom/applications/%s/versions", baseURL, appID)
	body, err := get(client, userCode, passcode, url)
	if err != nil {
		return fmt.Errorf("list versions: %w", err)
	}
	fmt.Printf("existing versions: %s\n", body)

	var versionIDs []string
	if err := json.Unmarshal(body, &versionIDs); err != nil {
		return fmt.Errorf("parse versions: %w (body: %s)", err, body)
	}

	for _, id := range selectVersionsToDelete(versionIDs, sbomVersion) {
		fmt.Printf("deleting SBOM version %s\n", id)
		delURL := fmt.Sprintf("%s/api/v2/sbom/applications/%s/versions/%s", baseURL, appID, id)
		req, _ := http.NewRequest(http.MethodDelete, delURL, nil)
		req.SetBasicAuth(userCode, passcode)
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("warning: delete %s failed: %v\n", id, err)
			continue
		}
		resp.Body.Close()
		fmt.Printf("deleted %s → %s\n", id, resp.Status)
	}
	return nil
}

// selectVersionsToDelete returns all existing versions of the same kind as uploadVersion.
func selectVersionsToDelete(existing []string, uploadVersion string) []string {
	uploading := isSemver(uploadVersion)
	var toDelete []string
	for _, v := range existing {
		if isSemver(v) == uploading {
			toDelete = append(toDelete, v)
		}
	}
	return toDelete
}

func isSemver(v string) bool {
	var major, minor, patch int
	n, _ := fmt.Sscanf(v, "%d.%d.%d", &major, &minor, &patch)
	return n == 3
}

// uploadSBOM posts the SBOM file and returns the status-polling URL.
func uploadSBOM(client *http.Client, userCode, passcode, baseURL, appID, sbomVersion string, sbomFilename string) (string, error) {
	f, err := os.Open(sbomFilename)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", sbomFilename, err)
	}
	defer f.Close()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", sbomFilename)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(fw, f); err != nil {
		return "", err
	}
	_ = mw.WriteField("applicationId", appID)
	_ = mw.WriteField("applicationVersion", sbomVersion)
	mw.Close()

	url := fmt.Sprintf("%s/api/v2/sbom/import?ignoreValidationError=true", baseURL)
	req, _ := http.NewRequest(http.MethodPost, url, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.SetBasicAuth(userCode, passcode)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("upload SBOM: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("import response: %s\n", body)

	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("upload SBOM: status %s: %s", resp.Status, body)
	}

	var result struct {
		StatusURL string `json:"statusUrl"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.StatusURL == "" {
		return "", fmt.Errorf("parse import response: %s", body)
	}
	return baseURL + "/" + strings.TrimPrefix(result.StatusURL, "/"), nil
}

// pollUntilDone polls the status URL until the import finishes or times out.
func pollUntilDone(client *http.Client, userCode, passcode, statusURL string) error {
	var lastBody []byte
	for i := range maxPolls {
		time.Sleep(pollEvery)

		body, err := get(client, userCode, passcode, statusURL)
		if err != nil {
			fmt.Printf("poll %d: request error: %v\n", i+1, err)
			continue
		}
		lastBody = body
		fmt.Printf("status (attempt %d): %s\n", i+1, body)

		var status struct {
			IsError      bool   `json:"isError"`
			ErrorMessage string `json:"errorMessage"`
			DownloadURL  string `json:"downloadUrl"`
		}
		if err := json.Unmarshal(body, &status); err != nil {
			continue
		}
		if status.DownloadURL == "" {
			continue
		}
		if status.IsError {
			return fmt.Errorf("SBOM import failed: %s", status.ErrorMessage)
		}
		return nil
	}
	return fmt.Errorf("SBOM import timed out after %s (last response: %s)", time.Duration(maxPolls)*pollEvery, lastBody)
}

// get performs a GET with basic auth and returns the response body.
func get(client *http.Client, userCode, passcode, url string) ([]byte, error) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.SetBasicAuth(userCode, passcode)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s → %s: %s", url, resp.Status, body)
	}
	return body, nil
}

func getEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Fprintf(os.Stderr, "env var %s is required\n", key)
		os.Exit(1)
	}
	return v
}

func handleError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
