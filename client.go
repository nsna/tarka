package tarka

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

var (
	errorElemRegex = regexp.MustCompile(`(?i)<i\s+id=['"]error_elem['"][^>]*>(.*?)</i>`)
	recordIDRegex  = regexp.MustCompile(`domain_rr_id=(\d+)`)
)

// baseURL returns the configured base URL or the Tarka default.
func (p *Provider) baseURL() string {
	if p.BaseURL == "" {
		return "https://tarka.cloud/custdata"
	}
	return p.BaseURL
}

// domainID returns the configured domain ID or the default zone.
func (p *Provider) domainID() string {
	if p.DomainID == "" {
		return "77"
	}
	return p.DomainID
}

// extractError pulls the Tarka error element out of an HTML body. The PHP app
// answers 200 OK with the failure embedded in the page, so status alone lies.
func extractError(body string) error {
	if m := errorElemRegex.FindStringSubmatch(body); len(m) > 1 {
		return fmt.Errorf("tarka rejected request: %s", strings.TrimSpace(strings.ReplaceAll(m[1], "\n", " ")))
	}
	return fmt.Errorf("unknown error occurred, body snippet: %s", truncate(body, 200))
}

// extractRecordID finds the row for a record in the domain listing and returns its ID.
func extractRecordID(body, name, data string) (string, error) {
	// <wbr> tags are sprinkled through long values; strip them so the text is contiguous.
	clean := strings.ReplaceAll(body, "<wbr>", "")
	clean = strings.ReplaceAll(clean, "<WBR>", "")

	for row := range strings.SplitSeq(clean, "</tr>") {
		if strings.Contains(row, name) && strings.Contains(row, "TXT") && strings.Contains(row, data) {
			if m := recordIDRegex.FindStringSubmatch(row); len(m) > 1 {
				return m[1], nil
			}
		}
	}
	return "", fmt.Errorf("record not found in domain listing")
}

func truncate(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[:n] + "..."
}

// ensureAuthenticated makes sure we have a valid session
func (p *Provider) ensureAuthenticated(ctx context.Context) error {
	if p.httpClient != nil && p.isSessionValid(ctx) {
		return nil
	}
	p.log.Info("session is invalid or uninitialized, authenticating")
	return p.login(ctx)
}

// isSessionValid checks if the current session is still valid
func (p *Provider) isSessionValid(ctx context.Context) bool {
	if p.httpClient == nil {
		return false
	}

	baseURL := p.baseURL()

	u, err := url.Parse(baseURL)
	if err != nil {
		p.log.Error("failed to parse BaseURL for session validation", zap.String("base_url", baseURL), zap.Error(err))
		return false
	}
	if len(p.httpClient.Jar.Cookies(u)) == 0 {
		return false
	}

	// Create a GET request to the customer view page
	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/customer-view.php", nil)
	if err != nil {
		// If we can't create the request, assume session is invalid
		p.log.Error("failed to create session validation request", zap.Error(err))
		return false
	}

	// Configure client to not follow redirects so we can detect them
	client := &http.Client{
		Jar:     p.httpClient.Jar, // Use the same cookie jar
		Timeout: 10 * time.Second, // Shorter timeout for validation
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects - we want to detect them
			return http.ErrUseLastResponse
		},
	}

	// Execute the request
	resp, err := client.Do(req)
	if err != nil {
		// Network error or timeout, assume session is invalid
		p.log.Error("session validation request failed", zap.Error(err))
		return false
	}
	defer resp.Body.Close()

	// Check if we got a successful response
	if resp.StatusCode == http.StatusOK {
		p.log.Info("session validation successful")
		return true
	}

	// If we got a redirect (3xx) or any other non-200 status,
	// the session is likely invalid
	p.log.Warn("session validation failed", zap.Int("status_code", resp.StatusCode))
	return false
}

// login performs the form-based authentication
func (p *Provider) login(ctx context.Context) error {
	if p.httpClient == nil {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return fmt.Errorf("failed to create cookie jar: %w", err)
		}
		p.httpClient = &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
		}
	}

	baseURL := p.baseURL()

	// Prepare login data
	loginData := url.Values{}
	loginData.Set("do_login", "1")
	loginData.Set("username", p.Username)
	loginData.Set("password", p.Password)

	// Create login request
	req, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/login.php", strings.NewReader(loginData.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute login request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "error_elem") {
		return fmt.Errorf("login failed: %v", extractError(string(body)))
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed with status: %d", resp.StatusCode)
	}

	// Check that the auth cookie was set in the jar
	u, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("failed to parse base URL: %w", err)
	}
	for _, cookie := range p.httpClient.Jar.Cookies(u) {
		if cookie.Name == "tarka_netcraft_com_au-auth-cookie-2" {
			p.log.Info("successfully authenticated and obtained session cookie")
			return nil
		}
	}

	return fmt.Errorf("no auth cookie received after login")
}

// addTXTRecord adds a TXT record using the Tarka DNS API
func (p *Provider) addTXTRecord(ctx context.Context, name, data string, ttl time.Duration) error {
	baseURL := p.baseURL()
	domainID := p.domainID()

	// The name comes from libdns as a relative name (e.g., "_acme-challenge.app.tic")
	// We need to process it for Tarka's API which expects the name without the zone suffix
	recordName := name

	// Handle root zone records
	if recordName == "@" {
		recordName = ""
	}

	// Convert TTL to seconds, default to empty string if not specified
	ttlStr := ""
	if ttl > 0 {
		ttlStr = strconv.Itoa(int(ttl.Seconds()))
	}

	// Prepare record data
	recordData := url.Values{}
	recordData.Set("domain_id", domainID)
	recordData.Set("do_change", "1")
	recordData.Set("do_add", "1")
	recordData.Set("name", recordName)
	recordData.Set("ttl", ttlStr)
	recordData.Set("rr_type_id", "8") // TXT record type
	recordData.Set("data", data)
	recordData.Set("caa_flags", "0")
	recordData.Set("caa_tag", "issue")
	recordData.Set("caa_value", "")
	recordData.Set("expires", "10 minutes") // Auto-expire for ACME challenges

	p.log.Info("Adding TXT record", zap.Any("record", recordData))

	// Create the request
	requestURL := fmt.Sprintf("%s/domain-rr-edit.php?domain_id=%s&do_add=1", baseURL, domainID)
	req, err := http.NewRequestWithContext(ctx, "POST", requestURL, strings.NewReader(recordData.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create record request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute the request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("record creation request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "error_elem") {
		return fmt.Errorf("adding record failed: %v", extractError(string(body)))
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("record creation failed with status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	return nil
}

// deleteTXTRecord looks the record up in the domain listing and deletes it by ID.
// A record that is already gone (auto-expired) is treated as success.
func (p *Provider) deleteTXTRecord(ctx context.Context, name, data string) error {
	baseURL := p.baseURL()
	domainID := p.domainID()

	if name == "@" {
		name = ""
	}

	listURL := fmt.Sprintf("%s/domain-view.php?domain_id=%s", baseURL, domainID)
	req, err := http.NewRequestWithContext(ctx, "GET", listURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create list request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch domain list: %w", err)
	}
	defer resp.Body.Close()

	listBody, _ := io.ReadAll(resp.Body)

	recordID, err := extractRecordID(string(listBody), name, data)
	if err != nil {
		p.log.Info("record not present in listing, assuming already expired",
			zap.String("name", name))
		return nil
	}

	deleteData := url.Values{}
	deleteData.Set("domain_rr_id", recordID)
	deleteData.Set("do_change", "1")
	deleteData.Set("do_delete", "on")
	deleteData.Set("name", name)
	deleteData.Set("rr_type_id", "8") // TXT record type
	deleteData.Set("data", data)

	deleteURL := fmt.Sprintf("%s/domain-rr-edit.php?domain_rr_id=%s", baseURL, recordID)
	delReq, err := http.NewRequestWithContext(ctx, "POST", deleteURL, strings.NewReader(deleteData.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create delete request: %w", err)
	}

	delReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	delReq.Header.Set("Referer", deleteURL)

	delResp, err := p.httpClient.Do(delReq)
	if err != nil {
		return fmt.Errorf("delete request failed: %w", err)
	}
	defer delResp.Body.Close()

	delBody, _ := io.ReadAll(delResp.Body)
	if strings.Contains(string(delBody), "error_elem") {
		return fmt.Errorf("delete failed: %v", extractError(string(delBody)))
	}

	if delResp.StatusCode != http.StatusOK {
		return fmt.Errorf("delete failed with status %d", delResp.StatusCode)
	}

	p.log.Info("deleted TXT record", zap.String("name", name), zap.String("record_id", recordID))
	return nil
}
