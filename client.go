package tarka

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

// createRecord is a helper function to create a libdns.Record from an RR
func createRecord(name, recordType, data string, ttl time.Duration) libdns.Record {
	return libdns.RR{
		Name: name,
		Type: recordType,
		Data: data,
		TTL:  ttl,
	}
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

	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = "https://tarka.cloud/custdata"
	}

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

	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = "https://tarka.cloud/custdata"
	}

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
	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = "https://tarka.cloud/custdata"
	}

	domainID := p.DomainID
	if domainID == "" {
		domainID = "77" // Default domain ID
	}

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

	if resp.StatusCode != http.StatusOK {
		// Read response body for debugging
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("record creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
