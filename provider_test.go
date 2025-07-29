package tarka

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

// mockServer creates a httptest.Server to mock the Tarka API.
func mockServer() *httptest.Server {
	mux := http.NewServeMux()

	// Mock login
	mux.HandleFunc("/custdata/login.php", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "Login Page")
			return
		}
		if r.FormValue("username") == "testuser" && r.FormValue("password") == "testpass" {
			cookie := &http.Cookie{
				Name:  "tarka_netcraft_com_au-auth-cookie-2",
				Value: "test-session-cookie",
			}
			http.SetCookie(w, cookie)
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "Login successful")
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "Login failed")
		}
	})

	// Mock session validation endpoint
	mux.HandleFunc("/custdata/customer-view.php", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("tarka_netcraft_com_au-auth-cookie-2")
		if err != nil || cookie.Value != "test-session-cookie" {
			http.Redirect(w, r, "/custdata/login.php", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Customer view page")
	})

	// Mock record creation
	mux.HandleFunc("/custdata/domain-rr-edit.php", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("tarka_netcraft_com_au-auth-cookie-2")
		if err != nil || cookie.Value != "test-session-cookie" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.FormValue("do_add") == "1" && r.FormValue("rr_type_id") == "8" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "Record added")
		} else {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Bad request")
		}
	})

	return httptest.NewServer(mux)
}

func newTestProvider(serverURL string) *Provider {
	return &Provider{
		Username: "testuser",
		Password: "testpass",
		DomainID: "123",
		BaseURL:  serverURL + "/custdata",
		log:      zap.NewNop(),
	}
}

func TestProvider_AppendRecords_Success(t *testing.T) {
	server := mockServer()
	defer server.Close()

	p := newTestProvider(server.URL)

	records := []libdns.Record{
		libdns.RR{
			Type:  "TXT",
			Name:  "_acme-challenge",
			Data:  "test-token",
			TTL:   120 * time.Second,
		},
	}

	appendedRecords, err := p.AppendRecords(context.Background(), "example.com", records)
	if err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}

	if len(appendedRecords) != 1 {
		t.Fatalf("expected 1 record to be appended, got %d", len(appendedRecords))
	}

	if appendedRecords[0].RR().Data != "test-token" {
		t.Errorf("expected record data 'test-token', got '%s'", appendedRecords[0].RR().Data)
	}
}

func TestProvider_AppendRecords_AuthFailure(t *testing.T) {
	server := mockServer()
	defer server.Close()

	p := newTestProvider(server.URL)
	p.Password = "wrongpass" // Trigger auth failure

	records := []libdns.Record{
		libdns.RR{Type: "TXT", Name: "_acme-challenge", Data: "test-token"},
	}

	_, err := p.AppendRecords(context.Background(), "example.com", records)
	if err == nil {
		t.Fatal("expected AppendRecords to fail due to auth error, but it succeeded")
	}

	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("expected error to contain 'authentication failed', got: %v", err)
	}
}

func TestProvider_isSessionValid(t *testing.T) {
	server := mockServer()
	defer server.Close()

	// Test case 1: Valid session
	t.Run("valid session", func(t *testing.T) {
		p := newTestProvider(server.URL)
		err := p.login(context.Background())
		if err != nil {
			t.Fatalf("login failed: %v", err)
		}
		if !p.isSessionValid(context.Background()) {
			t.Error("expected session to be valid, but it was invalid")
		}
	})

	// Test case 2: Invalid session (bad cookie)
	t.Run("invalid session with bad cookie", func(t *testing.T) {
		p := newTestProvider(server.URL)
		jar, _ := cookiejar.New(nil)
		u, _ := url.Parse(p.BaseURL)
		jar.SetCookies(u, []*http.Cookie{{Name: "tarka_netcraft_com_au-auth-cookie-2", Value: "invalid-cookie"}})
		p.httpClient = &http.Client{Jar: jar}

		if p.isSessionValid(context.Background()) {
			t.Error("expected session to be invalid with a bad cookie, but it was valid")
		}
	})

	// Test case 3: No session (no client)
	t.Run("no session", func(t *testing.T) {
		p := newTestProvider(server.URL)
		if p.isSessionValid(context.Background()) {
			t.Error("expected session to be invalid when no client exists, but it was valid")
		}
	})
}