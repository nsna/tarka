package tarka

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
		wantErr   string
		expect    *Provider
	}{
		{
			name: "valid config",
			input: `tarka {
				username  testuser
				password  testpass
				domain_id 123
			}`,
			shouldErr: false,
			expect: &Provider{
				Username: "testuser",
				Password: "testpass",
				DomainID: "123",
			},
		},
		{
			name: "valid config with propagation wait time",
			input: `tarka {
				username  testuser
				password  testpass
				domain_id 123
				propagation_wait_time 15s
			}`,
			shouldErr: false,
			expect: &Provider{
				Username:            "testuser",
				Password:            "testpass",
				DomainID:            "123",
				PropogationWaitTime: 15 * time.Second,
			},
		},
		{
			name: "missing username",
			input: `tarka {
				password testpass
				domain_id 123
			}`,
			shouldErr: true,
			wantErr:   "missing 'username'",
		},
		{
			name:      "unrecognized subdirective",
			input:     `tarka { foo bar }`,
			shouldErr: true,
			wantErr:   "unrecognized subdirective 'foo'",
		},
		{
			// Add required fields to prevent early exit
			name: "invalid propagation wait time",
			input: `tarka {
				username test
				password test
				domain_id 123
				propagation_wait_time 10invalid
			}`,
			shouldErr: true,
			wantErr:   "invalid duration for propagation_wait_time",
		},
		{
			// Add required fields and update wantErr
			name: "propagation wait time with extra arg",
			input: `tarka {
				username test
				password test
				domain_id 123
				propagation_wait_time 10s extra
			}`,
			shouldErr: true,
			wantErr:   "wrong argument count",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tc.input)
			p := new(Provider)

			err := p.UnmarshalCaddyfile(d)

			if tc.shouldErr {
				if err == nil {
					t.Fatal("expected an error but got none")
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("expected error to contain '%s', got: %v", tc.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("did not expect an error but got: %v", err)
				}
				if p.Username != tc.expect.Username {
					t.Errorf("expected username '%s', got '%s'", tc.expect.Username, p.Username)
				}
				if p.Password != tc.expect.Password {
					t.Errorf("expected password '%s', got '%s'", tc.expect.Password, p.Password)
				}
				if p.DomainID != tc.expect.DomainID {
					t.Errorf("expected domain_id '%s', got '%s'", tc.expect.DomainID, p.DomainID)
				}
				if p.PropogationWaitTime != tc.expect.PropogationWaitTime {
					t.Errorf("expected propagation_wait_time '%s', got '%s'", tc.expect.PropogationWaitTime, p.PropogationWaitTime)
				}
			}
		})
	}
}

func TestProvision(t *testing.T) {
	tests := []struct {
		name             string
		initialProvider  *Provider
		expectedWaitTime time.Duration
		shouldErr        bool
	}{
		{
			name:             "default propagation wait time",
			initialProvider:  &Provider{},
			expectedWaitTime: 5 * time.Second,
			shouldErr:        false,
		},
		{
			name: "user-defined propagation wait time",
			initialProvider: &Provider{
				PropogationWaitTime: 20 * time.Second,
			},
			expectedWaitTime: 20 * time.Second,
			shouldErr:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.initialProvider
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			err := p.Provision(ctx)

			if tc.shouldErr {
				if err == nil {
					t.Fatal("expected an error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("did not expect an error but got: %v", err)
				}
				if p.PropogationWaitTime != tc.expectedWaitTime {
					t.Errorf("expected PropogationWaitTime to be %v, got %v", tc.expectedWaitTime, p.PropogationWaitTime)
				}
				if p.log == nil {
					t.Error("log was not initialized")
				}
			}
		})
	}
}
