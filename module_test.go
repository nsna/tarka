package tarka

import (
	"context"
	"strings"
	"testing"

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
			name:      "missing username",
			input:     `tarka {
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
			}
		})
	}
}

func TestProvision(t *testing.T) {
	p := &Provider{}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := p.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	if p.log == nil {
		t.Error("log was not initialized")
	}
}