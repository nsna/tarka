package tarka

import (
	"context"
	"fmt"
	"net/http"

	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

// Provider implements the libdns interfaces for Tarka DNS
type Provider struct {
	// Username for Tarka DNS login
	Username string `json:"username,omitempty"`

	// Password for Tarka DNS login
	Password string `json:"password,omitempty"`

	// DomainID is the numeric domain ID for your zone in Tarka DNS
	DomainID string `json:"domain_id,omitempty"`

	// BaseURL is the base URL for Tarka DNS (defaults to https://tarka.cloud/custdata)
	BaseURL string `json:"base_url,omitempty"`

	// httpClient for making requests
	httpClient *http.Client

	// logging module via Caddy
	log *zap.Logger
}

// GetRecords lists DNS records in the zone. This is a no-op for our use case.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	// Not implemented - return empty slice
	// If you needed to implement this, you would:
	// 1. Make API call to list records
	// 2. Convert each record to libdns.RR
	// 3. Return them wrapped as Records
	return []libdns.Record{}, nil
}

// AppendRecords adds DNS records to the zone.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := p.ensureAuthenticated(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	var appendedRecords []libdns.Record

	for _, record := range records {
		rr := record.RR()

		if rr.Type != "TXT" {
			return nil, fmt.Errorf("only TXT records are supported, got %s", rr.Type)
		}

		err := p.addTXTRecord(ctx, rr.Name, rr.Data, rr.TTL)
		if err != nil {
			return nil, fmt.Errorf("failed to add record %s: %w", rr.Name, err)
		}

		appendedRecords = append(appendedRecords, record)
	}

	return appendedRecords, nil
}

// SetRecords sets DNS records in the zone. For our use case, this is the same as AppendRecords.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return p.AppendRecords(ctx, zone, records)
}

// DeleteRecords deletes DNS records from the zone. This is a no-op since we rely on auto-expiry.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// Not implemented - rely on auto-expiry
	// Return the records as if they were deleted
	return records, nil
}

// GetZones lists all zones available. This is a no-op for our use case.
func (p *Provider) GetZones(ctx context.Context) ([]libdns.Zone, error) {
	// Not implemented - return empty slice
	return []libdns.Zone{}, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
