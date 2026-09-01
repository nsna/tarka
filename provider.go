package tarka

import (
	"context"
	"fmt"
	"net/http"
	"time"

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

	// Delay to wait for DNS records to apply
	PropogationWaitTime time.Duration `json:"propogation_wait_time,omitempty"`

	// httpClient for making requests
	httpClient *http.Client

	// logging module via Caddy
	log *zap.Logger
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

	// The HTTP endpoint takes a short while before new records actually resolve.
	if p.PropogationWaitTime > 0 {
		p.log.Info("waiting for propagation", zap.Duration("wait", p.PropogationWaitTime))
		select {
		case <-time.After(p.PropogationWaitTime):
		case <-ctx.Done():
			return appendedRecords, ctx.Err()
		}
	}

	return appendedRecords, nil
}

// SetRecords sets DNS records in the zone. For our use case, this is the same as AppendRecords.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return p.AppendRecords(ctx, zone, records)
}

// DeleteRecords deletes DNS records from the zone.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := p.ensureAuthenticated(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	var deleted []libdns.Record

	for _, record := range records {
		rr := record.RR()

		if rr.Type != "TXT" {
			return deleted, fmt.Errorf("only TXT records are supported, got %s", rr.Type)
		}

		if err := p.deleteTXTRecord(ctx, rr.Name, rr.Data); err != nil {
			return deleted, fmt.Errorf("failed to delete record %s: %w", rr.Name, err)
		}

		deleted = append(deleted, record)
	}

	return deleted, nil
}

// Interface guards
var (
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
