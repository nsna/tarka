package tarka

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

const apiEndpoint = "https://tarka.netcraft.com.au/tarka/certbot-api.php"

// Due to how the Tarka API operates, we can't add or remove records
// with the API, only send a request to letsencrypt endpoint.
//
// Only the updateRecord will be implemented to pass off to this endpoint
func (p *Provider) updateRecord(ctx context.Context, zone string, record libdns.Record) error {

	// CORRECTED: Construct the FQDN from the relative record name and the zone.
	// The record.RR().Name for an ACME challenge will be "_acme-challenge".
	// The zone will be "app.tic.toshiba.com.au".
	// This combines them into "_acme-challenge.app.tic.toshiba.com.au".
	fqdn := libdns.AbsoluteName(record.RR().Name, zone)

	params := url.Values{}
	params.Set("domain", fqdn)
	params.Set("token", p.APIToken)
	params.Set("validation", record.RR().Data)

	req, err := http.NewRequestWithContext(ctx, "POST", apiEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error: status %d", resp.StatusCode)
	}

	return nil
}
