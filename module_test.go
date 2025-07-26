package tarka

import (
	"fmt"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestTarkaConfigBlock(t *testing.T) {
	fmt.Println("Testing tarka config block with token...")
	api_token := "abc123"
	config := fmt.Sprintf(`tarka {
		api_token %s
	}`, api_token)

	dispenser := caddyfile.NewTestDispenser(config)
	p := Provider{}

	err := p.UnmarshalCaddyfile(dispenser)
	if err != nil {
		t.Errorf("UnmarshalCaddyfile failed with %v", err)
		return
	}

	expected := api_token
	actual := p.APIToken
	if expected != actual {
		t.Errorf("Expected APIToken to be '%s' but got '%s'", expected, actual)
	}
}

func TestTarkaMissingToken(t *testing.T) {
	fmt.Println("Testing tarka config block with unexpected value...")
	api_hostname := "abc123"
	config := fmt.Sprintf(`tarka {
		api_hostname %s
	}`, api_hostname)

	dispenser := caddyfile.NewTestDispenser(config)
	p := Provider{}

	err := p.UnmarshalCaddyfile(dispenser)
	if err == nil {
		t.Errorf("Expected error, but unmarshall succeeded: %v", err)
		return
	}

	expected := "unrecognized subdirective 'api_hostname', at Testfile:2"
	if err.Error() != expected {
		t.Errorf("Expected error: '%s', but got: '%s'", expected, err.Error())
	}
}
