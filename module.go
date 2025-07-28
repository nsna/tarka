package tarka

import (
	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(Provider{})
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "dns.providers.tarka",
		New: func() caddy.Module {
			// This now simply returns a new instance of our Provider struct.
			// No wrapping is needed.
			return new(Provider)
		},
	}
}

// Before using the provider config, resolve placeholders in the API token(s).
// Implements caddy.Provisioner.
func (p *Provider) Provision(ctx caddy.Context) error {
	p.Username = caddy.NewReplacer().ReplaceAll(p.Username, "")
	p.Password = caddy.NewReplacer().ReplaceAll(p.Password, "")
	p.DomainID = caddy.NewReplacer().ReplaceAll(p.DomainID, "")
	p.log = caddy.Log().Named("dns.providers.tarka")
	return nil
}

// Expansion of placeholders in the API token is left to the JSON config caddy.Provisioner (above).
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "username":
				if d.NextArg() {
					p.Username = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "password":
				if d.NextArg() {
					p.Password = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "domain_id":
				if d.NextArg() {
					p.DomainID = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	if p.Username == "" {
		return d.Err("missing 'username'")
	}
	if p.Password == "" {
		return d.Err("missing 'password'")
	}
	if p.DomainID == "" {
		return d.Err("missing 'domain_id'")
	}
	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
)
