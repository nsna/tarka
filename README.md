# Tarka DNS Provider
## Building
To build caddy with this module, xcaddy is required:
```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

Build:
```bash
xcaddy build --with github.com/nsna/tarka=.
```

To run locally after building:
```bash
./caddy run --config Caddyfile
```

## Tarka
This module simulates the HTTP requests of the webUI.
