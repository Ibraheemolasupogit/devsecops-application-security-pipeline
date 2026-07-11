# Security Headers And CORS

The API applies security headers centrally in `main.py`:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`
- `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`
- `Cache-Control: no-store` for `/api/` responses

CORS uses an explicit allow-list. Wildcard origins are rejected by configuration validation. HSTS is configurable and disabled by default for local HTTP development.
