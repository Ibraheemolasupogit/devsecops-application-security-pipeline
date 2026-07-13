# Security Header Validation

`make security-header-test` validates security headers dynamically on representative success, authentication failure, authorisation failure and error responses.

Required local headers include:

- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Content-Security-Policy`
- `Permissions-Policy`
- `Cache-Control` for API responses
- `X-Correlation-ID`

`Strict-Transport-Security` is not required for local HTTP mode.
