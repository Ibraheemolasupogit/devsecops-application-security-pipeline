# Dynamic Security Policy

Policy configuration lives in `security/dynamic/policy.yaml`.

Blocking conditions include unexpected 5xx responses, authentication bypass, authorisation bypass, object-level access bypass, mass-assignment success, schema mismatch, missing required security headers, wildcard CORS behaviour, resource-limit bypass, high-risk ZAP alerts and unavailable required tools.

Medium-risk ZAP alerts are warnings unless promoted by policy.
