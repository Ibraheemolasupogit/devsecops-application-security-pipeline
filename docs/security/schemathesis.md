# Schemathesis

Schemathesis runs from the pinned container `schemathesis/schemathesis:4.0.26`.

Configuration is stored in `security/dynamic/config.yaml`:

- deterministic generation enabled;
- `max_examples` set to `12`;
- request timeout set to `5` seconds;
- maximum response time set to `1000` ms;
- phases limited to examples and fuzzing;
- checks limited to server-error, content-type and response-schema conformance.

The wrapper starts the API on `127.0.0.1:8000` and scans it through Docker's local gateway. Generated reports are sanitized and no JWTs are stored in committed evidence.
