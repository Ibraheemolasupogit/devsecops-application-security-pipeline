# CORS Validation

`make cors-test` validates CORS dynamically.

Allowed local origins receive explicit allow-origin headers. Disallowed origins, disallowed methods and `null` origins do not receive permissive CORS headers. Wildcard origins are rejected by application settings validation.
