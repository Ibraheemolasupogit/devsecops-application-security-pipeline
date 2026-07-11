# API Security Control Matrix

| Control | Implementation | Verification | Evidence |
| --- | --- | --- | --- |
| JWT validation | `security/authentication/jwt_validator.py` | `tests/security/test_api_security_controls.py` | `outputs/security/api-security/authentication-control-summary.json` |
| Role permissions | `security/authorisation.py` | `tests/security/test_api_security_controls.py` | `outputs/security/api-security/authorisation-matrix.json` |
| Protected routes | `security/authentication/dependencies.py` | `tests/security/test_api_security_controls.py` | `outputs/security/api-security/endpoint-security-inventory.json` |
| Object checks | `services/access_requests.py`, `services/datasets.py` | `tests/security/test_api_security_controls.py` | `outputs/security/api-security/endpoint-security-inventory.json` |
| Negative security tests | `tests/security/test_api_security_controls.py` | `make api-security-test` | `outputs/security/api-security/negative-test-summary.json` |
| Audit controls | `audit/service.py`, route and service callers | `tests/security/test_api_security_controls.py` | `outputs/security/api-security/audit-control-summary.json` |
