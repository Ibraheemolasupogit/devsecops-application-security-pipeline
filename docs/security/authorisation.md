# Authorisation

Authorisation is deny-by-default. Roles map to explicit permissions in `src/genomic_research_access_api/security/authorisation.py`.

Roles:

- `researcher`: list/read public dataset metadata and create/read own access requests.
- `approver`: review, approve and reject permitted access requests.
- `data_custodian`: reviewer permissions plus restricted dataset detail.
- `security_auditor`: read access-request metadata and audit events.
- `application_admin`: administrative API permissions with separation-of-duties checks still enforced.

Route dependencies enforce function-level permissions before request handlers call services. Service methods enforce object-level rules such as ownership, restricted dataset entitlement and requester/approver separation.
