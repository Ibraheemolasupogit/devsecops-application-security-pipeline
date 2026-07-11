# API Security Report

| Metric | Value |
| --- | --- |
| Authentication | implemented |
| Authorisation | implemented |
| Protected API routes | 8 |
| Roles | 5 |
| Negative security tests | 24 |

| Method | Path | Permissions | Object Rule |
| --- | --- | --- | --- |
| GET | /api/v1/datasets | dataset:list | not_applicable |
| GET | /api/v1/datasets/{dataset_id} | dataset:read | restricted datasets require custodian/admin role or approved request |
| POST | /api/v1/access-requests | access_request:create | requester identity is derived from token subject |
| GET | /api/v1/access-requests | access_request:list_own, access_request:list_all | researchers see own requests; privileged reviewers see permitted queue |
| GET | /api/v1/access-requests/{request_id} | access_request:read_own, access_request:read_all | unauthorised object access returns not found |
| POST | /api/v1/access-requests/{request_id}/approve | access_request:approve | requester cannot approve own request |
| POST | /api/v1/access-requests/{request_id}/reject | access_request:reject | requester cannot reject own request |
| GET | /api/v1/audit-events | audit_event:read | audit records require security-auditor or administrator permission |
