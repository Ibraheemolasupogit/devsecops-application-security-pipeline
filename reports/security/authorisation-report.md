# Authorisation Report

| Role | Permissions |
| --- | --- |
| application_admin | access_request:approve, access_request:create, access_request:list_all, access_request:list_own, access_request:read_all, access_request:read_own, access_request:reject, administration:manage, audit_event:read, dataset:list, dataset:read, dataset:read_restricted |
| approver | access_request:approve, access_request:list_all, access_request:read_all, access_request:reject, dataset:list, dataset:read |
| data_custodian | access_request:approve, access_request:list_all, access_request:read_all, access_request:reject, dataset:list, dataset:read, dataset:read_restricted |
| researcher | access_request:create, access_request:list_own, access_request:read_own, dataset:list, dataset:read |
| security_auditor | access_request:list_all, access_request:read_all, audit_event:read |

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
