# Object-Level Authorisation

Researchers can read only their own access requests. Review-capable roles can read the review queue permitted by their role. Unauthorised access to an existing access request returns a not-found style response so the API does not confirm resource existence.

Restricted dataset detail requires either a role with `dataset:read_restricted` or an approved access request for the same token subject and dataset.

Approval and rejection enforce separation of duties. The requester cannot approve or reject their own request, including when the requester has an administrator role.
