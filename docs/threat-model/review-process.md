# Review Process

Threat-model reviews are required when:

- API routes are added or removed.
- Authentication or authorisation is introduced.
- Persistence moves from memory to durable storage.
- AWS, Terraform or deployment workflows are introduced.
- CI/CD permissions change.
- Audit logging or evidence generation changes.
- New data classifications or dataset types are added.

Validation command:

```bash
make threat-model-validate
```

Evidence verification command:

```bash
make verify-threat-model-evidence
```

Reviewers should confirm that future controls are not described as implemented until code, tests and evidence exist.
