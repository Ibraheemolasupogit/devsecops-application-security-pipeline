# Dependency Security

Dependency scanning uses project-scoped `pip-audit`.

```bash
make dependency-audit
make sca
```

Milestone 5 remediated vulnerable runtime pins by updating FastAPI, PyJWT and Starlette. Scanner-tool dependencies are installed for local execution but are not treated as runtime application dependencies for the project SCA gate.

EKS evolution M2 upgrades the directly pinned PyJWT to 2.15.1 after a live advisory audit. See [dependency remediation and advisory inventory](../engineering/dependency-hygiene.md). Activate the repository .venv before checks; direct pins do not lock all transitive dependencies.
