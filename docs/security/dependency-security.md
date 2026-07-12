# Dependency Security

Dependency scanning uses project-scoped `pip-audit`.

```bash
make dependency-audit
make sca
```

Milestone 5 remediated vulnerable runtime pins by updating FastAPI, PyJWT and Starlette. Scanner-tool dependencies are installed for local execution but are not treated as runtime application dependencies for the project SCA gate.
