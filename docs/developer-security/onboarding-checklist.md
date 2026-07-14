# Onboarding Checklist

This checklist supports `SR-DEV-001`, `SR-DEV-002` and `SR-EVIDENCE-001`.

- [ ] Read `README.md`, `CONTRIBUTING.md` and `SECURITY.md`.
- [ ] Run `make security-doctor` and resolve unavailable required tools.
- [ ] Run `make setup`.
- [ ] Start the app with `make run` when manual API testing is needed.
- [ ] Generate a local synthetic token with `make dev-token-researcher` or another role-specific target.
- [ ] Run `make quality`.
- [ ] Run `make appsec-fast` for routine changes.
- [ ] Run `make dynamic-full` for API boundary changes.
- [ ] Run `make findings-full`, `make release-full`, `make lifecycle-full` and `make evidence-full` before review when evidence changed.
- [ ] Complete `.github/pull_request_template.md` without pasting secrets or raw scanner logs.
- [ ] Confirm suppressions and exceptions are narrow, governed and expiring.
- [ ] Run `make developer-enablement-full` when changing developer guidance.

Success means a new contributor can set up the repository, run local checks, understand findings, request governed exceptions if needed and verify remediation without bypassing controls. Evidence is recorded under `outputs/security/developer-enablement/` and reports under `reports/security/`.

