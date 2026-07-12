# SAST

SAST uses Semgrep and Bandit:

- `make semgrep-test` validates custom Semgrep rules.
- `make sast-semgrep` scans repository Python code with local rules.
- `make sast-bandit` scans `src/` and `scripts/` with medium/high thresholds.
- `make sast` runs both scanners.

Custom rules cover client-controlled requester identity, raw Authorization header logging, unpinned JWT algorithms and `subprocess` with `shell=True`.
