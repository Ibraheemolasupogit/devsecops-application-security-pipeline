# Local Security Workflow

For Milestone 7 findings work:

```bash
make appsec-full
make dynamic-full
make findings-full
make verify-findings-evidence
make findings-report
```

`findings-full` consumes existing scanner outputs and does not require Docker by itself.
