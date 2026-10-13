# M7 corrective suppression validation — 2026-10-13

Scope: resolve the expired-suppression failures and validate the existing bootstrap lifecycle correction. No deployment, state migration, resource mutation, image publication, commit, or push is authorized by this report.

## Classification before repository changes

There were **six failing AppSec tests caused by two expired suppression records**, not six expired suppressions. Both records had owner `platform-engineering`, approver `product_security_engineer`, creation date 2026-07-12, review date 2026-08-12, and expiry 2026-10-12:

| Reference | Suppression ID | Original vulnerability/package | Current candidate/evidence status | Classification |
| --- | --- | --- | --- | --- |
| A | `SUP-TRIVY-PERL-BASE-CRITICAL-001` | Critical `CVE-2026-42496`, `perl-base` | Absent from recorded evidence and fresh Trivy scan | No longer needed; remove |
| B | `SUP-TRIVY-PERL-BASE-CRITICAL-002` | Critical `CVE-2026-8376`, `perl-base` | Absent from recorded evidence and fresh Trivy scan | No longer needed; remove |

Both original reasons stated: “Trivy reports this critical Debian 13 perl-base vulnerability with no fixed version available after moving to the current supported slim-trixie base and applying apt upgrades.” The original compensating control stated that the Python API does not invoke Perl, the package remains a Debian base dependency, and the image is rebuilt with package updates during validation. The current evidence no longer reports either reviewed CVE, so renewal is unnecessary. Neither record was renewed or replaced, and neither missing CVE became an unsuppressed finding.

All six failures were reproduced before editing the register. Every failure consulted the same register and failed on `active suppression is expired`; both A and B were classified as removable before editing:

| File | Failing test | Reviewed records / decision |
| --- | --- | --- |
| `tests/security/test_appsec_pipeline.py` | `test_suppression_register_is_valid_and_narrow` | A and B: remove; absent current CVEs |
| `tests/security/test_appsec_pipeline.py` | `test_scanner_parsers_handle_blocking_fixture_outputs` | A and B: remove; absent current CVEs |
| `tests/security/test_appsec_pipeline.py` | `test_pipeline_summary_blocks_on_incomplete_scans` | A and B: remove; absent current CVEs |
| `tests/security/test_appsec_pipeline.py` | `test_appsec_evidence_is_deterministic` | A and B: remove; absent current CVEs |
| `tests/security/test_appsec_pipeline.py` | `test_appsec_evidence_verification_rejects_missing_or_tampered_outputs` | A and B: remove; absent current CVEs |
| `tests/security/test_appsec_pipeline.py` | `test_appsec_reports_are_generated_from_evidence` | A and B: remove; absent current CVEs |

## Candidate and scanner evidence

The existing candidate was reused without rebuilding: `genomic-research-access-api:git-7bc2106054f197fdd432ce11412aede926764812`, image ID/digest `sha256:4cf7c5e4472e227388bb9fed5b87781bc1b8d0833dc699edce96f3116bee28ec`, platform `linux/amd64`. Dockerfile, Dockerignore, and dependency-definition hashes match the recorded build metadata. An isolated read-only container with networking disabled confirmed that the aggregate digest of all packaged Python source files matches the workspace: `258bb9df60f5861652ced3eb68950eed78f0cd19aeb8d332d32c4365e5186f0e`.

Trivy 0.72.0 used its database updated 2026-10-12T13:18:23Z. The fresh policy scan reports **44 High, 0 Critical, 0 suppressed, 0 blocking**. A diagnostic scan across all severities additionally confirmed neither removed CVE appears; its vulnerability counts were 44 High, 58 Medium, 61 Low, 3 Unknown, and 0 Critical. The repository's existing severity selection and release rules were not changed. `perl-base` 5.40.1-6+deb13u1 still has unsuppressed High `CVE-2026-9538`, status `fix_deferred`, with no reported fixed version. All 44 policy-scope Trivy findings remain visible in canonical evidence.

The candidate retains its original dirty-build provenance and source commit. Matching image contents support diagnostic reuse; they do not establish a clean publishable candidate. Publication remains blocked and no image is published.

## Corrective changes and validation method

Only the two obsolete records were removed from `security/config/suppressions.yaml`. No exception approvals were invented, no expiry was extended, and no severity/release policy was relaxed. `test_source_preservation_suppression_and_fix_available` previously required the disappeared CVE to remain suppressed; it now checks that each current configured suppression preserves its expiry, rationale and approver in canonical findings.

Coverage naturally returned from 84.48% to **85.27%** after the genuine AppSec failures were resolved. No coverage threshold, source exclusions, no-cover markers, or coverage-only tests were added. Linked findings/release/lifecycle/consolidated/integration/portfolio evidence is regenerated through the existing pipeline. Infrastructure evidence also requires regeneration because the earlier lifecycle correction changed the recorded checksum of bootstrap `versions.tf`.

The Make targets use their existing deterministic evidence dates. Current-date evidence is additionally regenerated through the existing CLI timestamp/as-of-date arguments; neither a backdated evaluation nor a synthetic lifecycle fixture constitutes a new approval or renewal. The bootstrap saved plan, configuration and live variable-file hashes are checked for unchanged contents; plan regeneration is unnecessary.

## Final results

All requested validation targets were executed. Required sandbox retries enabled provider processes, Docker access and dependency/advisory downloads; they did not change the permitted actions. The final current-date evidence refresh used `2026-10-13T04:40:43Z` and as-of date `2026-10-13` and passed each domain's verifier, including supply-chain verification.

| Validation | Final result |
| --- | --- |
| `make format`, `format-check`, `lint`, `type-check` | Passed |
| `make test`, `test-coverage` | Passed; 309 tests, 85.27% coverage |
| `make quality` | Passed |
| `make appsec-full SUPPLY_CHAIN_REUSE_EXISTING=1` | Passed; reused candidate, no build or publication |
| `make supply-chain-full SUPPLY_CHAIN_REUSE_EXISTING=1` | Passed; reused candidate, no build or publication |
| `make verify-findings-evidence`, `verify-release-evidence` | Passed |
| `make lifecycle-full`, `evidence-full`, `integration-full`, `portfolio-full` | Passed after required infrastructure checksum refresh |
| `make terraform-bootstrap-validate` | Passed; 1 mock-provider plan run |
| `make terraform-test` | Passed; 23 mock-provider plan runs |
| `make infrastructure-test` | Passed; 37 tests |
| `make checkov-scan` | 510 passed, 0 failed, 48 skipped; 147 resources, 0 parsing errors |
| `make final-validation` | Passed |
| Existing bootstrap saved plan | 9 additions, 0 changes, 0 destroys; no replacements |
| Bootstrap plan / variables / configuration hashes | Unchanged; plan not regenerated |
| `git diff --check` | Passed |

Checkov's optional online guidelines lookup remained unavailable due to local certificate validation; built-in checks completed with zero failed checks. No TLS verification was disabled. Trivy's policy-scope count is 44 High findings, 0 Critical, 0 suppressed and 0 blocking. Canonical evidence contains 67 findings. Release remains **`conditional_pass`**, requiring its existing recorded approvals; publication remains **`blocked`**, with `publication_allowed = false`, because the candidate's original dirty-build provenance remains intact. The current-date lifecycle evaluation treats expired fixture exceptions as expired and reactivates their findings rather than renewing them.

No expired active suppression remains in either scanner register. No suppressions were renewed or added, and no missing reviewed CVE was fabricated as a new finding. The corrective fix is ready to commit under the stated validation criteria; this does not authorize release or publication. Local `terraform.tfvars`, live backend files, state/backups and saved plans remain ignored and untracked. No Terraform apply/destroy, AWS resource mutation, state migration, ECR push, Kubernetes deployment, M8 work, commit or push occurred.

Recommended commit message: `Fix Terraform bootstrap local-state lifecycle`.

## Files changed in this pass

The prior bootstrap configuration, ignore-rule, runbook and infrastructure-test edits were preserved without further changes. This pass changed the suppression register, its canonical-lineage regression test, the validation documentation, and regenerated evidence/reports listed below.

```text
docs/engineering/m7-corrective-validation.md
docs/engineering/milestone-7-validation.md
outputs/portfolio/evidence-index.json
outputs/portfolio/portfolio-manifest.json
outputs/portfolio/portfolio-summary.json
outputs/portfolio/report-index.json
outputs/portfolio/reports/final-architecture-report.md
outputs/portfolio/reports/final-evidence-report.md
outputs/portfolio/reports/final-project-report.md
outputs/portfolio/reports/final-security-assurance-report.md
outputs/portfolio/reports/final-testing-report.md
outputs/security/appsec/appsec-pipeline-summary.json
outputs/security/appsec/evidence-manifest.json
outputs/security/appsec/raw/bandit.json
outputs/security/appsec/raw/checkov.json
outputs/security/appsec/raw/semgrep.json
outputs/security/appsec/raw/trivy.json
outputs/security/appsec/sbom.cdx.json
outputs/security/champions/champion-metrics.json
outputs/security/champions/evidence-manifest.json
outputs/security/developer-enablement/enablement-summary.json
outputs/security/developer-enablement/evidence-manifest.json
outputs/security/developer-enablement/prerequisite-check-summary.json
outputs/security/evidence/consolidated-evidence.json
outputs/security/evidence/evidence-domain-summary.json
outputs/security/evidence/evidence-manifest.json
outputs/security/evidence/portfolio-security-summary.json
outputs/security/evidence/release-assurance-summary.json
outputs/security/evidence/security-exception-summary.json
outputs/security/evidence/security-metrics.json
outputs/security/evidence/vulnerability-management-summary.json
outputs/security/findings/deduplicated-findings.json
outputs/security/findings/deduplication-summary.json
outputs/security/findings/evidence-manifest.json
outputs/security/findings/finding-source-map.json
outputs/security/findings/findings-summary.json
outputs/security/findings/normalised-findings.csv
outputs/security/findings/normalised-findings.json
outputs/security/findings/ownership-summary.json
outputs/security/findings/risk-summary.json
outputs/security/findings/sla-summary.json
outputs/security/findings/suppressed-findings.csv
outputs/security/infrastructure/evidence-manifest.json
outputs/security/integration/checksums.sha256
outputs/security/integration/control-traceability.json
outputs/security/integration/data-quality-summary.json
outputs/security/integration/finding-lifecycle-status.json
outputs/security/integration/finding-release-impact.json
outputs/security/integration/finding-source-lineage.json
outputs/security/integration/integration-manifest.json
outputs/security/integration/integration-summary.json
outputs/security/integration/integration-validation-summary.json
outputs/security/integration/ownership-and-sla.json
outputs/security/integration/product-security-findings.csv
outputs/security/integration/product-security-findings.json
outputs/security/integration/security-exceptions.json
outputs/security/integration/security-metrics.json
outputs/security/lifecycle/due-soon-findings.csv
outputs/security/lifecycle/evidence-manifest.json
outputs/security/lifecycle/exception-history.json
outputs/security/lifecycle/expired-exceptions.csv
outputs/security/lifecycle/expiring-exceptions.csv
outputs/security/lifecycle/false-positive-register.csv
outputs/security/lifecycle/lifecycle-history.json
outputs/security/lifecycle/lifecycle-summary.json
outputs/security/lifecycle/risk-accepted-findings.csv
outputs/security/lifecycle/security-exceptions.json
outputs/security/lifecycle/vulnerability-register.csv
outputs/security/lifecycle/vulnerability-register.json
outputs/security/portfolio/evidence-index.json
outputs/security/portfolio/portfolio-manifest.json
outputs/security/portfolio/portfolio-metrics.json
outputs/security/portfolio/portfolio-summary.json
outputs/security/portfolio/report-index.json
outputs/security/release/evidence-manifest.json
outputs/security/release/finding-evaluations.json
outputs/security/release/matched-rules.json
outputs/security/release/release-actions.json
outputs/security/release/release-gate-decision.json
outputs/security/release/release-risk-summary.json
outputs/security/release/required-approvals.json
outputs/security/supply-chain/build-metadata.json
outputs/security/supply-chain/checksums.sha256
outputs/security/supply-chain/container-sbom.cdx.json
outputs/security/supply-chain/container-scan-summary.json
outputs/security/supply-chain/provenance.json
outputs/security/supply-chain/publication-eligibility.json
outputs/security/supply-chain/release-artifact.json
outputs/security/supply-chain/sbom-summary.json
outputs/security/supply-chain/supply-chain-manifest.json
reports/portfolio/final-architecture-report.md
reports/portfolio/final-evidence-report.md
reports/portfolio/final-limitations-report.md
reports/portfolio/final-portfolio-readiness-report.md
reports/portfolio/final-project-report.md
reports/portfolio/final-security-assurance-report.md
reports/portfolio/final-testing-report.md
reports/security/deduplication-report.md
reports/security/developer-onboarding-report.md
reports/security/executive-security-summary.md
reports/security/findings-and-risk-report.md
reports/security/findings-normalisation-report.md
reports/security/iac-security-report.md
reports/security/integration-lineage-report.md
reports/security/lifecycle-audit-report.md
reports/security/overdue-findings-report.md
reports/security/ownership-report.md
reports/security/portfolio-assurance-report.md
reports/security/product-security-export-report.md
reports/security/product-security-report.md
reports/security/release-actions-report.md
reports/security/release-gate-report.md
reports/security/release-risk-report.md
reports/security/remediation-sla-report.md
reports/security/risk-enrichment-report.md
reports/security/security-evidence-report.md
reports/security/security-exception-report.md
reports/security/security-tooling-readiness-report.md
reports/security/vulnerability-lifecycle-report.md
reports/security/vulnerability-remediation-report.md
security/config/suppressions.yaml
tests/security/test_findings_pipeline.py
```
