# Dependency Hygiene — PyJWT Remediation

EKS evolution Milestone 2, 2026-10-11. The live baseline pip-audit reported 14 advisories for PyJWT 2.13.0. Historical committed raw/pip-audit.json had zero findings for that version; it was a prior database snapshot, not evidence that the October baseline was safe.

## Root cause and pinning model

PyJWT[crypto]==2.13.0 is a **direct runtime dependency** in pyproject.toml, installed by editable project setup and the Docker wheel build. crypto pulls cryptography (>=3.4.0 per release metadata); FastAPI is not the cause of this pin. There is no Python lockfile/constraint/requirements file. Runtime/dev/security direct dependencies and build backend are exact pins, transitive resolution floats. Terraform .terraform.lock.hcl files lock a different dependency graph and remain tracked. Do not claim a fully reproducible Python build.

The fallback SBOM generator duplicated four pins and omitted two direct runtime packages. It now derives all direct components from pyproject.toml; a regression test changes input pins and confirms the generated inventory changes. This is a limited direct dependency inventory; the normal CycloneDX environment command still includes installed tooling and is not an image SBOM. Image-derived SBOM/locked resolution belongs to M6.

## Exact baseline advisories

Captured by the unmodified project-scoped pip-audit 2.7.3 after a network-enabled retry. Aliases and fix_versions below are the actual native JSON output. IDs sharing an alias are not counted twice.

| pip-audit ID | CVE alias | Upstream advisory | Reported fixed versions |
| --- | --- | --- | --- |
| PYSEC-2026-4145 | CVE-2026-102268 | [GHSA-ffc3-869f-jxw9](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-ffc3-869f-jxw9) | 2.14.0 |
| PYSEC-2026-4146 | CVE-2026-103001 | [GHSA-gvp8-978c-rx2q](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-gvp8-978c-rx2q) | No fix_versions entry; affected range ends at 2.13.0 |
| PYSEC-2026-4149 | CVE-2026-102271 | [GHSA-p4g4-x82p-q773](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-p4g4-x82p-q773) | 2.14.0 |
| PYSEC-2026-4152 | CVE-2026-102274 | [GHSA-w6j9-cwv2-h6wq](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-w6j9-cwv2-h6wq) | 2.14.0 |
| PYSEC-2026-4144 | CVE-2026-102267 | [GHSA-9v7f-9g4p-ffgj](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-9v7f-9g4p-ffgj) | 2.14.0 |
| PYSEC-2026-4143 | CVE-2026-102266 | [GHSA-9j54-fg26-wv3r](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-9j54-fg26-wv3r) | 2.14.0 |
| PYSEC-2026-4148 | CVE-2026-102270 | [GHSA-jwrc-g2q2-pq5p](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-jwrc-g2q2-pq5p) | 2.14.0 |
| PYSEC-2026-4140 | CVE-2026-101917 | [GHSA-2gx3-rcp4-g85q](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-2gx3-rcp4-g85q) | 2.14.0 |
| PYSEC-2026-4141 | CVE-2026-101918 | [GHSA-42vr-xj54-vc7v](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-42vr-xj54-vc7v) | 2.15.0 |
| PYSEC-2026-4147 | CVE-2026-102269 | [GHSA-hxm8-2xgr-2p9m](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-hxm8-2xgr-2p9m) | 2.14.0 |
| PYSEC-2026-4151 | CVE-2026-102273 | [GHSA-w2cx-738m-mc7w](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-w2cx-738m-mc7w) | 2.14.0 |
| PYSEC-2026-4150 | CVE-2026-102272 | [GHSA-r6x4-923q-g947](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-r6x4-923q-g947) | 2.14.0 |
| PYSEC-2026-4142 | CVE-2026-102265 | [GHSA-8wjv-2p76-3863](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-8wjv-2p76-3863) | 2.14.0 |
| PYSEC-2026-4183 | CVE-2026-102275 | [GHSA-x33g-cr3x-6449](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-x33g-cr3x-6449) | 2.15.0 |

For PYSEC-2026-4146 / CVE-2026-103001, pip-audit supplied no fixed version. The [upstream advisory](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-gvp8-978c-rx2q) lists the affected range >=2.11.0, <=2.13.0 and still has no patched-version field. The application creates fresh decode options and never disables signature verification in the validator, so the documented reused-options precondition is absent. This is context, not a suppression. We upgrade outside the stated range, retain this metadata caveat and verify the actual newer audit rather than inventing a fix version.

## Remediation and compatibility evidence

Canonical pin upgraded to PyJWT[crypto]==2.15.1, a non-yanked release with Python >=3.9 and crypto extra compatible with this project's Python >=3.11. [PyPI release metadata](https://pypi.org/project/PyJWT/2.15.1/) and [upstream changelog](https://pyjwt.readthedocs.io/en/stable/changelog.html) were checked. 2.15.1 includes the 2.14/2.15 security changes and fixes interoperability with padded JWS encodings; no downgrade or blanket ignore was used.

Installed the new pin in .venv and refreshed the editable project metadata. An initial --no-build-isolation attempt failed because setuptools.build_meta was absent; retry used the declared isolated pinned backend and succeeded. pip check then reported no broken requirements. All post-change Make checks use .venv/bin on PATH; the system interpreter still has its separate installation and must not be mistaken for the validated environment.

Focused API/JWT and dynamic boundary tests: 27 passed, 5 warnings. Existing expired/missing claims, wrong issuer/audience, bad algorithm/signature, object authorisation and negative input tests remain. Full quality/type/coverage results are recorded in [M2 validation](milestone-2-validation.md). No validator, role mapping, repository/service runtime semantics or security policy was changed.

Project-scoped make dependency-audit after upgrade: **exit 0, No known vulnerabilities found**. It resolves the declared application runtime graph in its own temporary environment, not all security-tool dependencies. No suppressions, ignores, severity changes or scanner bypass flags were added. Native canonical pip-audit output is retained under outputs/security/appsec/raw/pip-audit.json; this document preserves baseline advisory identities after that file is refreshed. No remaining vulnerability was reported in the upgraded runtime graph at validation time; advisory data can change.

## Remaining hygiene work

Transitive runtime/build resolution is not locked; decide a reviewed constraints/lock model for one-build supply-chain work in M6. Scanner/dev environment SBOM is larger than runtime scope. Full fresh image assurance requires a running Docker daemon; old Trivy results must not be called an upgraded image scan. Retain historical findings/lifecycle IDs and exceptions until actual remediation verification justifies changes; do not erase governed demonstration history simply because runtime SCA is now clear.
