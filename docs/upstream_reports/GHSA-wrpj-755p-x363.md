# GHSA-wrpj-755p-x363: affected package and version range do not match the fixed code

Draft report for github/advisory-database. To be submitted by a maintainer of this project.

- Advisory: GHSA-wrpj-755p-x363 (CVE-2026-32794)
- Summary: "Apache Airflow Provider for Databricks: TLS Certificate Verification is Disabled in
  Databricks Provider K8s Token Exchange"
- Record checked: `advisories/github-reviewed/.../GHSA-wrpj-755p-x363/GHSA-wrpj-755p-x363.json`
  at github/advisory-database commit `b16e369438ef2ab329b4c224cae8224f144bf5d5` (2026-10-19)

## What is wrong

The record's only `affected` entry is:

```json
{"package": {"ecosystem": "PyPI", "name": "apache-airflow"},
 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.10.0"}, {"fixed": "1.12.0"}]}]}
```

1. **Package.** The summary and the fix are about the Databricks provider, which ships on PyPI as
   `apache-airflow-providers-databricks`, not as `apache-airflow` (Airflow core).
2. **Range.** `1.10.0`–`1.12.0` is not a release line of either package:
   - Airflow core has no 1.12.0; its 1.x tags end at `1.10.15`, followed by 2.x.
   - The Databricks provider is at 7.x (latest tag in our clone: `providers-databricks/7.22.0`).

As published, the advisory flags Airflow core 1.10.x installs (which do not contain the affected
code) and does not flag affected Databricks provider installs.

## Evidence

All from a clone of apache/airflow (tags as of our fetch):

- Fix: commit `a8c12067fbe984cd2a99b35f0a6909a570e87a1c` (2026-03-17), PR
  https://github.com/apache/airflow/pull/63704 (already in the advisory's references), "Enable TLS
  certificate verification for K8s token exchange in `DatabricksHook`". It changes only files under
  `providers/databricks/`, replacing `verify=False` with `verify=K8S_CA_CERT_PATH` in
  `providers/databricks/src/airflow/providers/databricks/hooks/databricks_base.py`.
- `git merge-base --is-ancestor a8c12067fb providers-databricks/7.11.0` → not an ancestor.
- `git merge-base --is-ancestor a8c12067fb providers-databricks/7.12.0` → ancestor.
- The `verify=False` call was added in commit `aa8f9c40f1` (2026-02-17, PR #61458, "Databricks OIDC
  token federation for Kubernetes deployment"); `git log -S'verify=False'` on that file returns only
  these two commits.
- `aa8f9c40f1` is not in `providers-databricks/7.9.0` and is in `providers-databricks/7.10.0` and
  `providers-databricks/7.11.0`.

## Suggested correction

```json
{"package": {"ecosystem": "PyPI", "name": "apache-airflow-providers-databricks"},
 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "7.10.0"}, {"fixed": "7.12.0"}]}]}
```

The published range `1.10.0`/`1.12.0` has the same minor and patch numbers as `7.10.0`/`7.12.0`,
which suggests the major version was mistyped. That is our inference from the git history above;
please confirm the versions against the Apache security announcement
(https://lists.apache.org/thread/hn17yqsgsdtl81llvhf80rkp53hnz5nb) and the PyPI release history,
which we did not check.
