# reusable-oidc-gate

A generic, reusable GitHub Actions workflow that **derives** build provenance for the job that
called it, and **verifies** that provenance against sources outside the calling repository.

It exists because a caller cannot be trusted to describe its own execution. Anything a caller
writes about itself — a field, a flag, a summary — is written by the same party whose claim is
in question. This workflow therefore takes **no verdict as input**. It computes every fact it
reports.

## What it does

1. Requests an OIDC token for the running job and verifies the signature against the issuer's
   published JWKS. The public keys live outside any repository.
2. Checks that `job_workflow_ref` names **this** workflow — so the caller cannot claim the
   provenance of a workflow it did not actually run.
3. Requires that `job_workflow_ref` pins an immutable commit. A call made through a branch or a
   tag is rejected: those move, and a moving reference proves nothing about the code that ran.
4. Confirms, through this repository's public API and without any credential, that
   `job_workflow_sha` belongs to the history of the protected default branch.
5. Validates audience, issuer, and the token's validity window against the system clock.

Any failure fails the job. An empty result, an unreachable API or a missing claim is
**inconclusive**, never a pass.

## What it deliberately does not do

- It accepts **no** input that asserts a result. There is no `passed`, no `verdict`, no
  `skip_verification`.
- It never prints the token. Only derived, non-authenticable facts reach the log.
- It stores nothing and reaches no service other than the OIDC issuer's public keys and this
  repository's public API.

## Usage

```yaml
jobs:
  verify:
    # Pin an immutable commit. A branch or tag here is rejected by design.
    uses: felipemartinsal-boop/reusable-oidc-gate/.github/workflows/gate.yml@<commit-sha>
    permissions:
      id-token: write
    with:
      audience: your-audience
```

The job runs inside the **caller's** workflow run, so the caller's logs stay in the caller's
repository. Nothing executes here.

## Trust boundary

This workflow gives a caller evidence that **it cannot forge**: the OIDC signature is made by the
issuer, and `job_workflow_ref`/`job_workflow_sha` are set by the platform, not by the caller.

It does **not** protect against someone who administers the repositories involved. Anyone able to
change this repository's protected branch, or to change how the caller consumes the result, is
outside the guarantee. That is a governance problem, not something a workflow can solve.
