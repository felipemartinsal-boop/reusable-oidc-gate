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
    # Pin an immutable commit, and one that appears in approved-shas.json on the
    # protected branch. A branch, a tag, or any other commit is rejected.
    uses: felipemartinsal-boop/reusable-oidc-gate/.github/workflows/gate.yml@<approved-commit-sha>
    permissions:
      id-token: write
```

There are **no inputs**. An earlier version took the audience as one, which made
that check circular: the caller chose both the value requested and the value it
was compared against, so the test confirmed only the caller's consistency with
itself.

The job runs inside the **caller's** workflow run, so the caller's logs stay in
the caller's repository. Nothing executes here.

## Outcomes

| outcome | meaning |
|---|---|
| `VERIFIED` | every rule held |
| `REJECTED` | a rule was broken — a policy failure, or a proof known to be bad |
| `INCONCLUSIVE` | the verification could not be carried out: a crash, an empty key set, a network error, a malformed response |

`INCONCLUSIVE` is not a softer `REJECTED`. Collapsing the two lets a crash read
as "we checked and it was bad", which is a lie shaped exactly like the truth.
No catch-all turns an unexpected failure into a rejection.

## Exact pinning

Belonging to the protected branch's history is **necessary and not sufficient**.
An older commit is in that history too, and an older commit may carry a weaker
gate — so ancestry alone permits a silent downgrade. The commit must also appear
in [`approved-shas.json`](approved-shas.json) as read from the protected branch,
which means adding one takes a reviewed pull request.

Both conditions are checked independently.

## What the audience binds, and what it does not

The audience is a constant of the verifier, not a parameter.

**It binds:** the token to this gate's purpose. A token minted for some other
audience will not verify here, so one obtained elsewhere cannot be replayed
into this check.

**It does not bind:** who called, whether that caller was authorised, or
anything about the caller's repository. It is a sanity check on the token's
intended use — not an authorisation, not an identity, and not evidence about the
caller. Reading it as any of those would be reading a label as a credential.

## Trust boundary

This workflow gives a caller evidence that **it cannot forge**: the OIDC
signature is made by the issuer, and `job_workflow_ref`/`job_workflow_sha` are
set by the platform, not by the caller.

It does **not** protect against someone who administers the repositories
involved. Anyone able to change this repository's protected branch, or to change
how the caller consumes the result, is outside the guarantee.

**It also does not cover the consumer.** This gate produces evidence; it cannot
make anyone act on it. A caller that ignores the outcome, or that rewrites its
own verification, is unaffected by anything here. Externalising the producer of
a proof is not the same as externalising the decision, and only the first is on
offer.
