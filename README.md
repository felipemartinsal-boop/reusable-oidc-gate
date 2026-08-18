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

## Root of trust — there is no bootstrap

An earlier version read the repository and commit out of the JWT payload
**before** verifying its signature, fetched a verifier from that location, and
ran it. Unauthenticated data chose the code that would do the authentication.

The first attempt at a fix pinned the repository and the verifier's digest in
this workflow and fetched from constants. Two measurements killed that too:
neither `github.workflow_sha` nor `github.job_workflow_sha` yields **this**
workflow's own commit inside a reusable call. The first describes the *caller* —
the gate went looking for its own verifier at the caller's commit and got a 404
on every call. The second came back empty. So the gate could not name its own
code without asking the token, which is the circularity again.

**The verifier is therefore embedded in [`gate.yml`](.github/workflows/gate.yml).**
Nothing is fetched and nothing is selected: the code that runs is this file,
immutable at the approved commit. There is no URL to poison and no digest to
compare, because nothing arrives from outside.

The readable copy stays at [`verify.py`](verify.py), and
[`tests/bateria.py`](tests/bateria.py) fails if the two differ **by a single
byte** — so reviewability does not cost you fidelity.

`GATE_EXPECTED_REPO` is still fixed here, and the decision refuses any token
whose `job_workflow_ref` names a different repository.

## No run-time dependencies

`verify.py` implements RS256 — RSASSA-PKCS1-v1_5 with SHA-256 — against the
standard library. Pinning a commit and then installing unpinned cryptography
would leave the approved commit verifying with different code tomorrow, which is
not pinning. The algorithm allowlist is a constant: the token's own header does
not get to nominate how it will be checked, and `none`, `HS256` and `RS512` are
refused explicitly.

## Proof

[`tests/bateria.py`](tests/bateria.py) exercises the shipped `verify.py` **and**
the copy extracted from the workflow's heredoc, run as a module — so what is
proved is what executes. **63 cases**, in CI on three Python versions, entirely
synthetic: throwaway RSA keys built in-process, no network, and **no data from
any caller**.

### Why an external vector, and not just a synthetic one

A synthetic positive control signs with the verifier's *own* DigestInfo
constant. If that constant were wrong, the synthetic issuer would repeat the
same mistake and the test would stay green over an implementation no real issuer
would accept. The battery **demonstrates** this before relying on anything: it
loads a copy of the verifier with a corrupted DigestInfo, shows the synthetic
control still passes, and shows the same corrupted copy **fails** the vector
from [RFC 7515, Appendix A.2](https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.2).

That vector is versioned at
[`tests/vetor-rfc7515-a2.json`](tests/vetor-rfc7515-a2.json) — fixed signing
input, `n`, `e` and signature published by the IETF. It uses no helper and no
constant of this implementation. Tampering with the signature, the payload or
the key all fail it, and mutating either the DigestInfo or the padding brings it
down.

### RSA parameters are policy, not description

Modulus below the normative minimum, an even or degenerate exponent, or a key
declaring `use` other than signing are **rejections** — known policy violations.
An unreadable parameter is **inconclusive**. That distinction cost a real defect:
`urlsafe_b64decode` silently ignores characters outside the alphabet, so a
garbage modulus decoded to a small integer and was reported as "modulus too
short" — a policy violation invented out of unreadable input. Decoding is now
strict.

### The embedded copy is generated

[`tests/embutir.py`](tests/embutir.py) writes the block inside `gate.yml` from
`verify.py`. CI re-runs it and fails if the result differs, and the battery
compares the two byte for byte — so the readable file and the executed copy
cannot drift apart.

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
