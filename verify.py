"""Decision logic for the OIDC provenance gate.

Kept in its own file, and not inside the workflow, for one reason: a test that
rewrites the logic proves the rewrite. Both the workflow and any battery import
THIS file, so what is exercised is what ships.

`decidir` is pure: it takes the claims and the facts already fetched, and
returns an outcome. All I/O lives in `main`.

Three outcomes, and the distinction is the point:

    VERIFIED      every rule held
    REJECTED      a rule was broken -- a policy failure, or a proof known to be bad
    INCONCLUSIVE  the verification could not be carried out: crash, empty key
                  set, network error, malformed response, anything unexpected

An unexpected failure is never a rejection. Collapsing the two lets a crash
read as "we checked and it was bad", which is a lie with the same shape as the
truth.
"""

from __future__ import annotations

# Normative constant, NOT an input. The caller cannot choose the audience it is
# measured against; if it could, the check would compare a value the caller
# picked with a value the caller picked, and confirm only its own consistency.
AUDIENCIA_NORMATIVA = "reusable-oidc-gate/provenance/v1"

EMISSOR_NORMATIVO = "https://token.actions.githubusercontent.com"

VERIFIED = "VERIFIED"
REJECTED = "REJECTED"
INCONCLUSIVE = "INCONCLUSIVE"

CAMINHO_GATE = ".github/workflows/gate.yml"
FICHEIRO_APROVADOS = "approved-shas.json"


def _hex40(v) -> bool:
    if not isinstance(v, str) or len(v) != 40:
        return False
    return all(c in "0123456789abcdef" for c in v)


def decidir(claims, factos, agora):
    """Return (outcome, [reasons]).

    claims  -- the OIDC payload, already signature-verified by the caller of
               this function; `factos['assinatura']` carries that result.
    factos  -- what was fetched from outside: signature outcome, the gate
               repository's default branch, whether it is protected, and the
               approved-SHA list read from that branch.
    agora   -- unix seconds, from the system clock.
    """
    if not isinstance(claims, dict):
        return INCONCLUSIVE, ["claims are not an object"]
    if not isinstance(factos, dict):
        return INCONCLUSIVE, ["facts are not an object"]

    # --- infrastructure first: anything unusable here is INCONCLUSIVE --------
    assinatura = factos.get("assinatura")
    if assinatura is None:
        return INCONCLUSIVE, ["signature verification did not run"]
    if assinatura == "inconclusive":
        return INCONCLUSIVE, ["signature could not be verified: %s" % factos.get("assinatura_detalhe", "unknown")]

    aprovados = factos.get("aprovados")
    if aprovados is None:
        return INCONCLUSIVE, ["approved-SHA list unavailable"]
    if not isinstance(aprovados, list):
        return INCONCLUSIVE, ["approved-SHA list is malformed"]
    if len(aprovados) == 0:
        # An empty set is not permission to pass. It is the absence of an answer.
        return INCONCLUSIVE, ["approved-SHA list is empty"]
    if not all(_hex40(s) for s in aprovados):
        return INCONCLUSIVE, ["approved-SHA list contains an entry that is not a commit id"]

    ramo = factos.get("ramo_por_omissao")
    if not ramo:
        return INCONCLUSIVE, ["default branch of the gate repository unknown"]
    protegido = factos.get("ramo_protegido")
    if protegido is None:
        return INCONCLUSIVE, ["protection state of the default branch unknown"]

    for campo in ("iss", "aud", "exp", "iat", "job_workflow_ref", "job_workflow_sha"):
        if campo not in claims:
            return INCONCLUSIVE, ["token has no '%s' claim" % campo]

    try:
        exp = int(claims["exp"])
        iat = int(claims["iat"])
        agora = int(agora)
    except (TypeError, ValueError):
        return INCONCLUSIVE, ["token validity window is not numeric"]

    # --- policy: from here on, a violation is a REJECTION --------------------
    v = []

    if assinatura != "ok":
        v.append("signature rejected (%s)" % factos.get("assinatura_detalhe", assinatura))

    if claims["iss"] != EMISSOR_NORMATIVO:
        v.append("issuer is not the normative one")

    # The audience is a constant of this gate. It binds the token to THIS
    # verifier's purpose; it does NOT bind the caller, prove authorisation, or
    # say anything about who asked.
    if claims["aud"] != AUDIENCIA_NORMATIVA:
        v.append("audience is not the normative constant")

    if agora >= exp:
        v.append("token expired")
    if agora < iat - 60:
        v.append("token issued in the future")

    jwr = claims["job_workflow_ref"]
    jws = claims["job_workflow_sha"]

    if not isinstance(jwr, str) or ("/%s@" % CAMINHO_GATE) not in jwr:
        v.append("job_workflow_ref does not name this workflow")

    ref = jwr.rsplit("@", 1)[-1] if isinstance(jwr, str) and "@" in jwr else ""
    if not _hex40(ref):
        v.append("called through a moving reference ('%s'), not an immutable commit" % ref)
    elif ref != jws:
        v.append("the pinned ref and job_workflow_sha disagree")

    # EXACT PINNING. Belonging to the protected history is necessary and NOT
    # sufficient: an older commit is in that history too, and an older commit
    # may carry a weaker gate. Only the commit that was explicitly approved
    # passes -- ancestry is kept as a second, independent condition.
    if not _hex40(jws):
        v.append("job_workflow_sha is not a commit id")
    else:
        if jws not in aprovados:
            v.append("job_workflow_sha is not the approved commit")
        if factos.get("na_historia_protegida") is not True:
            v.append("job_workflow_sha is not in the history of the protected branch")

    if protegido is not True:
        v.append("the gate default branch is not protected")

    if claims.get("runner_environment") != "github-hosted":
        v.append("runner environment is not github-hosted")
    if not claims.get("run_id") or not claims.get("run_attempt"):
        v.append("run identity incomplete")

    if v:
        return REJECTED, v
    return VERIFIED, []


# ---------------------------------------------------------------- I/O wrapper

def _http_json(url):
    """Fetch JSON with no credential. Returns (dados, erro)."""
    import json
    import urllib.error
    import urllib.request
    pedido = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "reusable-oidc-gate",
    })
    try:
        with urllib.request.urlopen(pedido, timeout=20) as r:
            corpo = r.read()
    except urllib.error.HTTPError as e:
        return None, "HTTP %s" % e.code
    except Exception as e:  # rede, DNS, TLS, timeout
        return None, type(e).__name__
    try:
        return json.loads(corpo), None
    except Exception:
        return None, "malformed JSON"


def _verificar_assinatura(token, jwks):
    """(estado, detalhe). estado in {ok, mau, inconclusive}."""
    try:
        import jwt
        from jwt import PyJWKSet
    except Exception:
        return "inconclusive", "pyjwt unavailable"
    try:
        conjunto = PyJWKSet.from_dict(jwks)
    except Exception as e:
        # An empty or unusable key set is not a bad signature: it is the
        # inability to judge one. This is the crash that used to be laundered
        # into a rejection.
        return "inconclusive", "key set unusable (%s)" % type(e).__name__
    if not conjunto.keys:
        return "inconclusive", "key set has no keys"
    try:
        cabeca = jwt.get_unverified_header(token)
    except Exception as e:
        return "mau", "unreadable header (%s)" % type(e).__name__
    chave = None
    for k in conjunto.keys:
        if k.key_id == cabeca.get("kid"):
            chave = k.key
            break
    if chave is None:
        return "mau", "kid not in key set"
    try:
        jwt.decode(token, key=chave, algorithms=[cabeca["alg"]],
                   audience=AUDIENCIA_NORMATIVA, issuer=EMISSOR_NORMATIVO)
        return "ok", ""
    except Exception as e:
        return "mau", type(e).__name__


def main():
    import base64
    import json
    import os
    import sys
    import time

    def sair(estado, motivos):
        print("RESULT=%s" % estado)
        for m in motivos:
            print("REASON=%s" % m)
        sys.exit(0 if estado == VERIFIED else 1)

    token = os.environ.get("GATE_TOKEN", "")
    if not token or token.count(".") != 2:
        sair(INCONCLUSIVE, ["no usable token in this environment"])

    try:
        carga = token.split(".")[1]
        carga += "=" * (-len(carga) % 4)
        claims = json.loads(base64.urlsafe_b64decode(carga))
    except Exception as e:
        sair(INCONCLUSIVE, ["token payload unreadable (%s)" % type(e).__name__])

    jwr = claims.get("job_workflow_ref", "")
    repo = jwr.split("/.github/", 1)[0] if "/.github/" in jwr else ""
    if not repo:
        sair(INCONCLUSIVE, ["cannot derive the gate repository from job_workflow_ref"])

    factos = {}

    cfg, erro = _http_json("%s/.well-known/openid-configuration" % EMISSOR_NORMATIVO)
    if erro or not isinstance(cfg, dict) or not cfg.get("jwks_uri"):
        sair(INCONCLUSIVE, ["issuer discovery unavailable (%s)" % (erro or "no jwks_uri")])
    jwks, erro = _http_json(cfg["jwks_uri"])
    if erro or not isinstance(jwks, dict):
        sair(INCONCLUSIVE, ["key set unavailable (%s)" % (erro or "malformed")])

    estado, detalhe = _verificar_assinatura(token, jwks)
    factos["assinatura"] = "ok" if estado == "ok" else ("inconclusive" if estado == "inconclusive" else "mau")
    factos["assinatura_detalhe"] = detalhe

    api = "https://api.github.com/repos/%s" % repo
    info, erro = _http_json(api)
    if erro or not isinstance(info, dict) or not info.get("default_branch"):
        sair(INCONCLUSIVE, ["gate repository metadata unavailable (%s)" % (erro or "no default_branch")])
    ramo = info["default_branch"]
    factos["ramo_por_omissao"] = ramo

    binfo, erro = _http_json("%s/branches/%s" % (api, ramo))
    if erro or not isinstance(binfo, dict) or "protected" not in binfo:
        sair(INCONCLUSIVE, ["branch protection state unavailable (%s)" % (erro or "no field")])
    factos["ramo_protegido"] = bool(binfo["protected"])

    jws = claims.get("job_workflow_sha", "")
    if _hex40(jws):
        cmp_, erro = _http_json("%s/compare/%s...%s" % (api, jws, ramo))
        if erro or not isinstance(cmp_, dict) or not cmp_.get("status"):
            sair(INCONCLUSIVE, ["ancestry comparison unavailable (%s)" % (erro or "no status")])
        # `ahead` = the branch moved on from this commit; `identical` = it is the
        # tip. Both place the commit inside that history. `behind`/`diverged` do not.
        factos["na_historia_protegida"] = cmp_["status"] in ("identical", "ahead")
    else:
        factos["na_historia_protegida"] = False

    # The approved list is read from the PROTECTED branch, so changing it needs
    # the same review that protects the gate itself.
    conteudo, erro = _http_json("%s/contents/%s?ref=%s" % (api, FICHEIRO_APROVADOS, ramo))
    if erro or not isinstance(conteudo, dict) or not conteudo.get("content"):
        sair(INCONCLUSIVE, ["approved-SHA list unavailable (%s)" % (erro or "no content")])
    try:
        bruto = base64.b64decode(conteudo["content"])
        doc = json.loads(bruto)
        factos["aprovados"] = [e["sha"] for e in doc["approved"]]
    except Exception as e:
        sair(INCONCLUSIVE, ["approved-SHA list malformed (%s)" % type(e).__name__])

    try:
        estado, motivos = decidir(claims, factos, time.time())
    except Exception as e:
        # Any unexpected failure of the decision itself is inconclusive.
        sair(INCONCLUSIVE, ["decision raised %s" % type(e).__name__])

    print("FACT=gate_repository %s" % repo)
    print("FACT=default_branch %s protected=%s" % (ramo, factos["ramo_protegido"]))
    print("FACT=job_workflow_sha %s" % jws[:12])
    print("FACT=approved_count %d" % len(factos["aprovados"]))
    print("FACT=in_protected_history %s" % factos["na_historia_protegida"])
    print("FACT=signature %s %s" % (factos["assinatura"], factos["assinatura_detalhe"]))
    print("FACT=audience_matches %s" % (claims.get("aud") == AUDIENCIA_NORMATIVA))
    print("FACT=window_s %d" % (int(claims.get("exp", 0)) - int(claims.get("iat", 0))))
    sair(estado, motivos)


if __name__ == "__main__":
    main()
