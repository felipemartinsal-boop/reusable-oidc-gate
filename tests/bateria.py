"""Battery for the gate that ships in this repository.

It imports `verify.py` from the repository root -- the same file the workflow
downloads and runs. A battery that restated the logic would prove the
restatement, so there is no second copy of a rule anywhere in here.

Everything is synthetic: a throwaway RSA key generated in-process, a JWKS built
from it, and claims written by hand. No caller data, no real token, no network.

Run:  python tests/bateria.py
"""

import base64
import hashlib
import importlib.util
import json
import os
import re
import sys
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAMINHO_VERIFY = os.path.join(RAIZ, "verify.py")

_spec = importlib.util.spec_from_file_location("verify", CAMINHO_VERIFY)
V = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(V)

AGORA = int(time.time())
APROVADO = "a" * 40
ANCESTRAL = "b" * 40
NOVO = "c" * 40
REPO = "felipemartinsal-boop/reusable-oidc-gate"
GATE = "%s/%s" % (REPO, V.CAMINHO_GATE)
OUTRO_REPO = "atacante/repo-malicioso"

falhas = []
casos = 0


def registar(cid, desc, obtido, esperado, extra=""):
    global casos
    casos += 1
    ok = obtido == esperado
    print("  %-5s %-56s %-14s %s" % (cid, desc, obtido, "ok" if ok else "FALHA"))
    if not ok:
        falhas.append("%s (%s): esperado %s, obtido %s %s" % (cid, desc, esperado, obtido, extra))


# --------------------------------------------------------------- RSA em stdlib
# Chave descartavel gerada aqui, sem dependencias: dois primos e o inverso
# modular. Serve para assinar tokens de teste com o mesmo esquema que o gate
# verifica.

def _primo(bits, semente):
    def e_primo(n):
        if n % 2 == 0:
            return False
        for p in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if n % p == 0:
                return n == p
        d, r = n - 1, 0
        while d % 2 == 0:
            d //= 2
            r += 1
        for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(r - 1):
                x = x * x % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    n = int.from_bytes(hashlib.sha512((semente + str(bits)).encode()).digest() * (bits // 512 + 1), "big")
    n |= (1 << (bits - 1)) | 1
    n &= (1 << bits) - 1
    n |= (1 << (bits - 1)) | 1
    while not e_primo(n):
        n += 2
    return n


class Chave:
    def __init__(self, semente):
        p = _primo(1024, semente + "-p")
        q = _primo(1024, semente + "-q")
        self.n = p * q
        self.e = 65537
        self.d = pow(self.e, -1, (p - 1) * (q - 1))
        self.k = (self.n.bit_length() + 7) // 8

    def assinar(self, dados):
        t = V._PREFIXO_SHA256 + hashlib.sha256(dados).digest()
        em = b"\x00\x01" + b"\xff" * (self.k - len(t) - 3) + b"\x00" + t
        s = pow(int.from_bytes(em, "big"), self.d, self.n)
        return s.to_bytes(self.k, "big")


def b64u_int(n):
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_bytes(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


CHAVE = Chave("bateria-1")
OUTRA = Chave("bateria-2")
JWKS = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
                  "n": b64u_int(CHAVE.n), "e": b64u_int(CHAVE.e)}]}


def emitir(chave=CHAVE, alg="RS256", kid="k1", corpo=None, adulterar=False):
    cabeca = b64u_bytes(json.dumps({"alg": alg, "kid": kid}).encode())
    carga = b64u_bytes(json.dumps(corpo or {"a": 1}).encode())
    assinatura = chave.assinar(("%s.%s" % (cabeca, carga)).encode("ascii"))
    if adulterar:
        b = bytearray(assinatura)
        b[0] ^= 0x01
        assinatura = bytes(b)
    return "%s.%s.%s" % (cabeca, carga, b64u_bytes(assinatura))


# ------------------------------------------------------------------- fixtures

def claims(**k):
    base = {
        "iss": V.EMISSOR_NORMATIVO,
        "aud": V.AUDIENCIA_NORMATIVA,
        "iat": AGORA - 10,
        "exp": AGORA + 290,
        "job_workflow_ref": "%s@%s" % (GATE, APROVADO),
        "job_workflow_sha": APROVADO,
        "run_id": "1",
        "run_attempt": "1",
        "runner_environment": "github-hosted",
    }
    base.update(k)
    return base


def factos(**k):
    base = {
        "assinatura": "ok",
        "assinatura_detalhe": "",
        "aprovados": [APROVADO],
        "ramo_por_omissao": "main",
        "ramo_protegido": True,
        "na_historia_protegida": True,
        "repositorio_esperado": REPO,
    }
    base.update(k)
    return base


def decidir(c, f):
    try:
        estado, _ = V.decidir(c, f, AGORA)
        return estado
    except Exception as e:
        return "EXCECAO:" + type(e).__name__


# ============================================================== 1. assinatura
print("\n--- assinatura, contra a implementacao stdlib enviada ---")


def assinar_caso(cid, desc, token, jwks, esperado):
    estado, detalhe = V.verificar_assinatura(token, jwks)
    registar(cid, desc, estado, esperado, detalhe)


assinar_caso("S1", "token valido (POSITIVO)", emitir(), JWKS, "ok")
assinar_caso("S2", "assinatura adulterada num byte", emitir(adulterar=True), JWKS, "mau")
assinar_caso("S3", "assinado por outra chave, mesmo kid", emitir(chave=OUTRA), JWKS, "mau")
assinar_caso("S4", "kid fora do conjunto", emitir(kid="desconhecido"), JWKS, "mau")
assinar_caso("S5", "alg=none", emitir(alg="none"), JWKS, "mau")
assinar_caso("S6", "alg=HS256", emitir(alg="HS256"), JWKS, "mau")
assinar_caso("S7", "alg=RS512 (nao esta na allowlist)", emitir(alg="RS512"), JWKS, "mau")
assinar_caso("S8", "alg ausente do cabecalho", emitir(alg=None), JWKS, "mau")
assinar_caso("S9", "JWKS sem chaves", emitir(), {"keys": []}, "inconclusive")
assinar_caso("S10", "JWKS malformado", emitir(), {"nao": "jwks"}, "inconclusive")
assinar_caso("S11", "chave declara outro algoritmo", emitir(),
             {"keys": [dict(JWKS["keys"][0], alg="RS512")]}, "mau")
assinar_caso("S12", "token nao e um JWS de tres partes", "abc.def", JWKS, "inconclusive")
assinar_caso("S13", "tipo de chave nao RSA", emitir(),
             {"keys": [dict(JWKS["keys"][0], kty="EC")]}, "inconclusive")

# ================================================================= 2. decisao
print("\n--- decisao: pinagem exacta, audiencia, classificacao ---")

registar("D1", "SHA aprovado, tudo em ordem (POSITIVO)", decidir(claims(), factos()), V.VERIFIED)
registar("D2", "SHA ancestral protegido, NAO aprovado (downgrade)",
         decidir(claims(job_workflow_ref="%s@%s" % (GATE, ANCESTRAL), job_workflow_sha=ANCESTRAL),
                 factos()), V.REJECTED)
registar("D3", "SHA mais novo na historia, nao aprovado",
         decidir(claims(job_workflow_ref="%s@%s" % (GATE, NOVO), job_workflow_sha=NOVO),
                 factos()), V.REJECTED)
registar("D4", "ref movel", decidir(claims(job_workflow_ref="%s@refs/heads/main" % GATE), factos()),
         V.REJECTED)
registar("D5", "aprovado mas fora da historia protegida",
         decidir(claims(), factos(na_historia_protegida=False)), V.REJECTED)
registar("D6", "audiencia alterada", decidir(claims(aud="outra"), factos()), V.REJECTED)
registar("D7", "emissor errado", decidir(claims(iss="https://falso"), factos()), V.REJECTED)
registar("D8", "token expirado", decidir(claims(iat=AGORA - 3600, exp=AGORA - 3000), factos()),
         V.REJECTED)
registar("D9", "assinatura ma", decidir(claims(), factos(assinatura="mau")), V.REJECTED)
registar("D10", "JWKS vazio -> INCONCLUSIVE, nao REJECTED",
         decidir(claims(), factos(assinatura="inconclusive")), V.INCONCLUSIVE)
registar("D11", "lista de aprovados vazia", decidir(claims(), factos(aprovados=[])), V.INCONCLUSIVE)
registar("D12", "lista de aprovados malformada", decidir(claims(), factos(aprovados="x")),
         V.INCONCLUSIVE)
registar("D13", "resposta sem ramo por omissao", decidir(claims(), factos(ramo_por_omissao=None)),
         V.INCONCLUSIVE)
registar("D14", "claim em falta",
         decidir({k: v for k, v in claims().items() if k != "job_workflow_sha"}, factos()),
         V.INCONCLUSIVE)
registar("D15", "janela nao numerica", decidir(claims(exp="amanha"), factos()), V.INCONCLUSIVE)
registar("D16", "ramo do gate nao protegido", decidir(claims(), factos(ramo_protegido=False)),
         V.REJECTED)
registar("D17", "job_workflow_ref nomeia outro workflow",
         decidir(claims(job_workflow_ref="%s/.github/workflows/outro.yml@%s" % (REPO, APROVADO)),
                 factos()), V.REJECTED)
registar("D18", "runner nao hospedado pelo GitHub",
         decidir(claims(runner_environment="self-hosted"), factos()), V.REJECTED)

# ===================================================== 3. bootstrap malicioso
print("\n--- bootstrap malicioso: o payload nao escolhe o codigo ---")

registar("B1", "payload aponta para outro repositorio",
         decidir(claims(job_workflow_ref="%s/%s@%s" % (OUTRO_REPO, V.CAMINHO_GATE, APROVADO)),
                 factos()), V.REJECTED)
registar("B2", "payload aponta para outro repo E outro SHA",
         decidir(claims(job_workflow_ref="%s/%s@%s" % (OUTRO_REPO, V.CAMINHO_GATE, NOVO),
                        job_workflow_sha=NOVO), factos()), V.REJECTED)
registar("B3", "o workflow nao fixou repositorio esperado -> INCONCLUSIVE",
         decidir(claims(), factos(repositorio_esperado=None)), V.INCONCLUSIVE)

# O gate nao pode construir o URL do verificador a partir do token. Isto le o
# workflow enviado e exige-o, porque nenhum teste da decisao pode provar uma
# propriedade do bootstrap.
gate = open(os.path.join(RAIZ, V.CAMINHO_GATE), encoding="utf-8").read()

# O URL so pode interpolar nomes cuja origem seja constante deste ficheiro ou
# da plataforma. Qualquer outro nome ali seria uma via para o payload escolher
# de onde vem o codigo.
NOMES_PERMITIDOS = {"GATE_EXPECTED_REPO", "sha"}  # `sha` vem de COMMIT_DO_GATE
urls = re.findall(r"raw\.githubusercontent\.com/[^\"'\s]*", gate)
nomes = set()
for u in urls:
    nomes |= set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", u))
registar("B4", "URL do verificador so interpola constantes conhecidas",
         "sim" if urls and nomes and nomes <= NOMES_PERMITIDOS else "nao", "sim",
         "urls=%s nomes=%s" % (urls, sorted(nomes)))

# E `sha` tem de vir da plataforma, nao do token.
# O commit tem de vir do contexto que descreve o workflow CHAMADO. Medido: o
# `github.workflow_sha` descreve o CHAMADOR, e usa-lo fazia o gate buscar o
# proprio verificador no commit do chamador -- 404 em todas as chamadas.
registar("B4b", "o commit do gate vem de github.job_workflow_sha",
         "sim" if re.search(r"COMMIT_DO_GATE:\s*\$\{\{\s*github\.job_workflow_sha\s*\}\}", gate)
         else "nao", "sim")
registar("B4d", "o commit do chamador nao e usado para buscar nada",
         "sim" if "COMMIT_DO_CHAMADOR" in gate
         and not re.search(r"raw\.githubusercontent\.com/[^\"']*COMMIT_DO_CHAMADOR", gate)
         else "nao", "sim")

# O passo que busca o verificador nao pode tocar no token.
passo_fonte = gate.split("Fetch the pinned verifier")[1].split("- name:")[0]
registar("B4c", "o passo da busca nao le o token nem claims",
         "sim" if not re.search(r"job_workflow_ref|ACTIONS_ID_TOKEN|GATE_TOKEN|jq", passo_fonte) else "nao",
         "sim")
registar("B5", "o workflow fixa o repositorio esperado",
         "sim" if "GATE_EXPECTED_REPO" in gate else "nao", "sim")
registar("B6", "o workflow verifica o digest do verificador antes de o correr",
         "sim" if "VERIFY_SHA256" in gate and "sha256sum" in gate else "nao", "sim")
registar("B7", "o workflow nao instala dependencias em tempo de execucao",
         "nao" if "pip install" in gate else "sim", "sim")
registar("B8", "o verificador nao importa terceiros",
         "sim" if not re.search(r"^\s*(import|from)\s+(jwt|cryptography|requests)",
                                open(CAMINHO_VERIFY, encoding="utf-8").read(), re.M) else "nao", "sim")

# =========================================== 4. digest fixado bate com o ficheiro
print("\n--- integridade: o digest fixado descreve o ficheiro enviado ---")

m = re.search(r"VERIFY_SHA256:\s*([0-9a-f]{64})", gate)
digest_ficheiro = hashlib.sha256(open(CAMINHO_VERIFY, "rb").read()).hexdigest()
registar("I1", "VERIFY_SHA256 esta fixado no workflow", "sim" if m else "nao", "sim")
if m:
    registar("I2", "o digest fixado bate com verify.py",
             "bate" if m.group(1) == digest_ficheiro else "divergente", "bate",
             "fixado=%s ficheiro=%s" % (m.group(1)[:12], digest_ficheiro[:12]))

# ===================================================================== resumo
print("\n%d casos" % casos)
if falhas:
    print("\nBATERIA REPROVOU:")
    for f in falhas:
        print("  - " + f)
    sys.exit(1)
print("BATERIA PASSOU: todos os casos com o resultado esperado")
