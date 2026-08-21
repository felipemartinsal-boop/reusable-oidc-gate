"""Battery for the gate that ships in this repository.

It exercises `verify.py` from the repository root -- and also the copy actually
embedded in `gate.yml`, extracted from the workflow and run as a module, so the
thing proved is the thing that executes. The workflow does not download the
verifier: it materialises it from itself.

A battery that restated the logic would prove the restatement, so no rule is
written twice in here. And a synthetic positive control that signs with the
verifier's own DigestInfo constant proves only that the file agrees with itself,
which is why one fixed vector published by the IETF is included and why the
demonstration of that circularity is the first thing this file runs.

Everything is synthetic: throwaway RSA keys built in-process, claims written by
hand, and the RFC vector. No caller data, no real token, no network, no
dependencies.

Run:  python tests/bateria.py
"""

import base64
import hashlib
import importlib.util
import io
import json
import os
import re
import sys
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAMINHO_VERIFY = os.path.join(RAIZ, "verify.py")
CAMINHO_VETOR = os.path.join(RAIZ, "tests", "vetor-rfc7515-a2.json")

falhas = []
casos = 0


def registar(cid, desc, obtido, esperado, extra=""):
    global casos
    casos += 1
    ok = obtido == esperado
    print("  %-5s %-58s %-14s %s" % (cid, desc, obtido, "ok" if ok else "FALHA"))
    if not ok:
        falhas.append("%s (%s): esperado %s, obtido %s %s" % (cid, desc, esperado, obtido, extra))


def carregar(nome, fonte, ficheiro):
    """Executa uma fonte como modulo, sem a importar do disco."""
    spec = importlib.util.spec_from_loader(nome, loader=None)
    mod = importlib.util.module_from_spec(spec)
    mod.__file__ = ficheiro
    exec(compile(fonte, ficheiro, "exec"), mod.__dict__)
    return mod


def so_lf(texto):
    """CRLF e CR isolado passam a LF; a newline final deixa de contar.

    So' fins de linha. Um caractere trocado, uma linha reordenada ou um espaco
    a mais continuam a ser diferencas, e tem de continuar a reprovar -- senao
    esta normalizacao deixava de proteger o que existe para proteger.

    Existe porque a comparacao lia os dois lados de maneira diferente: verify.py
    com newline="" (preserva CRLF) e gate.yml em modo texto (converte para LF).
    Num checkout Windows isso punha CRLF contra LF e acusava 402 bytes de
    diferenca -- um por linha -- num conteudo identico.
    """
    return texto.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")


FONTE_VERIFY = io.open(CAMINHO_VERIFY, encoding="utf-8", newline="").read()
V = carregar("verify", FONTE_VERIFY, CAMINHO_VERIFY)

# --- a copia que o workflow materializa de facto ----------------------------
GATE = io.open(os.path.join(RAIZ, V.CAMINHO_GATE), encoding="utf-8").read()
_m = re.search(r"<<'FIM_DO_VERIFICADOR'\n(.*?)\n\s*FIM_DO_VERIFICADOR\n", GATE, re.S)
EMBUTIDO = None
FONTE_EMBUTIDA = ""
if _m:
    _linhas = _m.group(1).split("\n")
    _recuo = min((len(l) - len(l.lstrip()) for l in _linhas if l.strip()), default=0)
    FONTE_EMBUTIDA = "\n".join(l[_recuo:] if l.strip() else "" for l in _linhas) + "\n"
    EMBUTIDO = carregar("verify_embutido", FONTE_EMBUTIDA, "<gate.yml:heredoc>")

AGORA = int(time.time())
APROVADO = "a" * 40
ANCESTRAL = "b" * 40
NOVO = "c" * 40
REPO = "felipemartinsal-boop/reusable-oidc-gate"
CAMINHO_NO_REPO = "%s/%s" % (REPO, V.CAMINHO_GATE)
OUTRO_REPO = "atacante/repo-malicioso"


# ================================================ RSA sintetico, sem terceiros

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
    n &= (1 << bits) - 1
    # Os dois bits de topo ficam a 1 para o produto de dois primos ter mesmo
    # 2*bits bits. Sem isto o modulo saia com 2047 e a POLITICA do verificador
    # rejeitava a chave da propria bateria -- o teste apanhou-o.
    n |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1
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

    def assinar(self, dados, prefixo=None):
        # `prefixo` e' parametrizavel de proposito: e' o que permite demonstrar a
        # circularidade, assinando com a constante de um verificador mutado.
        t = (prefixo if prefixo is not None else V._PREFIXO_SHA256) + hashlib.sha256(dados).digest()
        em = b"\x00\x01" + b"\xff" * (self.k - len(t) - 3) + b"\x00" + t
        s = pow(int.from_bytes(em, "big"), self.d, self.n)
        return s.to_bytes(self.k, "big")


def b64u_int(n):
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()


def b64u_bytes(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def virar_bit(s):
    b = bytearray(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
    b[0] ^= 0x01
    return b64u_bytes(bytes(b))


CHAVE = Chave("bateria-1")
OUTRA = Chave("bateria-2")
JWKS = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
                  "n": b64u_int(CHAVE.n), "e": b64u_int(CHAVE.e)}]}


def emitir(chave=CHAVE, alg="RS256", kid="k1", corpo=None, adulterar=False, prefixo=None):
    cabeca = b64u_bytes(json.dumps({"alg": alg, "kid": kid}).encode())
    carga = b64u_bytes(json.dumps(corpo or {"a": 1}).encode())
    assinatura = chave.assinar(("%s.%s" % (cabeca, carga)).encode("ascii"), prefixo)
    if adulterar:
        b = bytearray(assinatura)
        b[0] ^= 0x01
        assinatura = bytes(b)
    return "%s.%s.%s" % (cabeca, carga, b64u_bytes(assinatura))


VETOR = json.load(io.open(CAMINHO_VETOR, encoding="utf-8"))


def token_vetor(assinatura=None, carga=None):
    return "%s.%s.%s" % (VETOR["protected_header_b64"],
                         carga if carga is not None else VETOR["payload_b64"],
                         assinatura if assinatura is not None else VETOR["signature_b64"])


def jwks_vetor(**alt):
    k = dict(VETOR["jwk"])
    k.update(alt)
    return {"keys": [k]}


# ==================================== 0. RED: o controlo sintetico e' circular
print("\n--- RED: porque um vetor externo e' obrigatorio ---")

FONTE_MUTADA = FONTE_VERIFY.replace(
    '_PREFIXO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")',
    '_PREFIXO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000421")')
assert FONTE_MUTADA != FONTE_VERIFY, "a constante do DigestInfo nao foi encontrada"
MUTADO = carregar("verify_digestinfo_mau", FONTE_MUTADA, "<DigestInfo mutado>")

# Assinado com a constante DO VERIFICADOR MUTADO -- exactamente o que acontece
# quando o emissor sintetico importa a constante de quem confere.
registar("R1", "verificador com DigestInfo errado aceita o sintetico dele",
         MUTADO.verificar_assinatura(emitir(prefixo=MUTADO._PREFIXO_SHA256), JWKS)[0], "ok",
         "e' este o falso verde que o vetor externo existe para apanhar")
registar("R2", "o MESMO verificador mutado reprova o vetor oficial",
         MUTADO.verificar_assinatura(token_vetor(), jwks_vetor())[0], "mau",
         "o vetor externo derruba a mutacao que o sintetico deixou passar")

# ========================= 1. vetor oficial RFC 7515 A.2, sem constantes nossas
print("\n--- vetor oficial: %s ---" % VETOR["fonte"])

registar("X1", "vetor oficial valido (POSITIVO externo)",
         V.verificar_assinatura(token_vetor(), jwks_vetor())[0], "ok")
registar("X2", "assinatura do vetor adulterada num bit",
         V.verificar_assinatura(token_vetor(assinatura=virar_bit(VETOR["signature_b64"])),
                                jwks_vetor())[0], "mau")
registar("X3", "payload do vetor adulterado",
         V.verificar_assinatura(token_vetor(carga=virar_bit(VETOR["payload_b64"])),
                                jwks_vetor())[0], "mau")
registar("X4", "chave do vetor adulterada (modulo)",
         V.verificar_assinatura(token_vetor(), jwks_vetor(n=virar_bit(VETOR["jwk"]["n"])))[0], "mau")
registar("X5", "expoente do vetor trocado por 3",
         V.verificar_assinatura(token_vetor(), jwks_vetor(e=b64u_int(3)))[0], "mau")
registar("X6", "o vetor tambem passa no codigo EMBUTIDO no gate.yml",
         EMBUTIDO.verificar_assinatura(token_vetor(), jwks_vetor())[0] if EMBUTIDO
         else "sem embutido", "ok")
registar("X7", "mutar o DigestInfo derruba o vetor externo",
         MUTADO.verificar_assinatura(token_vetor(), jwks_vetor())[0], "mau")

_PAD_ANTIGO = 'esperado = b"\\x00\\x01" + b"\\xff" * (k - len(t) - 3) + b"\\x00" + t'
_PAD_NOVO = 'esperado = b"\\x00\\x02" + b"\\xff" * (k - len(t) - 3) + b"\\x00" + t'
FONTE_PAD = FONTE_VERIFY.replace(_PAD_ANTIGO, _PAD_NOVO)
if FONTE_PAD != FONTE_VERIFY:
    PAD = carregar("verify_padding_mau", FONTE_PAD, "<padding mutado>")
    registar("X8", "mutar o padding derruba o vetor externo",
             PAD.verificar_assinatura(token_vetor(), jwks_vetor())[0], "mau")
else:
    registar("X8", "mutar o padding derruba o vetor externo", "padrao nao encontrado", "mau")

# ======================================================= 2. parametros RSA/JWK
print("\n--- parametros RSA/JWK: politica fechada ---")

registar("P1", "modulo abaixo do minimo normativo",
         V.verificar_assinatura(token_vetor(), jwks_vetor(n=b64u_int(2 ** 1023 + 1)))[0], "mau")
registar("P2", "expoente par",
         V.verificar_assinatura(token_vetor(), jwks_vetor(e=b64u_int(4)))[0], "mau")
registar("P3", "expoente 1",
         V.verificar_assinatura(token_vetor(), jwks_vetor(e=b64u_int(1)))[0], "mau")
registar("P4", "use=sig declarado e aceito",
         V.verificar_assinatura(token_vetor(), jwks_vetor(use="sig"))[0], "ok")
registar("P5", "use=enc declarado reprova",
         V.verificar_assinatura(token_vetor(), jwks_vetor(use="enc"))[0], "mau")
registar("P6", "modulo ilegivel e INCONCLUSIVO, nao rejeicao",
         V.verificar_assinatura(token_vetor(), jwks_vetor(n="!!!nao-e-base64!!!"))[0],
         "inconclusive")
registar("P7", "minimo normativo declarado no verificador",
         "sim" if getattr(V, "MODULO_MINIMO_BITS", 0) >= 2048 else "nao", "sim")
registar("P8", "o vetor oficial cumpre a politica declarada",
         "sim" if VETOR["propriedades_declaradas_pelo_rfc"]["modulo_bits"] >= V.MODULO_MINIMO_BITS
         else "nao", "sim")

# ================================================================ 3. assinatura
print("\n--- assinatura: casos sinteticos (dependem da nossa constante) ---")


def assinar_caso(cid, desc, token, jwks, esperado):
    registar(cid, desc, V.verificar_assinatura(token, jwks)[0], esperado)


assinar_caso("S1", "token sintetico valido", emitir(), JWKS, "ok")
assinar_caso("S2", "assinatura adulterada num byte", emitir(adulterar=True), JWKS, "mau")
assinar_caso("S3", "assinado por outra chave, mesmo kid", emitir(chave=OUTRA), JWKS, "mau")
assinar_caso("S4", "kid fora do conjunto", emitir(kid="desconhecido"), JWKS, "mau")
assinar_caso("S5", "alg=none", emitir(alg="none"), JWKS, "mau")
assinar_caso("S6", "alg=HS256", emitir(alg="HS256"), JWKS, "mau")
assinar_caso("S7", "alg=RS512 fora da allowlist", emitir(alg="RS512"), JWKS, "mau")
assinar_caso("S8", "alg ausente do cabecalho", emitir(alg=None), JWKS, "mau")
assinar_caso("S9", "JWKS sem chaves", emitir(), {"keys": []}, "inconclusive")
assinar_caso("S10", "JWKS malformado", emitir(), {"nao": "jwks"}, "inconclusive")
assinar_caso("S11", "chave declara outro algoritmo", emitir(),
             {"keys": [dict(JWKS["keys"][0], alg="RS512")]}, "mau")
assinar_caso("S12", "token nao e um JWS de tres partes", "abc.def", JWKS, "inconclusive")
assinar_caso("S13", "tipo de chave nao RSA", emitir(),
             {"keys": [dict(JWKS["keys"][0], kty="EC")]}, "inconclusive")
registar("S14", "allowlist tem so RS256", str(V.ALGORITMOS_PERMITIDOS), "('RS256',)")

# =================================================================== 4. decisao
print("\n--- decisao: pinagem exacta, audiencia, classificacao ---")


def claims(**k):
    base = {
        "iss": V.EMISSOR_NORMATIVO,
        "aud": V.AUDIENCIA_NORMATIVA,
        "iat": AGORA - 10,
        "exp": AGORA + 290,
        "job_workflow_ref": "%s@%s" % (CAMINHO_NO_REPO, APROVADO),
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


def decidir(c, f, mod=None):
    try:
        return (mod or V).decidir(c, f, AGORA)[0]
    except Exception as e:
        return "EXCECAO:" + type(e).__name__


registar("D1", "SHA aprovado, tudo em ordem (POSITIVO)", decidir(claims(), factos()), V.VERIFIED)
registar("D2", "SHA ancestral protegido, NAO aprovado (downgrade)",
         decidir(claims(job_workflow_ref="%s@%s" % (CAMINHO_NO_REPO, ANCESTRAL),
                        job_workflow_sha=ANCESTRAL), factos()), V.REJECTED)
registar("D3", "SHA mais novo na historia, nao aprovado",
         decidir(claims(job_workflow_ref="%s@%s" % (CAMINHO_NO_REPO, NOVO),
                        job_workflow_sha=NOVO), factos()), V.REJECTED)
registar("D4", "ref movel",
         decidir(claims(job_workflow_ref="%s@refs/heads/main" % CAMINHO_NO_REPO), factos()),
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
         decidir({k: x for k, x in claims().items() if k != "job_workflow_sha"}, factos()),
         V.INCONCLUSIVE)
registar("D15", "janela nao numerica", decidir(claims(exp="amanha"), factos()), V.INCONCLUSIVE)
registar("D16", "ramo do gate nao protegido", decidir(claims(), factos(ramo_protegido=False)),
         V.REJECTED)
registar("D17", "job_workflow_ref nomeia outro workflow",
         decidir(claims(job_workflow_ref="%s/.github/workflows/outro.yml@%s" % (REPO, APROVADO)),
                 factos()), V.REJECTED)
registar("D18", "runner nao hospedado pelo GitHub",
         decidir(claims(runner_environment="self-hosted"), factos()), V.REJECTED)
registar("D19", "a decisao EMBUTIDA concorda no caso positivo",
         decidir(claims(), factos(), EMBUTIDO) if EMBUTIDO else "sem embutido", V.VERIFIED)
registar("D20", "a decisao EMBUTIDA concorda no downgrade",
         decidir(claims(job_workflow_ref="%s@%s" % (CAMINHO_NO_REPO, ANCESTRAL),
                        job_workflow_sha=ANCESTRAL), factos(), EMBUTIDO)
         if EMBUTIDO else "sem embutido", V.REJECTED)

# ==================================================== 5. bootstrap malicioso
print("\n--- bootstrap: o payload nao escolhe o codigo ---")

registar("B1", "payload aponta para outro repositorio",
         decidir(claims(job_workflow_ref="%s/%s@%s" % (OUTRO_REPO, V.CAMINHO_GATE, APROVADO)),
                 factos()), V.REJECTED)
registar("B2", "payload aponta para outro repo E outro SHA",
         decidir(claims(job_workflow_ref="%s/%s@%s" % (OUTRO_REPO, V.CAMINHO_GATE, NOVO),
                        job_workflow_sha=NOVO), factos()), V.REJECTED)
registar("B3", "sem repositorio esperado fixado -> INCONCLUSIVE",
         decidir(claims(), factos(repositorio_esperado=None)), V.INCONCLUSIVE)
registar("B4", "o gate nao busca codigo de lado nenhum",
         "sim" if not re.search(r"raw\.githubusercontent|curl[^\n]*\.py|git clone|actions/checkout",
                                GATE) else "nao", "sim")
registar("B5", "o workflow embute um verificador", "sim" if EMBUTIDO else "nao", "sim")
registar("B6", "o embutido e igual a verify.py (fins de linha normalizados)",
         "igual" if _m and so_lf(FONTE_EMBUTIDA) == so_lf(FONTE_VERIFY) else "divergente", "igual",
         "embutido=%d bytes, ficheiro=%d bytes" % (len(FONTE_EMBUTIDA), len(FONTE_VERIFY)))

# --- portabilidade dos fins de linha: casos crafted, sem tocar no disco ------
# O B6 acima compara ficheiros reais. Estes provam que a normalizacao aceita as
# quatro formas de fim de linha E continua a recusar diferencas de conteudo.
_BASE = "linha um\nlinha dois\nlinha tres\n"
registar("B6a", "LF contra LF", "igual" if so_lf(_BASE) == so_lf(_BASE) else "divergente", "igual")
registar("B6b", "CRLF contra LF",
         "igual" if so_lf(_BASE.replace("\n", "\r\n")) == so_lf(_BASE) else "divergente", "igual")
registar("B6c", "CR isolado contra LF",
         "igual" if so_lf(_BASE.replace("\n", "\r")) == so_lf(_BASE) else "divergente", "igual")
registar("B6d", "sem newline final contra com newline final",
         "igual" if so_lf(_BASE.rstrip("\n")) == so_lf(_BASE) else "divergente", "igual")
registar("B6e", "misto CRLF/LF/CR contra LF",
         "igual" if so_lf("linha um\r\nlinha dois\rlinha tres\n") == so_lf(_BASE)
         else "divergente", "igual")
registar("B6f", "MUTACAO de conteudo continua a reprovar",
         "igual" if so_lf(_BASE.replace("dois", "DOIS")) == so_lf(_BASE) else "divergente",
         "divergente")
registar("B6g", "linha reordenada continua a reprovar",
         "igual" if so_lf("linha dois\nlinha um\nlinha tres\n") == so_lf(_BASE)
         else "divergente", "divergente")
registar("B6h", "espaco a mais continua a reprovar",
         "igual" if so_lf("linha um \nlinha dois\nlinha tres\n") == so_lf(_BASE)
         else "divergente", "divergente")
registar("B6i", "linha em falta continua a reprovar",
         "igual" if so_lf("linha um\nlinha tres\n") == so_lf(_BASE) else "divergente",
         "divergente")
# Normaliza ANTES de injectar: num checkout CRLF o ficheiro ja vem com \r\n, e
# injectar outra vez daria \r\r\n -- que nao e' fim de linha nenhum, e' conteudo
# novo. Sem isto o caso reprovava por uma razao que nao tem que ver com o que
# ele existe para provar.
registar("B6j", "o verify.py real, com CRLF injectado, continua igual",
         "igual" if so_lf(so_lf(FONTE_VERIFY).replace("\n", "\r\n")) == so_lf(FONTE_VERIFY)
         else "divergente", "igual")
registar("B6k", "o verify.py real, com um byte trocado, reprova",
         "igual" if so_lf(FONTE_VERIFY.replace("VERIFIED", "VERIFIEX", 1)) == so_lf(FONTE_VERIFY)
         else "divergente", "divergente")

_passo = GATE.split("Materialise the embedded verifier")[1].split("- name:")[0]
_comandos = re.sub(r"<<'FIM_DO_VERIFICADOR'.*?FIM_DO_VERIFICADOR", "", _passo, flags=re.S)
registar("B7", "os comandos que embutem nao leem o token nem claims",
         "sim" if not re.search(r"job_workflow_ref|ACTIONS_ID_TOKEN|GATE_TOKEN|jq ", _comandos)
         else "nao", "sim")
registar("B8", "o workflow fixa o repositorio esperado",
         "sim" if "GATE_EXPECTED_REPO" in GATE else "nao", "sim")
_efectivas = "\n".join(l for l in GATE.split("\n") if not l.lstrip().startswith("#"))
_efectivas = re.sub(r"<<'FIM_DO_VERIFICADOR'.*?FIM_DO_VERIFICADOR", "", _efectivas, flags=re.S)
registar("B9", "nenhuma linha efectiva usa o commit do chamador",
         "sim" if not re.search(r"GITHUB_WORKFLOW_SHA|github\.workflow_sha", _efectivas) else "nao",
         "sim")
registar("B10", "o workflow nao instala dependencias em tempo de execucao",
         "nao" if "pip install" in GATE else "sim", "sim")
registar("B11", "o verificador nao importa terceiros",
         "sim" if not re.search(r"^\s*(import|from)\s+(jwt|cryptography|requests|httpx)",
                                FONTE_VERIFY, re.M) else "nao", "sim")

# ===================================================================== resumo
print("\n%d casos" % casos)
if falhas:
    print("\nBATERIA REPROVOU:")
    for f in falhas:
        print("  - " + f)
    sys.exit(1)
print("BATERIA PASSOU: todos os casos com o resultado esperado")
