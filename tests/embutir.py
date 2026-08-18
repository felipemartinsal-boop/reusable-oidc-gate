"""Regenerates the verifier embedded in gate.yml from verify.py.

The workflow carries its own copy of the verifier so that nothing is fetched at
run time. That copy is a build artifact: this is the generator, and
tests/bateria.py refuses any divergence of a single byte.

Run after editing verify.py:

    python tests/embutir.py

It rewrites only the block between the heredoc markers and leaves the rest of
gate.yml untouched.
"""

import io
import os
import re
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAMINHO_VERIFY = os.path.join(RAIZ, "verify.py")
CAMINHO_GATE = os.path.join(RAIZ, ".github", "workflows", "gate.yml")
INDENT = " " * 10
INICIO = "<<'FIM_DO_VERIFICADOR'\n"
FIM = "\n          FIM_DO_VERIFICADOR\n"


def main():
    verificador = io.open(CAMINHO_VERIFY, encoding="utf-8", newline="").read()
    gate = io.open(CAMINHO_GATE, encoding="utf-8", newline="").read()

    i = gate.find(INICIO)
    if i < 0:
        print("FALHA: marcador de inicio do heredoc nao encontrado em gate.yml")
        return 1
    j = gate.find(FIM, i)
    if j < 0:
        print("FALHA: marcador de fim do heredoc nao encontrado em gate.yml")
        return 1

    # O bloco YAML remove a indentacao comum, portanto indentar aqui devolve o
    # ficheiro byte a byte no runner. Linhas vazias ficam vazias -- espacos em
    # branco a mais mudariam os bytes.
    corpo = "\n".join((INDENT + l) if l.strip() else ""
                      for l in verificador.rstrip("\n").split("\n"))

    novo = gate[:i + len(INICIO)] + corpo + gate[j:]
    if novo == gate:
        print("gate.yml ja continha exactamente este verificador")
        return 0
    io.open(CAMINHO_GATE, "w", encoding="utf-8", newline="\n").write(novo)
    print("gate.yml actualizado: %d linhas embutidas de verify.py" %
          len(verificador.rstrip("\n").split("\n")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
