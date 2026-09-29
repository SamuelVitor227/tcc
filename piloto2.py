"""
Estudo piloto V2 - prompt com as categorias de CWE explicitadas
TCC - Analise Comparativa entre Ferramentas SAST e Modelos de Linguagem

Le casos do OWASP Benchmark for Java v1.2, submete cada um ao modelo via
Ollama, confronta a resposta com o gabarito e mede tempo de execucao.

Uso:
    python piloto2.py                         # 30 casos, modelo padrao
    python piloto.py --n 50                   # 50 casos
    python piloto.py --modelo llama3.1:8b     # outro modelo
"""

import argparse
import csv
import json
import random
import re
import time
from collections import Counter, defaultdict
from pathlib import Path

import requests

# --------------------------------------------------------------------------
# CONFIGURACAO
# --------------------------------------------------------------------------

BASE = Path(__file__).resolve().parent        # pasta onde este script esta
TESTCODE = BASE / "testcode"
GABARITO = BASE / "expectedresults-1.2.csv"
SAIDA = BASE / "resultados"

OLLAMA = "http://localhost:11434/api/generate"
MODELO_PADRAO = "qwen2.5-coder:14b"
TEMPERATURA = 0
TIMEOUT = 300
SEMENTE = 42                                  # amostragem reproduzivel

# --------------------------------------------------------------------------
# PROMPT  (fixo - reproduzir em apendice conforme a metodologia)
# --------------------------------------------------------------------------

PROMPT = """Analise o código Java a seguir e determine se ele contém alguma das seguintes vulnerabilidades:

- CWE-22: path traversal
- CWE-78: injeção de comando de sistema operacional
- CWE-79: cross-site scripting
- CWE-89: injeção de SQL
- CWE-90: injeção de LDAP
- CWE-327: uso de algoritmo criptográfico quebrado ou arriscado
- CWE-328: uso de hash criptográfico fraco
- CWE-330: uso de valores insuficientemente aleatórios
- CWE-501: violação de fronteira de confiança
- CWE-614: cookie sensível sem o atributo Secure
- CWE-643: injeção de XPath

Considere vulnerável apenas o código em que a entrada não confiável alcança a operação sensível sem sanitização ou validação adequada. Se houver tratamento que neutralize a entrada, o código não é vulnerável.

Responda exclusivamente com um objeto JSON no formato:
{{"vulnerable": true, "cwe": 89}}
ou
{{"vulnerable": false, "cwe": null}}

O campo "cwe" deve conter o identificador numérico da CWE correspondente à vulnerabilidade encontrada, ou null caso não haja vulnerabilidade. Não inclua explicação, comentários, marcação markdown ou qualquer texto fora do objeto JSON.

Código:
{codigo}"""

# --------------------------------------------------------------------------


def carregar_gabarito():
    """Le expectedresults-1.2.csv -> {caso: (vulneravel, cwe, categoria)}"""
    gab = {}
    with open(GABARITO, encoding="utf-8") as f:
        for linha in csv.reader(f):
            if not linha or linha[0].startswith("#"):
                continue
            nome, categoria, real, cwe = linha[0], linha[1], linha[2], linha[3]
            gab[nome.strip()] = (real.strip().lower() == "true",
                                 int(cwe.strip()),
                                 categoria.strip())
    return gab


def amostra_estratificada(gabarito, n):
    """Amostra equilibrada por categoria de CWE e por rotulo verdadeiro/falso."""
    grupos = defaultdict(list)
    for caso, (vuln, cwe, cat) in gabarito.items():
        grupos[(cat, vuln)].append(caso)

    rnd = random.Random(SEMENTE)
    for casos in grupos.values():
        rnd.shuffle(casos)

    selecionados, i = [], 0
    chaves = sorted(grupos.keys())
    while len(selecionados) < n:
        avancou = False
        for chave in chaves:
            if i < len(grupos[chave]) and len(selecionados) < n:
                selecionados.append(grupos[chave][i])
                avancou = True
        if not avancou:
            break
        i += 1
    return selecionados


def consultar(modelo, codigo):
    """Envia o caso ao modelo. Retorna (texto_bruto, segundos)."""
    payload = {
        "model": modelo,
        "prompt": PROMPT.format(codigo=codigo),
        "stream": False,
        "options": {"temperature": TEMPERATURA},
    }
    inicio = time.perf_counter()
    r = requests.post(OLLAMA, json=payload, timeout=TIMEOUT)
    decorrido = time.perf_counter() - inicio
    r.raise_for_status()
    return r.json().get("response", ""), decorrido


def interpretar(texto):
    """Extrai {vulnerable, cwe} da resposta. Retorna None se nao parsear."""
    limpo = re.sub(r"```(?:json)?|```", "", texto).strip()
    match = re.search(r"\{[^{}]*\}", limpo, re.DOTALL)
    if not match:
        return None
    try:
        dado = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    if "vulnerable" not in dado:
        return None
    cwe = dado.get("cwe")
    try:
        cwe = int(cwe) if cwe is not None else None
    except (TypeError, ValueError):
        cwe = None
    return {"vulnerable": bool(dado["vulnerable"]), "cwe": cwe}


def classificar(resposta, vuln_real, cwe_real):
    """Classifica segundo o criterio do OWASP Benchmark.

    Aponta vulnerabilidade da CWE esperada:
      - caso real     -> TP
      - caso negativo -> FP
    Nao aponta (ou aponta CWE divergente):
      - caso real     -> FN
      - caso negativo -> TN
    """
    if resposta is None:
        return "ERRO"
    apontou = resposta["vulnerable"] and resposta["cwe"] == cwe_real
    if vuln_real:
        return "TP" if apontou else "FN"
    return "FP" if apontou else "TN"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30, help="numero de casos")
    ap.add_argument("--modelo", default=MODELO_PADRAO)
    args = ap.parse_args()

    SAIDA.mkdir(parents=True, exist_ok=True)
    gabarito = carregar_gabarito()
    print(f"Gabarito carregado: {len(gabarito)} casos")

    casos = amostra_estratificada(gabarito, args.n)
    print(f"Amostra: {len(casos)} casos | Modelo: {args.modelo}\n")

    bruto = SAIDA / f"bruto_v2_{args.modelo.replace(':', '_')}.jsonl"
    contagem, tempos, erros = Counter(), [], 0

    with open(bruto, "w", encoding="utf-8") as saida:
        for i, caso in enumerate(casos, 1):
            arquivo = TESTCODE / f"{caso}.java"
            if not arquivo.exists():
                print(f"  ! {caso}.java nao encontrado")
                continue

            codigo = arquivo.read_text(encoding="utf-8", errors="replace")
            vuln_real, cwe_real, categoria = gabarito[caso]

            try:
                texto, segundos = consultar(args.modelo, codigo)
            except Exception as e:
                print(f"  ! {caso}: {e}")
                erros += 1
                continue

            resposta = interpretar(texto)
            classe = classificar(resposta, vuln_real, cwe_real)
            contagem[classe] += 1
            tempos.append(segundos)

            # saida bruta persistida antes de qualquer processamento
            saida.write(json.dumps({
                "caso": caso, "categoria": categoria,
                "vuln_real": vuln_real, "cwe_real": cwe_real,
                "resposta_bruta": texto, "resposta_parseada": resposta,
                "classe": classe, "segundos": round(segundos, 2),
            }, ensure_ascii=False) + "\n")

            print(f"[{i:3}/{len(casos)}] {caso} {categoria:14} "
                  f"{classe:4} {segundos:6.1f}s")

    # ---------------- relatorio ----------------
    tp, fp, tn, fn = (contagem["TP"], contagem["FP"],
                      contagem["TN"], contagem["FN"])
    total = tp + fp + tn + fn

    print("\n" + "=" * 58)
    print(f"Modelo: {args.modelo}")
    print(f"Classificados: {total} | Falhas de parse: {contagem['ERRO']} "
          f"| Erros de chamada: {erros}")
    print(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}")

    if tp + fn and fp + tn:
        tpr = tp / (tp + fn)
        fpr = fp / (fp + tn)
        prec = tp / (tp + fp) if tp + fp else 0.0
        f1 = 2 * prec * tpr / (prec + tpr) if prec + tpr else 0.0
        print(f"\nTPR (recall)    : {tpr:.3f}")
        print(f"FPR             : {fpr:.3f}")
        print(f"Precisao        : {prec:.3f}")
        print(f"F1-score        : {f1:.3f}")
        print(f"Benchmark Score : {(tpr - fpr) * 100:.1f}")

    if tempos:
        media = sum(tempos) / len(tempos)
        ordenado = sorted(tempos)
        mediana = ordenado[len(ordenado) // 2]
        print(f"\nTempo/caso  media {media:.1f}s | mediana {mediana:.1f}s "
              f"| min {ordenado[0]:.1f}s | max {ordenado[-1]:.1f}s")
        h = 2740 * media / 3600
        print(f"\nEXTRAPOLACAO")
        print(f"  2.740 casos, 1 repeticao .......... {h:.1f} h")
        print(f"  2.740 casos, 3 repeticoes ......... {h * 3:.1f} h")
        print(f"  3 modelos, 3 repeticoes ........... {h * 9:.1f} h")

    print(f"\nSaida bruta: {bruto}")
    print("=" * 58)


if __name__ == "__main__":
    main()
