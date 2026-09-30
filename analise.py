"""
Analise dos resultados do corpus completo (prompt com CWEs)
TCC - Analise Comparativa entre Ferramentas SAST e Modelos de Linguagem

Le resultados/bruto_v2_*.jsonl (somente leitura) e gera em resultados/analise/:
    consolidado.csv / .tex     - uma linha por modelo, metricas agregadas
    por_cwe.csv / .tex         - uma linha por categoria, TPR e FPR de cada modelo
    tempo.csv / .tex           - tempo mediano, medio e total por modelo
    concordancia_qwen.csv      - casos em que Qwen 14B e 7B divergiram

Uso:
    python analise.py
"""

import csv
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path

BASE = Path(__file__).resolve().parent
RESULTADOS = BASE / "resultados"
SAIDA = RESULTADOS / "analise"
GABARITO = BASE / "expectedresults-1.2.csv"
TOTAL_CASOS = 2740

NOMES = {
    "qwen2.5-coder_14b": "Qwen2.5-Coder 14B",
    "qwen2.5-coder_7b": "Qwen2.5-Coder 7B",
    "llama3.1_8b": "Llama 3.1 8B",
}

CATEGORIAS = {
    22: "Path traversal", 78: "Injeção de comando", 79: "XSS",
    89: "Injeção de SQL", 90: "Injeção de LDAP", 327: "Criptografia fraca",
    328: "Hash fraco", 330: "Aleatoriedade fraca",
    501: "Fronteira de confiança", 614: "Cookie inseguro", 643: "Injeção de XPath",
}

QWEN_14B, QWEN_7B = "qwen2.5-coder_14b", "qwen2.5-coder_7b"


# --------------------------------------------------------------------------
# leitura
# --------------------------------------------------------------------------

def carregar_modelos():
    """{chave_modelo: {caso: registro}} a partir de bruto_v2_*.jsonl."""
    modelos = {}
    for arquivo in sorted(RESULTADOS.glob("bruto_v2_*.jsonl")):
        chave = arquivo.stem.removeprefix("bruto_v2_")
        with open(arquivo, encoding="utf-8") as f:
            registros = [json.loads(l) for l in f if l.strip()]
        casos = {r["caso"]: r for r in registros}
        if len(casos) != TOTAL_CASOS:
            print(f"AVISO: {arquivo.name} tem {len(casos)} casos "
                  f"(esperado {TOTAL_CASOS})")
        modelos[chave] = casos
    ordem = list(NOMES)
    return dict(sorted(modelos.items(),
                       key=lambda kv: ordem.index(kv[0]) if kv[0] in ordem
                       else len(ordem)))


def nome(chave):
    return NOMES.get(chave, chave)


# --------------------------------------------------------------------------
# metricas
# --------------------------------------------------------------------------

def metricas(registros):
    c = Counter(r["classe"] for r in registros)
    tp, fp, tn, fn = c["TP"], c["FP"], c["TN"], c["FN"]
    tpr = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * prec * tpr / (prec + tpr) if prec + tpr else 0.0
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "ERRO": c["ERRO"],
            "TPR": tpr, "FPR": fpr, "Precisao": prec, "F1": f1,
            "Score": (tpr - fpr) * 100}


def por_categoria(casos):
    grupos = defaultdict(list)
    for r in casos.values():
        grupos[r["cwe_real"]].append(r)
    return {cwe: metricas(regs) for cwe, regs in sorted(grupos.items())}


def score_oficial(cats):
    """Media do (TPR - FPR) entre categorias, como no scorecard do OWASP."""
    return statistics.mean(m["TPR"] - m["FPR"] for m in cats.values()) * 100


# --------------------------------------------------------------------------
# exportacao
# --------------------------------------------------------------------------

def br(valor, casas=3):
    """Numero com virgula decimal, para o LaTeX do artigo."""
    return f"{valor:.{casas}f}".replace(".", ",")


def latex_escape(texto):
    for a, b in (("\\", r"\textbackslash{}"), ("&", r"\&"), ("%", r"\%"),
                 ("_", r"\_"), ("#", r"\#")):
        texto = texto.replace(a, b)
    return texto


def salvar(nome_base, cabecalho, linhas_csv, cabecalho_tex, linhas_tex,
           alinhamento):
    with open(SAIDA / f"{nome_base}.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cabecalho)
        w.writerows(linhas_csv)

    if isinstance(cabecalho_tex, str):          # cabecalho LaTeX pronto
        cabecalho_tex = [cabecalho_tex]
    else:
        cabecalho_tex = [" & ".join(cabecalho_tex) + r" \\"]
    tex = [f"\\begin{{tabular}}{{{alinhamento}}}", r"\hline",
           *cabecalho_tex, r"\hline"]
    tex += [" & ".join(linha) + r" \\" for linha in linhas_tex]
    tex += [r"\hline", r"\end{tabular}"]
    (SAIDA / f"{nome_base}.tex").write_text("\n".join(tex) + "\n",
                                            encoding="utf-8")


def tabela_consolidada(modelos):
    cab = ["Modelo", "TP", "FP", "TN", "FN", "TPR", "FPR", "Precisao", "F1",
           "Score", "Score_oficial"]
    linhas_csv, linhas_tex = [], []
    for chave, casos in modelos.items():
        m = metricas(casos.values())
        oficial = score_oficial(por_categoria(casos))
        linhas_csv.append([nome(chave), m["TP"], m["FP"], m["TN"], m["FN"],
                           f"{m['TPR']:.4f}", f"{m['FPR']:.4f}",
                           f"{m['Precisao']:.4f}", f"{m['F1']:.4f}",
                           f"{m['Score']:.2f}", f"{oficial:.2f}"])
        linhas_tex.append([latex_escape(nome(chave)), str(m["TP"]),
                           str(m["FP"]), str(m["TN"]), str(m["FN"]),
                           br(m["TPR"]), br(m["FPR"]), br(m["Precisao"]),
                           br(m["F1"]), br(m["Score"], 1), br(oficial, 1)])
        if m["ERRO"]:
            print(f"AVISO: {nome(chave)} tem {m['ERRO']} falhas de parse")
    cab_tex = ["Modelo", "TP", "FP", "TN", "FN", "TPR", "FPR", "Precisão",
               "F1", "Score", "Score (OWASP)"]
    salvar("consolidado", cab, linhas_csv, cab_tex, linhas_tex, "l" + "r" * 10)
    return linhas_csv


def tabela_por_cwe(modelos):
    cats = {chave: por_categoria(casos) for chave, casos in modelos.items()}
    cwes = sorted({cwe for c in cats.values() for cwe in c})

    cab = ["CWE", "Categoria", "Casos"]
    for chave in modelos:
        cab += [f"TPR {nome(chave)}", f"FPR {nome(chave)}"]
    cab_tex = "\n".join([
        " & ".join(["", ""] + [f"\\multicolumn{{2}}{{c}}{{{latex_escape(nome(k))}}}"
                               for k in modelos]) + r" \\",
        " & ".join(["CWE", "Categoria"] + ["TPR", "FPR"] * len(modelos)) + r" \\",
    ])

    linhas_csv, linhas_tex = [], []
    for cwe in cwes:
        primeiro = next(iter(cats.values()))[cwe]
        casos = sum(primeiro[k] for k in ("TP", "FP", "TN", "FN", "ERRO"))
        lc = [cwe, CATEGORIAS.get(cwe, ""), casos]
        lt = [str(cwe), latex_escape(CATEGORIAS.get(cwe, ""))]
        for chave in modelos:
            m = cats[chave][cwe]
            lc += [f"{m['TPR']:.4f}", f"{m['FPR']:.4f}"]
            lt += [br(m["TPR"]), br(m["FPR"])]
        linhas_csv.append(lc)
        linhas_tex.append(lt)

    salvar("por_cwe", cab, linhas_csv, cab_tex, linhas_tex,
           "rl" + "rr" * len(modelos))
    return cab, linhas_csv


def tabela_tempo(modelos):
    cab = ["Modelo", "Mediana_s", "Media_s", "Total_h"]
    linhas_csv, linhas_tex = [], []
    for chave, casos in modelos.items():
        t = [r["segundos"] for r in casos.values()]
        med, media, total = statistics.median(t), statistics.mean(t), sum(t) / 3600
        linhas_csv.append([nome(chave), f"{med:.2f}", f"{media:.2f}",
                           f"{total:.2f}"])
        linhas_tex.append([latex_escape(nome(chave)), br(med, 2), br(media, 2),
                           br(total, 2)])
    salvar("tempo", cab, linhas_csv,
           ["Modelo", "Mediana (s)", "Média (s)", "Total (h)"], linhas_tex,
           "lrrr")
    return linhas_csv


# --------------------------------------------------------------------------
# concordancia Qwen 14B x 7B
# --------------------------------------------------------------------------

def resposta(r):
    p = r["resposta_parseada"]
    return None if p is None else (p["vulnerable"], p["cwe"])


def concordancia_qwen(modelos):
    if QWEN_14B not in modelos or QWEN_7B not in modelos:
        print("Concordancia Qwen: arquivos dos dois modelos nao encontrados")
        return None
    a, b = modelos[QWEN_14B], modelos[QWEN_7B]
    comuns = sorted(set(a) & set(b))

    div_classe = [c for c in comuns if a[c]["classe"] != b[c]["classe"]]
    div_resposta = [c for c in comuns if resposta(a[c]) != resposta(b[c])]

    with open(SAIDA / "concordancia_qwen.csv", "w", newline="",
              encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["caso", "cwe_real", "vuln_real",
                    "classe_14b", "resposta_14b", "classe_7b", "resposta_7b",
                    "classe_divergente"])
        for c in div_resposta:
            w.writerow([c, a[c]["cwe_real"], a[c]["vuln_real"],
                        a[c]["classe"], json.dumps(a[c]["resposta_parseada"]),
                        b[c]["classe"], json.dumps(b[c]["resposta_parseada"]),
                        c in div_classe])

    por_cwe = Counter(a[c]["cwe_real"] for c in div_classe)
    return len(comuns), div_classe, div_resposta, por_cwe


# --------------------------------------------------------------------------

def main():
    SAIDA.mkdir(parents=True, exist_ok=True)
    modelos = carregar_modelos()
    if not modelos:
        print("Nenhum resultados/bruto_v2_*.jsonl encontrado")
        return

    print("=" * 78)
    print("CONSOLIDADO")
    print(f"{'Modelo':20} {'TP':>5} {'FP':>5} {'TN':>5} {'FN':>5} "
          f"{'TPR':>6} {'FPR':>6} {'Prec':>6} {'F1':>6} {'Score':>6} {'Oficial':>7}")
    for l in tabela_consolidada(modelos):
        print(f"{l[0]:20} {l[1]:>5} {l[2]:>5} {l[3]:>5} {l[4]:>5} "
              f"{float(l[5]):6.3f} {float(l[6]):6.3f} {float(l[7]):6.3f} "
              f"{float(l[8]):6.3f} {float(l[9]):6.1f} {float(l[10]):7.1f}")
    print("Score = TPR - FPR global | Oficial = media por categoria (scorecard OWASP)")

    print("\nPOR CWE (TPR / FPR)")
    cab, linhas = tabela_por_cwe(modelos)
    print(f"{'CWE':>4} {'Categoria':24}" +
          "".join(f" {nome(k)[:17]:>17}" for k in modelos))
    for l in linhas:
        pares = [f"{float(l[i]):.2f} / {float(l[i + 1]):.2f}"
                 for i in range(3, len(l), 2)]
        print(f"{l[0]:>4} {l[1]:24}" + "".join(f" {p:>17}" for p in pares))

    print("\nTEMPO")
    for l in tabela_tempo(modelos):
        print(f"{l[0]:20} mediana {l[1]} s | media {l[2]} s | total {l[3]} h")

    conc = concordancia_qwen(modelos)
    if conc:
        n, div_classe, div_resposta, por_cwe = conc
        print("\nCONCORDANCIA QWEN 14B x 7B")
        print(f"Casos comparados .................. {n}")
        print(f"Classificacao divergente (TP/FP/TN/FN): {len(div_classe)} "
              f"({len(div_classe) / n:.1%})")
        print(f"Resposta divergente (vulneravel/CWE): {len(div_resposta)} "
              f"({len(div_resposta) / n:.1%})")
        if por_cwe:
            print("Divergencias de classificacao por CWE: " +
                  ", ".join(f"{k}: {v}" for k, v in sorted(por_cwe.items())))

    print(f"\nArquivos gerados em {SAIDA}")
    print("=" * 78)


if __name__ == "__main__":
    main()
