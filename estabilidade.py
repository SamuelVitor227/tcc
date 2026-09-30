"""
Estabilidade das respostas entre repeticoes
TCC - Analise Comparativa entre Ferramentas SAST e Modelos de Linguagem

Le resultados/bruto_rep_<modelo>_r<n>.jsonl e, para comparacao, a execucao
original resultados/bruto_v2_<modelo>.jsonl (todos somente leitura). Gera em
resultados/analise/:
    estabilidade.csv / .tex             - variacao entre repeticoes, por modelo
    estabilidade_metricas.csv / .tex    - metricas de cada execucao
    estabilidade_divergentes.csv        - casos cuja resposta variou

Definicoes (sobre os casos presentes em todas as repeticoes):
    classificacao variou  TP/FP/TN/FN nao e a mesma em todas as repeticoes
    veredito variou       o campo "vulnerable" nao e o mesmo em todas
    CWE variou            vulneravel em todas as repeticoes, mas com CWEs
                          diferentes (separa a instabilidade da CWE da do
                          veredito)
    diverge da v2         a classificacao da execucao v2 difere da de ao
                          menos uma repeticao

Uso:
    python estabilidade.py
"""

import csv
import json
import re
from collections import defaultdict

import analise as a     # metricas e exportacao iguais as da analise principal

PADRAO = re.compile(r"^bruto_rep_(.+)_r(\d+)\.jsonl$")


def ler(arquivo):
    with open(arquivo, encoding="utf-8") as f:
        return {r["caso"]: r for r in (json.loads(l) for l in f if l.strip())}


def carregar():
    """{modelo: {"v2": casos | None, "reps": {n: casos}}}, na ordem de NOMES."""
    reps = defaultdict(dict)
    for arquivo in a.RESULTADOS.glob("bruto_rep_*.jsonl"):
        m = PADRAO.match(arquivo.name)
        if m:
            reps[m.group(1)][int(m.group(2))] = ler(arquivo)

    ordem = list(a.NOMES)
    modelos = {}
    for chave in sorted(reps, key=lambda k: ordem.index(k) if k in ordem
                        else len(ordem)):
        original = a.RESULTADOS / f"bruto_v2_{chave}.jsonl"
        modelos[chave] = {
            "v2": ler(original) if original.exists() else None,
            "reps": dict(sorted(reps[chave].items())),
        }
    return modelos


def veredito(r):
    p = r["resposta_parseada"]
    return None if p is None else p["vulnerable"]


def cwe(r):
    p = r["resposta_parseada"]
    return None if p is None else p["cwe"]


def pct(n, total):
    return n / total * 100 if total else 0.0


# --------------------------------------------------------------------------
# analise por modelo
# --------------------------------------------------------------------------

def comparar(chave, dados):
    execs = list(dados["reps"].values())
    comuns = sorted(set.intersection(*(set(e) for e in execs)))
    for n, e in dados["reps"].items():
        if len(e) != a.TOTAL_CASOS:
            print(f"AVISO: {a.nome(chave)} r{n} tem {len(e)} casos "
                  f"(esperado {a.TOTAL_CASOS})")

    classe_var, veredito_var, cwe_var, v2_div = [], [], [], []
    for c in comuns:
        classes = {e[c]["classe"] for e in execs}
        vereditos = {veredito(e[c]) for e in execs}
        if len(classes) > 1:
            classe_var.append(c)
        if len(vereditos) > 1:
            veredito_var.append(c)
        elif vereditos == {True} and len({cwe(e[c]) for e in execs}) > 1:
            cwe_var.append(c)
        v2 = dados["v2"]
        if v2 and c in v2 and any(v2[c]["classe"] != e[c]["classe"]
                                  for e in execs):
            v2_div.append(c)

    return {"comuns": comuns, "classe": classe_var, "veredito": veredito_var,
            "cwe": cwe_var, "v2": v2_div if dados["v2"] else None}


# --------------------------------------------------------------------------
# exportacao
# --------------------------------------------------------------------------

def tabela_estabilidade(modelos, resultados):
    cab = ["Modelo", "Repeticoes", "Casos",
           "Classificacao_variou", "Classificacao_variou_pct",
           "Veredito_variou", "Veredito_variou_pct",
           "CWE_variou", "CWE_variou_pct",
           "Diverge_v2", "Diverge_v2_pct"]
    linhas_csv, linhas_tex = [], []
    for chave, res in resultados.items():
        total = len(res["comuns"])
        contagens = [len(res["classe"]), len(res["veredito"]), len(res["cwe"]),
                     None if res["v2"] is None else len(res["v2"])]
        lc = [a.nome(chave), len(modelos[chave]["reps"]), total]
        lt = [a.latex_escape(a.nome(chave)), str(len(modelos[chave]["reps"])),
              str(total)]
        for n in contagens:
            if n is None:
                lc += ["", ""]
                lt.append("--")
            else:
                lc += [n, f"{pct(n, total):.2f}"]
                lt.append(f"{n} ({a.br(pct(n, total), 2)}\\%)")
        linhas_csv.append(lc)
        linhas_tex.append(lt)
    cab_tex = ["Modelo", "Rep.", "Casos", "Classificação", "Veredito", "CWE",
               "Diverge da v2"]
    a.salvar("estabilidade", cab, linhas_csv, cab_tex, linhas_tex, "lrrrrrr")
    return linhas_csv


def tabela_metricas(modelos):
    cab = ["Modelo", "Execucao", "TP", "FP", "TN", "FN", "TPR", "FPR",
           "Precisao", "F1", "Score", "Score_oficial"]
    linhas_csv, linhas_tex = [], []
    for chave, dados in modelos.items():
        execs = ([("v2", dados["v2"])] if dados["v2"] else []) + \
                [(f"r{n}", e) for n, e in dados["reps"].items()]
        for rotulo, casos in execs:
            m = a.metricas(casos.values())
            oficial = a.score_oficial(a.por_categoria(casos))
            linhas_csv.append([a.nome(chave), rotulo, m["TP"], m["FP"], m["TN"],
                               m["FN"], f"{m['TPR']:.4f}", f"{m['FPR']:.4f}",
                               f"{m['Precisao']:.4f}", f"{m['F1']:.4f}",
                               f"{m['Score']:.2f}", f"{oficial:.2f}"])
            linhas_tex.append([a.latex_escape(a.nome(chave)), rotulo,
                               str(m["TP"]), str(m["FP"]), str(m["TN"]),
                               str(m["FN"]), a.br(m["TPR"]), a.br(m["FPR"]),
                               a.br(m["Precisao"]), a.br(m["F1"]),
                               a.br(m["Score"], 1), a.br(oficial, 1)])
    cab_tex = ["Modelo", "Execução", "TP", "FP", "TN", "FN", "TPR", "FPR",
               "Precisão", "F1", "Score", "Score (OWASP)"]
    a.salvar("estabilidade_metricas", cab, linhas_csv, cab_tex, linhas_tex,
             "ll" + "r" * 10)
    return linhas_csv


def lista_divergentes(modelos, resultados):
    max_reps = max(len(d["reps"]) for d in modelos.values())
    cab = ["modelo", "caso", "cwe_real", "vuln_real"]
    for n in range(1, max_reps + 1):
        cab += [f"classe_r{n}", f"resposta_r{n}"]
    cab += ["classe_v2", "resposta_v2", "classificacao_variou"]

    with open(a.SAIDA / "estabilidade_divergentes.csv", "w", newline="",
              encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cab)
        for chave, res in resultados.items():
            dados = modelos[chave]
            execs = dados["reps"]
            classe_var = set(res["classe"])
            for c in res["comuns"]:
                respostas = {json.dumps(e[c]["resposta_parseada"])
                             for e in execs.values()}
                if len(respostas) == 1:
                    continue
                ref = next(iter(execs.values()))[c]
                linha = [a.nome(chave), c, ref["cwe_real"], ref["vuln_real"]]
                for n in range(1, max_reps + 1):
                    e = execs.get(n)
                    linha += ([e[c]["classe"],
                               json.dumps(e[c]["resposta_parseada"])]
                              if e else ["", ""])
                v2 = dados["v2"]
                linha += ([v2[c]["classe"], json.dumps(v2[c]["resposta_parseada"])]
                          if v2 and c in v2 else ["", ""])
                linha.append(c in classe_var)
                w.writerow(linha)


# --------------------------------------------------------------------------

def main():
    a.SAIDA.mkdir(parents=True, exist_ok=True)
    modelos = carregar()
    if not modelos:
        print("Nenhum resultados/bruto_rep_*.jsonl encontrado")
        return

    resultados = {chave: comparar(chave, dados)
                  for chave, dados in modelos.items()}

    print("=" * 78)
    print("ESTABILIDADE ENTRE REPETICOES")
    print(f"{'Modelo':20} {'Rep':>3} {'Casos':>5} {'Classificacao':>15} "
          f"{'Veredito':>15} {'CWE':>15} {'Diverge v2':>15}")
    for l in tabela_estabilidade(modelos, resultados):
        celulas = [f"{l[i]} ({l[i + 1]}%)" if l[i] != "" else "--"
                   for i in range(3, len(l), 2)]
        print(f"{l[0]:20} {l[1]:>3} {l[2]:>5}" +
              "".join(f" {c:>15}" for c in celulas))

    print("\nMETRICAS POR EXECUCAO")
    print(f"{'Modelo':20} {'Exec':>4} {'TP':>5} {'FP':>5} {'TN':>5} {'FN':>5} "
          f"{'TPR':>6} {'FPR':>6} {'Prec':>6} {'F1':>6} {'Score':>6} {'Oficial':>7}")
    for l in tabela_metricas(modelos):
        print(f"{l[0]:20} {l[1]:>4} {l[2]:>5} {l[3]:>5} {l[4]:>5} {l[5]:>5} "
              f"{float(l[6]):6.3f} {float(l[7]):6.3f} {float(l[8]):6.3f} "
              f"{float(l[9]):6.3f} {float(l[10]):6.1f} {float(l[11]):7.1f}")

    lista_divergentes(modelos, resultados)
    print(f"\nArquivos gerados em {a.SAIDA}")
    print("=" * 78)


if __name__ == "__main__":
    main()
