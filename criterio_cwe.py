"""
Efeito do criterio de CWE exata sobre a medicao
TCC - Analise Comparativa entre Ferramentas SAST e Modelos de Linguagem

Le resultados/bruto_v2_*.jsonl (somente leitura) e gera em resultados/analise/:
    sem_deteccao_respostas.csv      - casos reais de crypto, hash, weakrand e
                                      trustbound, por tipo de resposta
    sem_deteccao_cwes.csv           - CWEs reportadas no lugar da esperada
    criterio_cwe.csv / .tex         - metricas com e sem exigencia de CWE exata
    por_cwe_sem_cwe.csv / .tex      - TPR e FPR por categoria, sem exigir CWE
    injecao_respostas.csv / .tex    - "vulnerable": true em casos reais e
                                      negativos de cmdi, sqli e xpathi

Criterio sem CWE: basta "vulnerable": true no caso real (TP) ou no negativo
(FP); a CWE reportada e ignorada. Resposta nao interpretada conta como nao
apontada.

Uso:
    python criterio_cwe.py
"""

import csv
from collections import Counter

import analise as a     # leitura, metricas e exportacao da analise principal

SEM_DETECCAO = {"crypto": 327, "hash": 328, "weakrand": 330, "trustbound": 501}
INJECAO = {"cmdi": 78, "sqli": 89, "xpathi": 643}


def apontou(r):
    p = r["resposta_parseada"]
    return bool(p and p["vulnerable"])


def cwe_reportada(r):
    p = r["resposta_parseada"]
    return p["cwe"] if p else None


def classe_sem_cwe(r):
    if r["vuln_real"]:
        return "TP" if apontou(r) else "FN"
    return "FP" if apontou(r) else "TN"


def sem_cwe(casos):
    """Os mesmos registros, reclassificados sem exigir a CWE."""
    return {c: {**r, "classe": classe_sem_cwe(r)} for c, r in casos.items()}


def da_categoria(casos, categoria, cwe):
    regs = [r for r in casos.values() if r["categoria"] == categoria]
    if any(r["cwe_real"] != cwe for r in regs):
        raise ValueError(f"categoria {categoria} com CWE diferente de {cwe}")
    return regs


def pct(n, total):
    return f"{n / total * 100:.2f}" if total else ""


# --------------------------------------------------------------------------
# 1. respostas nas categorias sem deteccao
# --------------------------------------------------------------------------

def respostas_sem_deteccao(modelos):
    resumo, cwes = [], []
    for chave, casos in modelos.items():
        for categoria, esperada in SEM_DETECCAO.items():
            reais = [r for r in da_categoria(casos, categoria, esperada)
                     if r["vuln_real"]]
            nao = [r for r in reais if not apontou(r)]
            certa = [r for r in reais
                     if apontou(r) and cwe_reportada(r) == esperada]
            outras = Counter(cwe_reportada(r) for r in reais
                             if apontou(r) and cwe_reportada(r) != esperada)
            n_outras = sum(outras.values())
            resumo.append([a.nome(chave), categoria, esperada, len(reais),
                           len(nao), pct(len(nao), len(reais)),
                           n_outras, pct(n_outras, len(reais)),
                           len(certa), pct(len(certa), len(reais))])
            for cwe, n in outras.most_common():
                cwes.append([a.nome(chave), categoria, esperada,
                             "" if cwe is None else cwe, n,
                             pct(n, len(reais))])

    with open(a.SAIDA / "sem_deteccao_respostas.csv", "w", newline="",
              encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["modelo", "categoria", "cwe_esperada", "casos_reais",
                    "a_nao_detectou", "a_pct", "b_outra_cwe", "b_pct",
                    "cwe_esperada_reportada", "cwe_esperada_pct"])
        w.writerows(resumo)
    with open(a.SAIDA / "sem_deteccao_cwes.csv", "w", newline="",
              encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["modelo", "categoria", "cwe_esperada", "cwe_reportada",
                    "casos", "pct_dos_reais"])
        w.writerows(cwes)
    return resumo, cwes


# --------------------------------------------------------------------------
# 2. metricas com e sem exigencia de CWE
# --------------------------------------------------------------------------

def tabela_criterios(modelos):
    cab = ["Modelo", "Criterio", "TP", "FP", "TN", "FN", "TPR", "FPR",
           "Precisao", "F1", "Score", "Score_oficial"]
    linhas_csv, linhas_tex = [], []
    for chave, casos in modelos.items():
        for rotulo, regs in (("CWE exata", casos), ("Sem CWE", sem_cwe(casos))):
            m = a.metricas(regs.values())
            oficial = a.score_oficial(a.por_categoria(regs))
            linhas_csv.append([a.nome(chave), rotulo, m["TP"], m["FP"],
                               m["TN"], m["FN"], f"{m['TPR']:.4f}",
                               f"{m['FPR']:.4f}", f"{m['Precisao']:.4f}",
                               f"{m['F1']:.4f}", f"{m['Score']:.2f}",
                               f"{oficial:.2f}"])
            linhas_tex.append([a.latex_escape(a.nome(chave)), rotulo,
                               str(m["TP"]), str(m["FP"]), str(m["TN"]),
                               str(m["FN"]), a.br(m["TPR"]), a.br(m["FPR"]),
                               a.br(m["Precisao"]), a.br(m["F1"]),
                               a.br(m["Score"], 1), a.br(oficial, 1)])
    cab_tex = ["Modelo", "Critério", "TP", "FP", "TN", "FN", "TPR", "FPR",
               "Precisão", "F1", "Score", "Score (OWASP)"]
    a.salvar("criterio_cwe", cab, linhas_csv, cab_tex, linhas_tex,
             "ll" + "r" * 10)
    return linhas_csv


def tabela_por_cwe_sem_cwe(modelos):
    """Mesmo formato de por_cwe, sob o criterio sem CWE."""
    cats = {chave: a.por_categoria(sem_cwe(casos))
            for chave, casos in modelos.items()}
    cwes = sorted({cwe for c in cats.values() for cwe in c})

    cab = ["CWE", "Categoria", "Casos"]
    for chave in modelos:
        cab += [f"TPR {a.nome(chave)}", f"FPR {a.nome(chave)}"]
    cab_tex = "\n".join([
        " & ".join(["", ""] + [f"\\multicolumn{{2}}{{c}}{{{a.latex_escape(a.nome(k))}}}"
                               for k in modelos]) + r" \\",
        " & ".join(["CWE", "Categoria"] + ["TPR", "FPR"] * len(modelos)) + r" \\",
    ])

    linhas_csv, linhas_tex = [], []
    for cwe in cwes:
        primeiro = next(iter(cats.values()))[cwe]
        casos = sum(primeiro[k] for k in ("TP", "FP", "TN", "FN"))
        lc = [cwe, a.CATEGORIAS.get(cwe, ""), casos]
        lt = [str(cwe), a.latex_escape(a.CATEGORIAS.get(cwe, ""))]
        for chave in modelos:
            m = cats[chave][cwe]
            lc += [f"{m['TPR']:.4f}", f"{m['FPR']:.4f}"]
            lt += [a.br(m["TPR"]), a.br(m["FPR"])]
        linhas_csv.append(lc)
        linhas_tex.append(lt)
    a.salvar("por_cwe_sem_cwe", cab, linhas_csv, cab_tex, linhas_tex,
             "rl" + "rr" * len(modelos))
    return linhas_csv


# --------------------------------------------------------------------------
# 3. categorias de injecao: vulnerable: true em reais e negativos
# --------------------------------------------------------------------------

def respostas_injecao(modelos):
    cab = ["Modelo", "Categoria", "CWE", "Reais", "Reais_vulneravel",
           "Reais_vulneravel_pct", "Negativos", "Negativos_vulneravel",
           "Negativos_vulneravel_pct", "Reais_cwe_correta",
           "Negativos_cwe_correta"]
    linhas_csv, linhas_tex = [], []
    for chave, casos in modelos.items():
        for categoria, cwe in INJECAO.items():
            regs = da_categoria(casos, categoria, cwe)
            reais = [r for r in regs if r["vuln_real"]]
            neg = [r for r in regs if not r["vuln_real"]]
            rv = sum(apontou(r) for r in reais)
            nv = sum(apontou(r) for r in neg)
            rc = sum(apontou(r) and cwe_reportada(r) == cwe for r in reais)
            nc = sum(apontou(r) and cwe_reportada(r) == cwe for r in neg)
            linhas_csv.append([a.nome(chave), categoria, cwe, len(reais), rv,
                               pct(rv, len(reais)), len(neg), nv,
                               pct(nv, len(neg)), rc, nc])
            linhas_tex.append([a.latex_escape(a.nome(chave)), categoria,
                               str(cwe), f"{rv}/{len(reais)}",
                               f"{nv}/{len(neg)}", f"{rc}/{len(reais)}",
                               f"{nc}/{len(neg)}"])
    cab_tex = ["Modelo", "Categoria", "CWE", "Reais apontados",
               "Negativos apontados", "Reais (CWE certa)",
               "Negativos (CWE certa)"]
    a.salvar("injecao_respostas", cab, linhas_csv, cab_tex, linhas_tex,
             "llrrrrr")
    return linhas_csv


# --------------------------------------------------------------------------

def main():
    a.SAIDA.mkdir(parents=True, exist_ok=True)
    modelos = a.carregar_modelos()
    if not modelos:
        print("Nenhum resultados/bruto_v2_*.jsonl encontrado")
        return

    print("=" * 78)
    print("1. CASOS REAIS DAS CATEGORIAS SEM DETECCAO")
    resumo, cwes = respostas_sem_deteccao(modelos)
    print(f"{'Modelo':20} {'Categoria':11} {'Reais':>5} {'(a) nao':>14} "
          f"{'(b) outra CWE':>14} {'CWE certa':>11}")
    for l in resumo:
        print(f"{l[0]:20} {l[1]:11} {l[3]:>5} {l[4]:>6} ({l[5]:>5}%) "
              f"{l[6]:>6} ({l[7]:>5}%) {l[8]:>4} ({l[9]:>4}%)")
    print("\n   CWEs reportadas no grupo (b)")
    for l in cwes:
        print(f"   {l[0]:20} {l[1]:11} esperada {l[2]:>3} -> "
              f"CWE-{l[3]}: {l[4]} ({l[5]}%)")

    print("\n2. METRICAS COM E SEM EXIGENCIA DE CWE")
    print(f"{'Modelo':20} {'Criterio':10} {'TP':>5} {'FP':>5} {'TN':>5} "
          f"{'FN':>5} {'TPR':>6} {'FPR':>6} {'Prec':>6} {'F1':>6} "
          f"{'Score':>6} {'Oficial':>7}")
    for l in tabela_criterios(modelos):
        print(f"{l[0]:20} {l[1]:10} {l[2]:>5} {l[3]:>5} {l[4]:>5} {l[5]:>5} "
              f"{float(l[6]):6.3f} {float(l[7]):6.3f} {float(l[8]):6.3f} "
              f"{float(l[9]):6.3f} {float(l[10]):6.1f} {float(l[11]):7.1f}")

    print("\n   Por categoria, sem CWE (TPR / FPR)")
    for l in tabela_por_cwe_sem_cwe(modelos):
        pares = [f"{float(l[i]):.2f} / {float(l[i + 1]):.2f}"
                 for i in range(3, len(l), 2)]
        print(f"   {l[0]:>4} {l[1]:24}" + "".join(f" {p:>13}" for p in pares))

    print("\n3. CATEGORIAS DE INJECAO: vulnerable: true")
    print(f"{'Modelo':20} {'Categoria':9} {'Reais':>14} {'Negativos':>14}")
    for l in respostas_injecao(modelos):
        print(f"{l[0]:20} {l[1]:9} {l[4]:>4}/{l[3]:<4} ({float(l[5]):5.1f}%) "
              f"{l[7]:>4}/{l[6]:<4} ({float(l[8]):5.1f}%)")

    print(f"\nArquivos gerados em {a.SAIDA}")
    print("=" * 78)


if __name__ == "__main__":
    main()
