"""
Repeticoes do corpus completo - estabilidade das respostas dos modelos
TCC - Analise Comparativa entre Ferramentas SAST e Modelos de Linguagem

Executa os 2.740 casos N vezes (padrao 3) contra o mesmo modelo. Prompt,
temperatura, ordem dos casos, interpretacao da resposta e classificacao sao
importados de piloto2.py, garantindo que sejam identicos aos da execucao v2.

Cada repeticao grava resultados/bruto_rep_<modelo>_r<n>.jsonl, no mesmo formato
de bruto_v2_*.jsonl. Nenhum arquivo existente e sobrescrito: repeticao cujo
arquivo ja existe e pulada.

Uso:
    python repeticoes.py --modelo qwen2.5-coder:14b          # repeticoes 1 a 3
    python repeticoes.py --modelo llama3.1:8b --rep 5         # repeticoes 1 a 5
"""

import argparse
import json
import statistics
import time
from collections import Counter

import piloto2 as v2

TENTATIVAS = 3              # novas tentativas em falha de chamada ao modelo
ESPERA_TENTATIVA = 10       # segundos entre tentativas


def caminho(modelo, r):
    return v2.SAIDA / f"bruto_rep_{modelo.replace(':', '_')}_r{r}.jsonl"


def consultar(modelo, codigo):
    for tentativa in range(1, TENTATIVAS + 1):
        try:
            return v2.consultar(modelo, codigo)
        except Exception as e:
            if tentativa == TENTATIVAS:
                raise
            print(f"    tentativa {tentativa} falhou ({e}); repetindo")
            time.sleep(ESPERA_TENTATIVA)


def executar(modelo, r, casos, gabarito):
    """Roda uma repeticao completa. Retorna (contagem, tempos, erros)."""
    destino = caminho(modelo, r)
    contagem, tempos, erros = Counter(), [], 0

    # modo "x": falha se o arquivo existir, nunca sobrescreve
    with open(destino, "x", encoding="utf-8") as saida:
        for i, caso in enumerate(casos, 1):
            arquivo = v2.TESTCODE / f"{caso}.java"
            if not arquivo.exists():
                print(f"  ! {caso}.java nao encontrado")
                continue

            codigo = arquivo.read_text(encoding="utf-8", errors="replace")
            vuln_real, cwe_real, categoria = gabarito[caso]

            try:
                texto, segundos = consultar(modelo, codigo)
            except Exception as e:
                print(f"  ! {caso}: {e}")
                erros += 1
                continue

            resposta = v2.interpretar(texto)
            classe = v2.classificar(resposta, vuln_real, cwe_real)
            contagem[classe] += 1
            tempos.append(segundos)

            # saida bruta persistida antes de qualquer processamento
            saida.write(json.dumps({
                "caso": caso, "categoria": categoria,
                "vuln_real": vuln_real, "cwe_real": cwe_real,
                "resposta_bruta": texto, "resposta_parseada": resposta,
                "classe": classe, "segundos": round(segundos, 2),
            }, ensure_ascii=False) + "\n")
            saida.flush()

            print(f"[r{r} {i:4}/{len(casos)}] {caso} {categoria:14} "
                  f"{classe:4} {segundos:6.1f}s", flush=True)

    return contagem, tempos, erros


def resumo(modelo, r, contagem, tempos, erros):
    tp, fp, tn, fn = (contagem["TP"], contagem["FP"],
                      contagem["TN"], contagem["FN"])
    tpr = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    print("=" * 58)
    print(f"Modelo: {modelo} | repeticao {r}")
    print(f"Classificados: {tp + fp + tn + fn} | Falhas de parse: "
          f"{contagem['ERRO']} | Erros de chamada: {erros}")
    print(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}  "
          f"TPR={tpr:.3f}  FPR={fpr:.3f}  Score={(tpr - fpr) * 100:.1f}")
    if tempos:
        print(f"Tempo/caso mediana {statistics.median(tempos):.2f}s | "
              f"total {sum(tempos) / 3600:.2f} h")
    print(f"Saida bruta: {caminho(modelo, r)}")
    print("=" * 58, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--modelo", default=v2.MODELO_PADRAO)
    ap.add_argument("--rep", type=int, default=3, help="numero de repeticoes")
    args = ap.parse_args()

    v2.SAIDA.mkdir(parents=True, exist_ok=True)
    gabarito = v2.carregar_gabarito()
    casos = v2.amostra_estratificada(gabarito, len(gabarito))   # ordem da v2
    print(f"{len(casos)} casos | Modelo: {args.modelo} | "
          f"Repeticoes: {args.rep}\n", flush=True)

    for r in range(1, args.rep + 1):
        destino = caminho(args.modelo, r)
        if destino.exists():
            with open(destino, encoding="utf-8") as f:
                n = sum(1 for linha in f if linha.strip())
            aviso = "" if n == len(casos) else f" -- INCOMPLETO: {n} casos"
            print(f"Repeticao {r} ja existe, pulando: {destino.name}{aviso}",
                  flush=True)
            continue
        contagem, tempos, erros = executar(args.modelo, r, casos, gabarito)
        resumo(args.modelo, r, contagem, tempos, erros)


if __name__ == "__main__":
    main()
