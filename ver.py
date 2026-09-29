import json
from pathlib import Path

arq = next(Path("resultados").glob("bruto_*.jsonl"))
for linha in open(arq, encoding="utf-8"):
    d = json.loads(linha)
    r = d["resposta_parseada"]
    print(f"{d['categoria']:13} real={str(d['vuln_real']):5} "
          f"esperado=CWE-{d['cwe_real']:<4} modelo={r}")