"""
Conversor da saida bruta dos modelos para SARIF 2.1.0
TCC - Analise Comparativa entre Ferramentas SAST e Modelos de Linguagem

Converte cada resultados/bruto_v2_*.jsonl (somente leitura) em
resultados/sarif/LLM-<modelo>.sarif, para pontuacao pelo createScorecard.sh do
BenchmarkUtils com o mesmo procedimento aplicado as ferramentas SAST.

Cada resposta {"vulnerable": true, "cwe": N} vira um result com ruleId CWE-N,
apontando para o arquivo do caso de teste. O formato das regras (tag
external/cwe/cwe-N) segue o do CodeQL e do Semgrep. O BenchmarkUtils nao tem
leitor SARIF generico: e preciso registrar benchmarkutils/LLMSarifReader.java,
que aceita os arquivos cujo tool.driver.name comeca com "LLM-".

Uso:
    python para_sarif.py
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
RESULTADOS = BASE / "resultados"
SAIDA = RESULTADOS / "sarif"

PREFIXO_FERRAMENTA = "LLM-"          # deve coincidir com LLMSarifReader.java
CAMINHO_TESTCODE = "src/main/java/org/owasp/benchmark/testcode"
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

NOMES_CWE = {
    22: "Path traversal", 78: "OS command injection", 79: "Cross-site scripting",
    89: "SQL injection", 90: "LDAP injection",
    327: "Broken or risky cryptographic algorithm",
    328: "Weak hash", 330: "Insufficiently random values",
    501: "Trust boundary violation", 614: "Sensitive cookie without Secure",
    643: "XPath injection",
}


def iso(momento):
    """Formato aceito pelo SarifReader: yyyy-MM-dd'T'HH:mm:ss.SSSXXX"""
    return momento.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def regra(cwe):
    return {
        "id": f"CWE-{cwe}",
        "name": f"CWE{cwe}",
        "shortDescription": {"text": NOMES_CWE.get(cwe, f"CWE-{cwe}")},
        "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe}.html",
        "properties": {"tags": [f"external/cwe/cwe-{cwe:03d}", "security"]},
    }


def converter(arquivo):
    modelo = arquivo.stem.removeprefix("bruto_v2_")     # ex.: qwen2.5-coder_14b
    tag_ollama = ":".join(modelo.rsplit("_", 1))          # qwen2.5-coder:14b

    with open(arquivo, encoding="utf-8") as f:
        registros = [json.loads(l) for l in f if l.strip()]

    resultados, cwes = [], set()
    for r in registros:
        p = r["resposta_parseada"]
        if not p or not p["vulnerable"] or p["cwe"] is None:
            continue
        cwe = int(p["cwe"])
        cwes.add(cwe)
        resultados.append({
            "ruleId": f"CWE-{cwe}",
            "level": "error",
            "message": {"text": f"{tag_ollama} apontou CWE-{cwe}: "
                                f"{r['resposta_bruta'].strip()}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {
                    "uri": f"{CAMINHO_TESTCODE}/{r['caso']}.java",
                    "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": 1}}}],
        })

    # A duracao da analise e a soma dos tempos por caso. O instante de termino
    # e a ultima modificacao do jsonl; o inicio e derivado dele.
    duracao = timedelta(seconds=sum(r["segundos"] for r in registros))
    fim = datetime.fromtimestamp(arquivo.stat().st_mtime, tz=timezone.utc)

    sarif = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": f"{PREFIXO_FERRAMENTA}{modelo.replace('_', '-')}",
                "version": tag_ollama,
                "informationUri": "https://ollama.com/library/"
                                  + tag_ollama.split(":")[0],
                "rules": [regra(c) for c in sorted(cwes)],
            }},
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": iso(fim - duracao),
                "endTimeUtc": iso(fim),
            }],
            "results": resultados,
        }],
    }

    destino = SAIDA / f"{PREFIXO_FERRAMENTA}{modelo}.sarif"
    destino.write_text(json.dumps(sarif, ensure_ascii=False, indent=2),
                       encoding="utf-8")
    return destino, len(registros), len(resultados), sorted(cwes)


def main():
    SAIDA.mkdir(parents=True, exist_ok=True)
    arquivos = sorted(RESULTADOS.glob("bruto_v2_*.jsonl"))
    if not arquivos:
        print("Nenhum resultados/bruto_v2_*.jsonl encontrado")
        return
    for arquivo in arquivos:
        destino, casos, apontamentos, cwes = converter(arquivo)
        print(f"{arquivo.name}: {casos} casos, {apontamentos} apontamentos, "
              f"CWEs {cwes}\n  -> {destino}")


if __name__ == "__main__":
    main()
