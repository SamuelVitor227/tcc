/**
 * Leitor SARIF para os modelos de linguagem avaliados no TCC.
 *
 * <p>Aceita os arquivos gerados por para_sarif.py, cujo tool.driver.name comeca com "LLM-". As
 * regras seguem o formato do CodeQL e do Semgrep (tag external/cwe/cwe-N), entao a CWE e lida por
 * tag, sem mapeamento adicional: o prompt ja restringe as respostas as CWEs do benchmark.
 *
 * <p>Instalacao no BenchmarkUtils:
 *
 * <ol>
 *   <li>copiar este arquivo para plugin/src/main/java/org/owasp/benchmarkutils/score/parsers/sarif/
 *   <li>em parsers/Reader.java, adicionar "new LLMSarifReader()," na lista de allReaders() e o
 *       import org.owasp.benchmarkutils.score.parsers.sarif.LLMSarifReader
 *   <li>mvn install no BenchmarkUtils
 * </ol>
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

public class LLMSarifReader extends SarifReader {

    public LLMSarifReader() {
        super("LLM-", false, CweSourceType.TAG);
    }
}
