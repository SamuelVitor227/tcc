# Análise Comparativa entre Ferramentas SAST e Modelos de Linguagem na Detecção de Vulnerabilidades no OWASP Benchmark

Trabalho de Conclusão de Curso — Sistemas de Informação
PUC Minas, Unidade São Gabriel — 2026/2

**Autores:** Samuel Vitor Cardoso Santos · Pedro Henrique Oliveira Siqueira
**Orientador:** Prof. Gustavo Luis Soares

---

## Sobre

Comparação da eficácia de ferramentas SAST e de modelos de linguagem executados
localmente na detecção de vulnerabilidades em código Java, tendo o OWASP Benchmark
for Java v1.2 como instrumento de avaliação.

O benchmark reúne 2.740 casos de teste, cada um contendo uma vulnerabilidade real ou
um falso positivo deliberado, mapeado a uma CWE específica. Como o gabarito é
documentado, cada saída pode ser classificada em verdadeiro positivo, falso positivo,
verdadeiro negativo ou falso negativo.

## Tecnologias avaliadas

| Abordagem | Tecnologia | Versão |
|---|---|---|
| SAST | SpotBugs com FindSecBugs | a definir |
| SAST | Semgrep | a definir |
| SAST | SonarQube Community Edition | a definir |
| SAST | CodeQL | a definir |
| Controle negativo | PMD | a definir |
| LLM | Qwen2.5-Coder 14B | `qwen2.5-coder:14b` (Q4_K_M) |
| LLM | Qwen2.5-Coder 7B | `qwen2.5-coder:7b` (Q4_K_M) |
| LLM | Llama 3.1 8B | `llama3.1:8b` (Q4_K_M) |

O PMD entra como controle negativo: por não dispor de regras de segurança, espera-se
pontuação próxima de zero. Divergência indica erro no procedimento de coleta.

## Ambiente

| Item | Versão |
|---|---|
| SO | Windows 11 + WSL2 (Ubuntu) |
| Java | 8.0.412 (Temurin) |
| Maven | 3.9.16 |
| Ollama | 0.34.4 |
| Python | 3.14 |
| CPU | Intel Core i5-14600K |
| RAM | 64 GB |
| GPU | NVIDIA GeForce RTX 5070 (12 GB) |

O OWASP Benchmark exige Java 7 ou 8 de 64 bits e Maven 3.2.3 ou superior.

## Estrutura

```
tcc/
├── testcode/                  # 2.740 casos de teste (.java) do benchmark
├── expectedresults-1.2.csv    # gabarito oficial da v1.2
├── piloto.py                  # piloto v1 — prompt genérico
├── piloto2.py                 # v2 — prompt com as CWEs explicitadas (usado no corpus completo)
├── repeticoes.py              # repetições do corpus completo (mesmo prompt da v2)
├── analise.py                 # métricas consolidadas, por CWE, tempo e concordância
├── estabilidade.py            # variação das respostas entre repetições
├── criterio_cwe.py            # efeito do critério de CWE exata sobre as métricas
├── para_sarif.py              # converte a saída bruta para SARIF 2.1.0
├── ver.py                     # inspeção das respostas brutas
├── benchmarkutils/
│   └── LLMSarifReader.java    # leitor SARIF para o scorecard oficial
└── resultados/
    ├── bruto_*.jsonl          # saída bruta do piloto v1
    ├── bruto_v2_*.jsonl       # saída bruta do corpus completo
    ├── bruto_rep_*_r<n>.jsonl # saída bruta de cada repetição
    ├── piloto_30casos/        # saída bruta do piloto v2
    ├── analise/               # tabelas em CSV e LaTeX (analise.py e estabilidade.py)
    └── sarif/                 # SARIF gerado por para_sarif.py
```

## Como reproduzir

### 1. Preparar o benchmark

No WSL:

```bash
sudo apt update && sudo apt install -y zip unzip curl git
curl -s "https://get.sdkman.io" | bash
source "$HOME/.sdkman/bin/sdkman-init.sh"
sdk install java 8.0.412-tem
sdk install maven

git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git
cd BenchmarkJava
```

O repositório traz dois artefatos incompatíveis com o JDK 8, que precisam ser removidos:

```bash
mv .mvn/jvm.config .mvn/jvm.config.bak     # opções --add-exports (Java 9+)
sed -i '1117,1201d' pom.xml                # plugin Spotless (compilado para Java 17)
mvn compile
```

### 2. Copiar o corpus

```bash
cp -r src/main/java/org/owasp/benchmark/testcode /caminho/para/tcc/
cp expectedresults-1.2.csv /caminho/para/tcc/
```

### 3. Preparar os modelos

No Windows:

```powershell
ollama pull qwen2.5-coder:14b
ollama pull qwen2.5-coder:7b
ollama pull llama3.1:8b
```

### 4. Executar

```powershell
pip install requests
python piloto2.py --n 2740 --modelo qwen2.5-coder:14b
python piloto2.py --n 2740 --modelo qwen2.5-coder:7b
python piloto2.py --n 2740 --modelo llama3.1:8b
```

Cada execução sobrescreve o `resultados/bruto_v2_<modelo>.jsonl` do mesmo modelo.
Sem `--n`, o script roda a amostra de 30 casos do piloto.

Repetições, para medir a estabilidade das respostas:

```powershell
python repeticoes.py --modelo qwen2.5-coder:14b    # repetições 1 a 3
python repeticoes.py --modelo qwen2.5-coder:7b
python repeticoes.py --modelo llama3.1:8b
```

O `repeticoes.py` importa prompt, temperatura, ordem dos casos, interpretação e
classificação do `piloto2.py`, de modo que as repetições são idênticas à execução v2.
Cada repetição grava `resultados/bruto_rep_<modelo>_r<n>.jsonl`; um arquivo existente
nunca é sobrescrito, e a repetição correspondente é pulada.

### 5. Analisar

```powershell
python analise.py      # tabelas em resultados/analise/
python para_sarif.py   # SARIF em resultados/sarif/
python estabilidade.py # estabilidade entre repetições, em resultados/analise/
python criterio_cwe.py # métricas sem exigir CWE exata, em resultados/analise/
```

Os scripts só leem os `.jsonl`; a saída bruta nunca é alterada. Ela é versionada no
repositório byte a byte (`.gitattributes` desativa a conversão de quebra de linha).

### 6. Pontuar com o scorecard oficial

O BenchmarkUtils não tem leitor SARIF genérico: cada leitor aceita apenas o
`tool.driver.name` de uma ferramenta conhecida. Para que os modelos sejam pontuados
pelo mesmo procedimento das ferramentas SAST, registra-se um leitor próprio:

1. Copiar `benchmarkutils/LLMSarifReader.java` para
   `plugin/src/main/java/org/owasp/benchmarkutils/score/parsers/sarif/` no BenchmarkUtils
2. Em `parsers/Reader.java`, importar a classe e adicionar `new LLMSarifReader(),` à
   lista de `allReaders()`
3. `mvn install` no BenchmarkUtils
4. Copiar `resultados/sarif/*.sarif` para `BenchmarkJava/results/` e executar
   `./createScorecard.sh`

O SARIF usa o mesmo formato de regra do CodeQL e do Semgrep (tag
`external/cwe/cwe-N`), e o leitor não faz nenhum remapeamento de CWE.

## Protocolo

- Temperatura fixada em zero
- Três repetições por modelo sobre o corpus completo, além da execução v2
- Prompt definido previamente e reproduzido no apêndice do artigo
- Saída bruta persistida em disco antes de qualquer processamento, permitindo
  reprocessar sem nova execução
- Corpus completo (2.740 casos) na avaliação final; no piloto, amostragem
  estratificada por categoria de CWE e por rótulo, com semente fixa
- Execuções sequenciais, sem processamento concorrente, para não interferir na
  medição de tempo

### Critério de classificação

Apontar a CWE esperada em um caso real conta como verdadeiro positivo; apontá-la em
um caso negativo, como falso positivo. Não apontar, ou apontar CWE divergente, conta
como falso negativo em caso real e verdadeiro negativo em caso negativo.

## Resultados — corpus completo

2.740 casos por modelo, prompt com as CWEs explicitadas, execução v2. Nenhuma
falha de interpretação da resposta nem de chamada ao modelo. As contagens foram
conferidas contra os arquivos SARIF, aplicando o critério do scorecard.

### Métricas consolidadas

| Modelo | TP | FP | TN | FN | TPR | FPR | Precisão | F1 | Score | Score (OWASP) |
|---|---|---|---|---|---|---|---|---|---|---|
| Qwen2.5-Coder 14B | 832 | 636 | 689 | 583 | 0,588 | 0,480 | 0,567 | 0,577 | 10,8 | 14,3 |
| Qwen2.5-Coder 7B | 789 | 658 | 667 | 626 | 0,558 | 0,497 | 0,545 | 0,551 | 6,1 | 8,4 |
| Llama 3.1 8B | 591 | 475 | 850 | 824 | 0,418 | 0,358 | 0,554 | 0,476 | 5,9 | 10,5 |

**Score** é TPR − FPR sobre o corpus inteiro, como calculado pelos scripts de piloto.
**Score (OWASP)** é a média de TPR − FPR entre as 11 categorias, que é o cálculo do
scorecard oficial. As duas medidas diferem porque as categorias têm tamanhos
distintos; na comparação com as ferramentas SAST, vale a do scorecard.

### Por categoria de CWE (TPR / FPR)

| CWE | Categoria | Qwen 14B | Qwen 7B | Llama 8B |
|---|---|---|---|---|
| 22 | Path traversal | 0,970 / 0,889 | 0,932 / 0,948 | 0,075 / 0,015 |
| 78 | Injeção de comando | 1,000 / 1,000 | 1,000 / 1,000 | 0,167 / 0,112 |
| 79 | XSS | 0,951 / 0,589 | 0,846 / 0,603 | 0,923 / 0,804 |
| 89 | Injeção de SQL | 0,996 / 0,970 | 1,000 / 1,000 | 1,000 / 1,000 |
| 90 | Injeção de LDAP | 0,963 / 0,844 | 0,519 / 0,562 | 0,333 / 0,125 |
| 327 | Criptografia fraca | 0,000 / 0,000 | 0,000 / 0,078 | 0,000 / 0,000 |
| 328 | Hash fraco | 0,016 / 0,000 | 0,000 / 0,000 | 0,000 / 0,000 |
| 330 | Aleatoriedade fraca | 0,000 / 0,000 | 0,000 / 0,000 | 0,037 / 0,127 |
| 501 | Fronteira de confiança | 0,000 / 0,000 | 0,012 / 0,000 | 0,000 / 0,000 |
| 614 | Cookie inseguro | 0,833 / 0,000 | 0,806 / 0,000 | 0,806 / 0,000 |
| 643 | Injeção de XPath | 0,933 / 0,800 | 1,000 / 1,000 | 1,000 / 1,000 |

**Injeção.** Nas categorias de injeção, os modelos Qwen detectam quase todos os casos
reais, mas apontam também quase todos os corrigidos (FPR entre 0,56 e 1,00). Isso
confirma no corpus completo o que o piloto indicava: os modelos avaliam a estrutura
do código, e não se a sanitização é eficaz. Converge com o achado de Gnieciak e
Szandala (2025), que reportam vantagem em recall ao custo de falsos positivos.

**Criptografia e fronteira de confiança.** CWE-327, 328, 330 e 501 seguem
praticamente sem detecção em todos os modelos, mesmo listadas no prompt.

**Cookie inseguro.** CWE-614 é a única categoria com separação clara: TPR acima de
0,8 e nenhum falso positivo nos três modelos.

### Concordância entre Qwen 14B e 7B

O piloto indicava classificação idêntica entre os dois modelos Qwen. **O corpus
completo refuta esse resultado:** a classificação divergiu em 157 dos 2.740 casos
(5,7%), e a resposta (vulnerável/CWE) em 165 (6,0%). As divergências se concentram em
XSS (77), path traversal (29) e injeção de LDAP (23). A lista completa está em
`resultados/analise/concordancia_qwen.csv`. Os modelos concordam em 94,3% dos casos,
e a diferença de porte se reflete em um Score (OWASP) de 14,3 contra 8,4, em favor do
14B.

### Comportamento do Llama 3.1 8B

O Llama marcou 2.692 dos 2.740 casos (98,2%) como vulneráveis, 1.975 deles como
injeção de SQL. Em 1.626 respostas, a CWE apontada não era a do caso. O FPR menor
que o dos Qwen não indica comportamento mais conservador, como o piloto sugeria:
resulta de o modelo apontar a CWE errada, o que o critério conta como negativo. Nos
Qwen, a CWE divergiu em apenas 3 (14B) e 18 (7B) respostas.

### Tempo de execução

| Modelo | Mediana | Média | Total |
|---|---|---|---|
| Qwen2.5-Coder 14B | 2,70 s | 2,71 s | 2,06 h |
| Qwen2.5-Coder 7B | 2,38 s | 2,38 s | 1,81 h |
| Llama 3.1 8B | 2,39 s | 2,39 s | 1,82 h |

### Critério de CWE exata

O critério do OWASP Benchmark só conta a detecção se a CWE apontada for a esperada.
Para verificar se isso distorce a medição, `criterio_cwe.py` reclassifica as
respostas da execução v2 sem essa exigência: basta `vulnerable: true` no caso real
(TP) ou no negativo (FP).

| Modelo | Critério | TPR | FPR | Precisão | F1 | Score | Score (OWASP) |
|---|---|---|---|---|---|---|---|
| Qwen2.5-Coder 14B | CWE exata | 0,588 | 0,480 | 0,567 | 0,577 | 10,8 | 14,3 |
| | Sem CWE | 0,589 | 0,481 | 0,567 | 0,578 | 10,9 | 14,4 |
| Qwen2.5-Coder 7B | CWE exata | 0,558 | 0,497 | 0,545 | 0,551 | 6,1 | 8,4 |
| | Sem CWE | 0,566 | 0,501 | 0,547 | 0,556 | 6,5 | 9,6 |
| Llama 3.1 8B | CWE exata | 0,418 | 0,358 | 0,554 | 0,476 | 5,9 | 10,5 |
| | Sem CWE | 0,994 | 0,970 | 0,523 | 0,685 | 2,5 | 2,4 |

**Nos Qwen, o critério quase não pesa.** A CWE apontada é quase sempre a esperada,
e sem a exigência o Score sobe apenas 0,1 ponto no 14B e 0,4 no 7B.

**No Llama, o critério sem CWE mostra que o veredito não discrimina.** Sem exigir a
CWE, ele aponta 1.407 dos 1.415 casos reais, mas também 1.285 dos 1.325 negativos: o
TPR vai a 0,994 e o FPR a 0,970, e o Score cai de 5,9 para 2,5 (OWASP: de 10,5 para
2,4). O pouco de discriminação que o modelo tem está na CWE escolhida. Em cookie
inseguro, por exemplo, ele responde CWE-614 em 29 dos 36 casos reais e CWE-89 em 27
dos 31 negativos. O critério de CWE exata, portanto, não penaliza o Llama: é ele que
captura o único sinal do modelo.

A desagregação por categoria sob o critério sem CWE está em
`resultados/analise/por_cwe_sem_cwe.csv`.

#### Categorias sem detecção

Nos casos reais de criptografia fraca, hash fraco, aleatoriedade fraca e fronteira de
confiança, a hipótese de que os modelos reportariam CWEs vizinhas (CWE-338 no lugar de
CWE-330, CWE-327 no lugar de CWE-328) não se confirma:

| Modelo | Categoria | Casos reais | `vulnerable: false` | Outra CWE | CWE esperada |
|---|---|---|---|---|---|
| Qwen2.5-Coder 14B | crypto (327) | 130 | 130 | 0 | 0 |
| | hash (328) | 129 | 127 | 0 | 2 |
| | weakrand (330) | 218 | 218 | 0 | 0 |
| | trustbound (501) | 83 | 83 | 0 | 0 |
| Qwen2.5-Coder 7B | crypto (327) | 130 | 130 | 0 | 0 |
| | hash (328) | 129 | 126 | 3 (CWE-327) | 0 |
| | weakrand (330) | 218 | 218 | 0 | 0 |
| | trustbound (501) | 83 | 82 | 0 | 1 |
| Llama 3.1 8B | crypto (327) | 130 | 0 | 130 (CWE-89) | 0 |
| | hash (328) | 129 | 0 | 129 (CWE-89) | 0 |
| | weakrand (330) | 218 | 6 | 204 (CWE-89: 147, CWE-327: 54, CWE-328: 3) | 8 |
| | trustbound (501) | 83 | 2 | 81 (CWE-89) | 0 |

Os Qwen respondem `vulnerable: false` em 97,7% a 100% desses casos: a ausência de
detecção é real, e não um artefato do critério de CWE. A única troca por CWE vizinha
são 3 casos de hash em que o 7B reportou CWE-327. A CWE-338 não aparece em nenhuma
resposta, e nenhuma resposta de nenhuma execução traz CWE fora das 11 listadas no
prompt. O Llama aponta quase todos esses casos como vulneráveis, mas como injeção de
SQL, sem relação com a categoria.

O prompt v2 define como vulnerável o código em que a entrada não confiável alcança a
operação sensível, definição que não descreve bem falhas de criptografia ou de
aleatoriedade. O piloto v1, que não tinha essa frase, também respondeu
`vulnerable: false` nos 6 casos reais dessas categorias presentes na amostra; o
número é pequeno, mas indica que a definição não é a causa da ausência de detecção.

Detalhes em `sem_deteccao_respostas.csv` e `sem_deteccao_cwes.csv`, em
`resultados/analise/`.

#### Casos negativos nas categorias de injeção

Casos com `vulnerable: true`, independentemente da CWE:

| Modelo | cmdi reais | cmdi negativos | sqli reais | sqli negativos | xpathi reais | xpathi negativos |
|---|---|---|---|---|---|---|
| Qwen2.5-Coder 14B | 126/126 | 125/125 | 271/272 | 225/232 | 14/15 | 16/20 |
| Qwen2.5-Coder 7B | 126/126 | 125/125 | 272/272 | 232/232 | 15/15 | 20/20 |
| Llama 3.1 8B | 126/126 | 125/125 | 272/272 | 232/232 | 15/15 | 20/20 |

O 7B e o Llama apontam como vulneráveis 100% dos casos negativos deliberados das três
categorias, e o 14B deixa de apontar apenas 7 dos 232 negativos de sqli e 4 dos 20 de
xpathi. Os modelos praticamente não distinguem o código vulnerável de sua versão
sanitizada. Detalhes em `resultados/analise/injecao_respostas.csv`.

### Estabilidade entre repetições

Além da execução v2, cada modelo foi executado três vezes sobre o corpus completo,
com o mesmo prompt, temperatura zero e a mesma ordem de casos (`repeticoes.py`). As
nove repetições classificaram os 2.740 casos sem falha de interpretação nem de
chamada ao modelo.

| Modelo | Classificação variou | Veredito variou | CWE variou | Difere da v2 |
|---|---|---|---|---|
| Qwen2.5-Coder 14B | 0 (0,00%) | 0 (0,00%) | 0 (0,00%) | 8 (0,29%) |
| Qwen2.5-Coder 7B | 6 (0,22%) | 5 (0,18%) | 1 (0,04%) | 6 (0,22%) |
| Llama 3.1 8B | 12 (0,44%) | 1 (0,04%) | 14 (0,51%) | 12 (0,44%) |

*Classificação variou*: TP/FP/TN/FN não é a mesma nas três repetições. *Veredito
variou*: o campo `vulnerable` mudou. *CWE variou*: vulnerável nas três repetições,
mas com CWEs diferentes. *Difere da v2*: a classificação da execução v2 difere da de
ao menos uma repetição. Os casos estão em `resultados/analise/estabilidade_divergentes.csv`.

Faixa das métricas nas quatro execuções (v2 e as três repetições):

| Modelo | TPR | FPR | F1 | Score | Score (OWASP) |
|---|---|---|---|---|---|
| Qwen2.5-Coder 14B | 0,588–0,591 | 0,480 | 0,577–0,579 | 10,8–11,1 | 14,3–14,9 |
| Qwen2.5-Coder 7B | 0,558 | 0,494–0,497 | 0,551–0,552 | 6,1–6,4 | 8,4–9,1 |
| Llama 3.1 8B | 0,416–0,418 | 0,358 | 0,475–0,476 | 5,8–5,9 | 9,7–10,5 |

**Temperatura zero não garante resposta idêntica.** Apenas o Qwen 14B repetiu a
mesma resposta nos 2.740 casos nas três repetições. No 7B, a variação está no
veredito; no Llama, quase toda na escolha da CWE, coerente com o comportamento de
apontar quase todos os casos como vulneráveis.

**Execução v2 do Qwen 14B.** As três repetições do 14B são idênticas entre si, mas
diferem da v2 em 8 casos, distribuídos ao longo da execução e entre categorias, sem
alteração de tempo de resposta. O código, o modelo e a versão do Ollama (0.34.4) são
os mesmos. A causa não foi identificada; uma hipótese é o não determinismo
numérico da inferência em GPU entre sessões de carregamento do modelo.

**Efeito nas métricas.** A variação é pequena e não altera a ordem entre os modelos
em nenhuma das execuções: 14B > 7B > Llama pelo Score e 14B > Llama > 7B pelo Score
(OWASP). O Score (OWASP) é mais sensível, com variação de até 0,8 ponto, porque a
média por categoria amplia mudanças nas categorias menores.

## Estudo piloto

Registro da decisão metodológica sobre o prompt. A comparação entre modelos feita no
piloto foi substituída pelos resultados do corpus completo, acima.

Amostra de 30 casos, estratificada por categoria de CWE e por rótulo, com semente fixa.

### Efeito do prompt (Qwen2.5-Coder 14B)

| Métrica | Prompt genérico | Prompt com CWEs |
|---|---|---|
| TPR (recall) | 0,200 | 0,600 |
| FPR | 0,200 | 0,533 |
| Precisão | 0,500 | 0,529 |
| F1-score | 0,286 | 0,562 |
| Benchmark Score | 0,0 | 6,7 |
| Falhas de parse | 0 | 0 |

O prompt genérico levava o modelo a ancorar em injeção de SQL, reportando CWE-89 para
LDAP injection, XSS e path traversal. Explicitar as categorias eliminou a confusão e
triplicou a taxa de detecção. A versão com as CWEs explicitadas foi adotada por
corresponder ao conjunto de regras que as ferramentas SAST carregam, tornando a
comparação entre as abordagens equivalente.

O arquivo `piloto.py` tinha os acentos do prompt corrompidos por erro de codificação.
Após a correção, o piloto v1 foi executado novamente e produziu resposta idêntica nos
30 casos, com as mesmas métricas da tabela acima.

## Divisão de responsabilidades

| Eixo | Responsável |
|---|---|
| Ferramentas SAST | Pedro Henrique Oliveira Siqueira |
| Modelos de linguagem | Samuel Vitor Cardoso Santos |
| Fundamentação, discussão e redação | Ambos |

## Referências

GNIECIAK, D.; SZANDALA, T. Large language models versus static code analysis tools:
a systematic benchmark for vulnerability detection. **IEEE Access**, v. 13,
p. 198410–198422, 2025.

LI, K. et al. Comparison and evaluation on static application security testing (SAST)
tools for Java. In: **31st ACM Joint European Software Engineering Conference and
Symposium on the Foundations of Software Engineering**, 2023.

OWASP FOUNDATION. **OWASP Benchmark Project**.
Disponível em: https://owasp.org/www-project-benchmark/

ZHOU, X. et al. **Comparison of static application security testing tools and large
language models for repo-level vulnerability detection**. arXiv:2407.16235, 2024.

ZHOU, X.; CAO, S.; SUN, X.; LO, D. Large language model for vulnerability detection
and repair: literature review and the road ahead. **ACM Transactions on Software
Engineering and Methodology**, v. 34, n. 5, 2025.
