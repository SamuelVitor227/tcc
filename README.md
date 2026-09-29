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
├── piloto2.py                 # piloto v2 — prompt com as CWEs explicitadas
├── ver.py                     # inspeção das respostas brutas
└── resultados/
    ├── bruto_*.jsonl          # saída bruta do piloto v1
    └── bruto_v2_*.jsonl       # saída bruta do piloto v2
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
python piloto2.py                             # 30 casos, Qwen 14B
python piloto2.py --n 100                     # amostra maior
python piloto2.py --modelo llama3.1:8b        # outro modelo
```

## Protocolo

- Temperatura fixada em zero
- Prompt definido previamente e reproduzido no apêndice do artigo
- Saída bruta persistida em disco antes de qualquer processamento, permitindo
  reprocessar sem nova execução
- Amostragem estratificada por categoria de CWE e por rótulo, com semente fixa
- Execuções sequenciais, sem processamento concorrente, para não interferir na
  medição de tempo

### Critério de classificação

Apontar a CWE esperada em um caso real conta como verdadeiro positivo; apontá-la em
um caso negativo, como falso positivo. Não apontar, ou apontar CWE divergente, conta
como falso negativo em caso real e verdadeiro negativo em caso negativo.

## Resultados do estudo piloto

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

### Comparação entre modelos (prompt com CWEs)

| Modelo | TPR | FPR | Precisão | F1 | Score | Mediana |
|---|---|---|---|---|---|---|
| Qwen2.5-Coder 14B | 0,600 | 0,533 | 0,529 | 0,562 | 6,7 | 2,7 s |
| Qwen2.5-Coder 7B | 0,600 | 0,533 | 0,529 | 0,562 | 6,7 | 2,4 s |
| Llama 3.1 8B | 0,333 | 0,267 | 0,556 | 0,417 | 6,7 | 2,4 s |

Nenhum dos três apresentou falha de interpretação da resposta.

**Escala.** Os dois modelos da família Qwen produziram classificação idêntica em
todos os 30 casos, apesar da diferença de porte. A confirmação depende da execução
sobre o corpus completo, dado o tamanho da amostra.

**Especialização.** O modelo generalista detectou menos (TPR 0,333 contra 0,600), mas
sinalizou menos casos negativos (FPR 0,267 contra 0,533), apresentando comportamento
mais conservador.

**Sobre o Benchmark Score.** Os três modelos obtiveram 6,7, embora com perfis
distintos: o ganho em detecção veio acompanhado de aumento proporcional em falsos
positivos. A observação reforça a decisão de reportar também precisão e F1-score.

### Limitações observadas

1. Os três modelos produzem resposta idêntica para o caso vulnerável e para sua
   versão corrigida nas categorias de injeção, indicando avaliação da estrutura do
   código e não da eficácia da sanitização. Converge com o achado de Gnieciak e
   Szandala (2025), que reportam vantagem em recall ao custo de falsos positivos.
2. As categorias de criptografia fraca (CWE-327), hash fraco (CWE-328), aleatoriedade
   previsível (CWE-330) e violação de fronteira de confiança (CWE-501) não produziram
   nenhuma detecção em nenhum dos modelos, mesmo listadas explicitamente no prompt.

### Tempo de execução

Mediana entre 2,4 s e 2,7 s por caso. Extrapolando para os 2.740 casos, três
repetições e três modelos: aproximadamente 18 a 21 horas de processamento.

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
