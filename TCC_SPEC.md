# Especificacao do TCC

## 1. Projeto e objetivo

O SmartSec e uma ferramenta open source para automatizar testes de seguranca em fluxos DevSecOps. A ferramenta recebe um IP, dominio ou URL, orquestra scanners em ambiente isolado, interpreta os resultados com apoio de inteligencia artificial, apresenta o progresso em uma TUI e gera relatorios compreensiveis com evidencias e recomendacoes.

O objetivo geral e desenvolver uma ferramenta capaz de orquestrar analises de seguranca em ambiente isolado e interpretar seus resultados com IA agentica, reduzindo a dependencia de especialistas para equipes de engenharia de software.

O SmartSec nao substitui integralmente um especialista. Resultados devem ser rastreaveis, apresentar evidencias e deixar claras as limitacoes, incertezas e falhas de execucao.

## 2. Publico-alvo

- Engenheiro de software.
- Desenvolvedor autonomo.
- Estudante de Tecnologia da Informacao.
- Analista DevSecOps.

## 3. Escopo funcional

### Entradas

- IP, dominio ou URL de aplicacao web.
- Parametros de linha de comando.
- Arquivo de configuracao.
- Selecao de ferramentas e modelo de IA.

### Processamento

- Execucao manual ou automatica de scanners.
- Execucao em containers Podman rootless.
- Coleta e persistencia de stdout e stderr.
- Interpretacao dos logs por LLM.
- Decisao dinamica sobre testes subsequentes.
- Classificacao por severidade.
- Correlacao, deduplicacao e enriquecimento com CVE/NVD.
- Regras automaticas de interrupcao.

### Ferramentas previstas

Nmap, Nuclei, OWASP ZAP, SQLMap, Nikto e TruffleHog. O SmartSec orquestra ferramentas existentes; nao desenvolve scanners proprios.

### Modelos previstos

- GPT-4o remoto.
- Llama 3.1 8B via Ollama local.
- Claude somente se for mantido como compromisso explicito na matriz de escopo.

### Interfaces e saidas

- CLI para execucao e automacao.
- TUI para configuracao, progresso, logs e resultados.
- Modo headless para CI/CD.
- Logs estruturados e historico de execucoes.
- Relatorios Markdown e PDF.
- Exit codes padronizados.
- Recomendacoes de remediacao em linguagem acessivel.

### Plataforma

O foco principal e Linux, com Podman rootless como engine de isolamento e GitHub Actions como ambiente principal de validacao CI/CD. Docker pode ser usado apenas como contingencia documentada, nao como substituto silencioso do requisito Podman.

## 4. Requisitos funcionais

| ID | Requisito |
|---|---|
| REQ01 | Configurar alvo por IP, dominio ou URL via CLI. |
| REQ02 | Configurar ambiente, parametros e ferramentas. |
| REQ03 | Selecionar modelo de IA, incluindo GPT-4o, Claude se mantido, e Ollama. |
| REQ04 | Integrar a execucao a CI/CD em eventos como push, merge ou build. |
| REQ05 | Configurar regras de interrupcao automatica, por exemplo quantidade de achados criticos. |
| REQ06 | Executar ferramentas automaticamente e de forma orquestrada. |
| REQ07 | Executar ferramentas em containers Podman rootless. |
| REQ08 | Permitir executar manualmente ferramentas especificas sem decisao automatica. |
| REQ09 | Coletar e armazenar logs tecnicos. |
| REQ10 | Interpretar logs por IA. |
| REQ11 | Integrar CVE/NVD para validar e enriquecer achados. |
| REQ12 | Decidir dinamicamente as ferramentas seguintes. |
| REQ13 | Mostrar progresso em tempo real na TUI. |
| REQ14 | Pausar, retomar ou interromper execucoes manualmente. |
| REQ15 | Destacar vulnerabilidades criticas. |
| REQ16 | Traduzir resultados para linguagem compreensivel, com impacto e correcoes. O campo didatico do achado entra no relatorio como "Em linguagem simples", junto de impacto e recomendacao. |
| REQ17 | Gerar relatorio com vulnerabilidades, severidade, evidencias e recomendacoes. Inclui resumo por severidade (inclusive Info), pontos criticos, lista completa, proveniencia, analise da IA e execucoes com falha. |
| REQ18 | Exportar relatorios Markdown e PDF, no mesmo diretorio e com o mesmo nome, a partir do mesmo conteudo sanitizado. |
| REQ19 | Manter historico consultavel para auditoria. |

### Rastreabilidade da correlacao e do enriquecimento CVE/NVD

| Requisito | Onde e atendido | Evidencia |
|---|---|---|
| REQ11 — integrar CVE/NVD para enriquecer achados | `src/orchestrator/nvd.rs` (cliente, cache, limite de taxa), `src/orchestrator/enrichment.rs` (driver), campos `enrichment` e `severity_conflict` em `src/domain/vulnerability.rs` | `docs/evidence/issue-19-correlacao-nvd.md` §2, §3 |
| REQ12 (deduplicacao) — sem perder endpoints nem origens | `src/orchestrator/correlation.rs`, campo `origins` em `src/domain/vulnerability.rs` | `docs/evidence/issue-19-correlacao-nvd.md` §1, §7 |
| Regra de severidade do scanner autoritativa (secao 7) | `correlate` usa o maximo sem reclassificar; `annotate_nvd_divergence` preserva as duas classificacoes | `conflito_entre_scanners_preserva_as_duas_severidades`, `enriquecimento_nunca_reclassifica_a_severidade_do_scanner` |
| Evidencia minima e sanitizada | `Vulnerability::sanitized` cobre `origins` e `enrichment`; erro HTTP traduzido por categoria | `docs/evidence/issue-19-correlacao-nvd.md` §6 |
| Secao 7 — indisponibilidade nao impede o relatorio base | `NvdOutcome::Unavailable` em todos os caminhos, sem `unwrap` | `indisponibilidade_da_nvd_nao_impede_o_relatorio_base`, §4 |
Rastreabilidade do REQ19 (Sprint 2, issue #24): a CLI expoe `history` para listar as execucoes e `show <SCAN_ID>` para abrir uma delas; a TUI expoe a tela `Historico`, aberta com a tecla `h` ou pela paleta de comandos. A listagem varre `~/.config/smartsec/scans/*.json` e a leitura e somente leitura: nenhum artefato original e alterado. A evidencia esta em `docs/evidence/issue-24-historico.md`.

### Pausa, retomada, cancelamento e interrupcao automatica

Pausar e retomar afetam o container em execucao, e nao apenas a interface: a ordem chega ao executor Podman e vira `podman pause` e `podman unpause` no container real. Na TUI, `p` alterna pausa e retomada e `c` cancela, com equivalencia por mouse (botoes `Pausar/Retomar varredura` e `Cancelar varredura`) e pela paleta de comandos. No modo headless o cancelamento vem de `SIGINT` e `SIGTERM`.

O cancelamento e cooperativo e sempre precede qualquer `abort()` de task: o processo dentro do container e encerrado com `podman stop --time 5` (com `podman kill` como recurso) e o container e removido com `podman rm --force --ignore`. O guard `ContainerCleanup` continua como ultima linha de defesa para os caminhos de erro e de queda do processo. Ordens que chegam antes do `create`, durante o `create` ou durante o `start` tambem convergem para `rm --force --ignore`: nao existe estagio do ciclo de vida do container que fique sem limpeza.

A regra automatica de interrupcao e configuravel por `max_critical_findings` no TOML e por `--max-critical-findings` na CLI, com precedencia da CLI. `0` (padrao) mantem a regra desativada. A avaliacao ocorre **entre** ferramentas, para que a evidencia recem-coletada nao seja descartada e para nao matar o container que acabou de produzir o achado. Ao disparar, o pipeline para e o motivo fica registrado de forma auditavel em `ScanMetadata.interruption`, com a regra, a mensagem em pt-BR, a ferramenta em que disparou, a contagem observada e o limiar configurado. Historicos gravados antes desta feature continuam legiveis, porque o campo novo tem `#[serde(default)]`.

A regra nao altera agressividade, permissao ou concorrencia de nenhum scanner: ela age somente sobre o momento de interromper a orquestracao.

## 5. Requisitos nao funcionais

| ID | Requisito |
|---|---|
| RNF01 | Isolamento com Podman rootless. |
| RNF02 | Boa performance e baixo tempo de resposta. |
| RNF03 | Compatibilidade com Linux. |
| RNF04 | Interpretacao de logs pela IA em ate 45 segundos por ferramenta. |
| RNF05 | HTTPS e autenticacao por token nas APIs externas. |
| RNF06 | Retentativa limitada e fallback para modelo local. |
| RNF07 | TUI responsiva e legivel em terminal minimo de 80x24. |
| RNF08 | Adicionar ferramentas por configuracao sem recompilar o nucleo. |
| RNF09 | Logs persistentes, versoes e hashes das ferramentas para reproducibilidade. |
| RNF10 | Proteger dados sensiveis e obter consentimento antes de enviar logs a IA remota. |
| RNF11 | Modo headless com exit codes padronizados. |

## 6. Arquitetura esperada

```text
CLI/TUI
  -> configuracao e validacao do alvo
  -> orquestrador
       -> executor Podman rootless
       -> runners e parsers das ferramentas
       -> logs e historico
       -> agente de IA e provedores remoto/local
       -> correlacao e enriquecimento CVE/NVD
  -> resultados estruturados
       -> TUI, Markdown, PDF e CI/CD
```

Modulos atuais do prototipo:

- `src/main.rs`: entrada CLI, TUI e headless.
- `src/tui/`: telas, eventos e estado da interface.
- `src/orchestrator/`: pipeline, sandbox e parsers.
- `src/tools/`: manifesto e registry extensivel de ferramentas, alem dos runners reais de Nmap, Nuclei, Nikto, SQLMap, TruffleHog e ZAP.
- `src/ai/` e `src/llm/`: agente e provedores LLM.
- `src/tools/`: manifesto e registry extensivel de ferramentas, alem dos runners reais de Nmap, Nuclei e Nikto.
- `src/ai/`: agente, servico unico de analise e provedores LLM.
- `src/domain/`: severidade, ferramentas e vulnerabilidades.
- `src/config/`: configuracao e persistencia.
- `src/report/`: geracao de relatorios em Markdown e PDF, resolucao do caminho de saida e fonte embutida.

## 7. Estado conhecido do prototipo

O prototipo possui TUI, configuracao, suporte a mouse, relatorio Markdown e integracao real com Nmap, Nuclei, Nikto, SQLMap, TruffleHog e ZAP. As seis executam em containers Podman rootless; ferramentas sem runner real nao entram no catalogo executavel. A TUI e o modo headless usam o mesmo pipeline, preservam falhas de execucao e gravam logs estruturados para auditoria.

Nenhum finding demonstrativo pode ser misturado a uma execucao real. O fluxo executavel nao oferece modo demonstrativo; a origem legada `Demo` permanece apenas para leitura de historicos ja persistidos.

Cada finding deve manter campos proprietarios e proveniencia com origem, ferramenta, alvo, evidencia e timestamp. O fluxo real somente aceita achados produzidos pelos parsers dos scanners executados. A severidade estruturada do scanner e autoritativa: texto gerado por IA pode orientar a remediacao, mas nao pode reclassificar o achado. Todo texto operacional gerado pelo SmartSec e apresentado em portugues brasileiro.

Na Sprint 1, Nmap e Nuclei reais executam exclusivamente em Podman rootless. A rede `pasta` mapeia `169.254.1.2` dentro do scanner para o loopback do host, permitindo analisar um alvo autorizado publicado somente em `127.0.0.1` sem exposicao na rede local. A imagem do Nuclei e referenciada por digest, os templates sao montados em modo somente leitura, a configuracao temporaria fica restrita a tmpfs, condicao essa verificada em execucao e nunca presumida a partir do TMPDIR do ambiente, e o commit esperado deve ser validado antes da execucao. O Nmap usa TCP connect sem capabilities adicionais. O plano validado pelo orquestrador e aplicado aos argumentos do container. Cada registro estruturado preserva stdout e stderr sanitizados, status, duracao, timestamp, versao e imagem/digest quando aplicavel, alem do trace operacional sanitizado do Podman (comandos executados, saida do pull da imagem, inicio do container e limpeza), exibido ao vivo na TUI e no modo headless. Corpos de requisicao/resposta HTTP, comandos curl, credenciais e query strings nao podem aparecer em findings, auditorias ou relatorios; a evidencia minima preserva template, matcher, endpoint, host, URL e tags.
Na Sprint 2, a correlacao e o enriquecimento CVE/NVD entram no fluxo real apos a construcao dos achados, antes da analise por IA e da emissao do relatorio. O achado ganha tres campos aditivos, todos com `#[serde(default)]` para que os logs de auditoria gravados antes destamudanca continuem desserializando:

- `origins`: todas as origens que reportaram o mesmo problema, cada uma com ferramenta, severidade, evidencia e timestamp proprios. Fica vazio quando o achado nao foi agrupado;
- `enrichment`: contexto consultado na NVD, com `cve_id`, `cvss_base_score`, `cvss_vector`, `cvss_severity`, `cvss_version`, `reference`, `queried_at` (ISO-8601, obrigatorio) e `from_cache`;
- `severity_conflict`: divergencia de severidade entre scanners ou entre scanner e NVD, preservando as duas classificacoes.

Regra de correlacao: dois achados sao o mesmo problema quando, no mesmo alvo, compartilham uma identidade estruturada emitida pelo proprio scanner. As chaves sao `cve:<id>@<endpoint>`, `osvdb:<id>@<endpoint>`, `nuclei:<template>|<matcher>@<endpoint>`, `nikto:<referencia>@<url>` e `nmap:<porta>/<servico>/<produto>`, sempre acompanhadas do alvo. Semelhanca textual entre titulo, descricao e texto didatico nao gera correlacao, e evidencia sem identidade estrutural — como a saida do parser `generic-text` — nunca e mesclada. A severidade do grupo e a mais alta entre as origens, porque a severidade de cada scanner e autoritativa e o agrupamento apenas agrega: rebaixar esconderia um achado critico porque outro scanner omitiu a mesma anomalia com rotulo menor. Divergencias sao registradas em `severity_conflict` e todas as origens permanecem acessiveis em `origins`.

O enriquecimento usa a API NVD v2 em `https://services.nvd.nist.gov/rest/json/cves/2.0`, com a metrica CVSS preferencial sendo a `Primary` da propria NVD na ordem 4.0, 3.1, 3.0 e 2.0. As consultas sao sequenciais e respeitam o intervalo minimo publicado pela NVD: 6 segundos sem chave de API (5 requisicoes a cada 30 segundos) e 0,6 segundo com chave (50 a cada 30 segundos). A chave e opcional, lida de `SMARTSEC_NVD_API_KEY`, e nunca e gravada em arquivo, log, relatorio ou tela. HTTP 429 e 5xx recebem uma retentativa com backoff exponencial limitado; a NVD pode responder `Retry-After: 0`, que nao serve como espera. Cada consulta e gravada em `<config_dir>/smartsec/nvd-cache/{CVE}.json` com validade de 7 dias, e a data original da consulta viaja com a entrada mesmo quando a resposta vem do cache, porque dado de terceiro envelhece e o relatorio precisa declarar quando foi obtido.

Indisponibilidade da NVD — cliente nao inicializado, DNS, conexao recusada, timeout, HTTP 429, HTTP 4xx, HTTP 5xx, JSON malformado ou envelope inesperado — nunca interrompe a varredura nem impede o relatorio base: os achados saem inalterados, a severidade do scanner permanece a mesma e a causa fica visivel na TUI, no modo headless, no relatorio e no log estruturado. A indisponibilidade da NVD e um aviso, nao um erro de execucao: ela nao altera o codigo de saida. Um identificador ausente da base e um resultado, nao uma falha, e e contabilizado separadamente. Nenhum desses caminhos usa `unwrap`, `expect` ou `panic`. Corpos HTTP, comandos curl, credenciais e query strings nao podem aparecer nos campos de enriquecimento: o erro do cliente HTTP e traduzido por categoria, e nao pelo texto original, que contem a URL com a query string.
A interpretacao dos logs por IA passa por um unico servico (`src/ai/analysis_service.rs`), usado pela TUI e pelo modo headless atraves de `Orchestrator::analyze_findings`. O servico e um campo do orquestrador, compartilhado pelos dois modos, e nao uma instancia criada por chamada. Ele concentra, em ordem, a verificacao de consentimento e de configuracao, a chamada ao provedor principal, a validacao da resposta, a alternativa local e a analise deterministica; nenhum outro caminho pode chamar o agente diretamente. O teto de 45 segundos (RNF04) e um orcamento unico e dividido: o provedor principal recebe 3/4 do prazo e a alternativa local fica com o restante, porque `timeout_secs` do provedor pode ser igual ao teto inteiro e, sem a divisao, um provedor que travasse consumiria tudo e a alternativa local nunca seria chamada. O resultado e estruturado e identifica modelo, provedor efetivo, uso da alternativa local, motivo da falha quando houver e o horario da analise. O motivo da falha e registrado tambem quando a alternativa local responde com sucesso: um fallback sem causa pareceria uma escolha do operador em vez de uma queda. O log estruturado de um scan grava, alem dos campos ja existentes, `llm_model`, `llm_provider_effective` (provedor configurado permanece em `llm_provider`), `llm_fallback_used`, `llm_failure_reason`, `llm_analyzed_at` e `llm_neutralized_snippets`; todos usam valor padrao na desserializacao para que historicos gravados antes destes campos continuem carregando. `llm_failure_reason` e um diagnostico do proprio SmartSec e usa a sanitizacao de diagnostico, que preserva a frase e remove apenas a credencial: a sanitizacao de texto de scanner a substituiria por `[REDACTED]`, ja que o erro de transporte do cliente HTTP menciona `request`. Conteudo coletado do alvo e tratado como entrada nao confiavel: e enviado dentro de um bloco explicitamente delimitado, com instrucao de que e dado a analisar e nunca comando a executar. Delimitadores de sistema sao removidos sem diferenciar maiusculas de minusculas, e a busca por tentativas de reescrever a tarefa e feita sobre o texto inteiro, e nao linha a linha, para que uma ordem quebrada em duas linhas tambem seja neutralizada. O total de trechos neutralizados e persistido; o achado original nao e alterado.

Na Sprint 1, Nmap e Nuclei reais executam exclusivamente em Podman rootless. A rede `pasta` mapeia `169.254.1.2` dentro do scanner para o loopback do host, permitindo analisar um alvo autorizado publicado somente em `127.0.0.1` sem exposicao na rede local. A imagem do Nuclei e referenciada por digest, os templates sao montados em modo somente leitura, a configuracao temporaria fica restrita a tmpfs e o commit esperado deve ser validado antes da execucao. O Nmap usa TCP connect sem capabilities adicionais. O plano validado pelo orquestrador e aplicado aos argumentos do container. Cada registro estruturado preserva stdout e stderr sanitizados, status, duracao, timestamp, versao e imagem/digest quando aplicavel, alem do trace operacional sanitizado do Podman (comandos executados, saida do pull da imagem, inicio do container e limpeza), exibido ao vivo na TUI e no modo headless. Corpos de requisicao/resposta HTTP, comandos curl, credenciais e query strings nao podem aparecer em findings, auditorias ou relatorios; a evidencia minima preserva template, matcher, endpoint, host, URL e tags.

Na Sprint 2, o Nikto entra no portfolio real com imagem fixada por digest (`docker.io/alpine/nikto:2.2.0@sha256:eb2fe88217ec32695f3843f67c7a7f1628b484b653e99015aac69c586eb2a88b`, versao `2.1.6`) e runner `generic`. O modo JSON exige um destino de saida no proprio scanner: a flag `-o -` faz o Nikto escrever o relatorio no stdout, sem shell e sem arquivo, o que e compativel com o filesystem somente leitura do executor; `-ask no` e obrigatorio porque o prompt de envio ao CIRT.net, quando habilitado, contamina o stdout e corrompe o JSON. O parser `nikto-json` preserva URL (reconstruida a partir do alvo e do caminho relativo), metodo HTTP, referencia (ID do Nikto e OSVDB) e evidencia minima sanitizada, sem corpos HTTP, credenciais ou query strings. O Nikto nao emite campo de severidade: a severidade e derivada da taxonomia de IDs do proprio scanner e da referencia OSVDB, e nao de interpretacao do texto da mensagem. JSON invalido, stdout vazio, alvo sem servidor web (o Nikto termina com status 0 e informa o codigo interno `000029`) e exit status diferente de zero sao tratados como `failed` com mensagem acionavel em pt-BR; timeout e exit status vem do executor Podman e sao preservados. A evidencia da execucao real contra alvo local esta em `docs/evidence/issue-14-nikto.md`.

Na Sprint 2, o SQLMap entra no portfolio real com imagem fixada por digest (`docker.io/parrotsec/sqlmap:7.3@sha256:31bb35cd9fdc8c00d3673d26c48a59d2d8ea3c4955c252fb5dee2f96992b4596`, versao `1.10.4`) e runner `generic`. O SQLMap nao possui modo JSON, entao o parser `sqlmap-text` le o bloco de injecoes confirmadas do stdout. Medido em container: `--batch` e obrigatorio, porque sem ele o scanner bloqueia em `_input()` esperando o prompt de confirmacao; `--answers=exploit=N,...` e obrigatorio, porque em `--batch` o default do scanner para "do you want to exploit this SQL injection?" e `Y` e o `Y` sai do escopo da varredura para enumerar o banco do alvo. A agressividade e limitada por `--technique=BEUT` (exclui `stacked queries` e `inline queries`, que executam statements no banco alvo), `--level=2`, `--risk=2`, `--threads=1`, `--timeout=10`, `--retries=1` e `--time-sec=3`; a medicao sem esses limites levou 43 a 47 segundos e incluiu consultas ao banco do alvo, contra 5 a 12 segundos com eles, dentro do timeout de 15 minutos do executor. O `--output-dir=/tmp` mantem log e sessao no tmpfs efemero, compativel com o filesystem somente leitura. O parser preserva parametro, metodo HTTP, `Type` e `Title` da injecao confirmada e descarta o `Payload`, que e um fragmento com forma de query string; a severidade e derivada da taxonomia de tipos do proprio scanner. O SQLMap termina com status 0 em todos os cenarios, inclusive alvo inalcancavel e URL invalida, e com `stderr` vazio, portanto os diagnosticos vem do stdout: alvo inalcancavel, URL invalida, bloco sem `Type:`, stdout vazio, saida nao reconhecida e exit status diferente de zero sao tratados como `failed` com mensagem acionavel em pt-BR, enquanto a ausencia de parametros injetaveis e resultado legitimo e vira varredura limpa. Timeout e exit status vem do executor Podman e sao preservados. A evidencia da execucao real contra alvo local esta em `docs/evidence/issue-15-sqlmap.md`.

A tela de configuracao da TUI deve permanecer legivel em `80x24`, separar conexao principal de confiabilidade, ocultar campos nao aplicaveis e manter a tela aberta quando houver erro de validacao ou persistencia. Todas as acoes disponiveis por teclado devem possuir equivalente por mouse. O fluxo Nmap -> decisao -> Nuclei -> auditoria -> relatorio possui roteiro E2E reproduzivel em `scripts/e2e_tui_local.sh`; a evidencia da homologacao esta em `docs/evidence/issue-53-tui-e2e.md`.

O arquivo de configuracao TOML tem modelo comentado em `smartsec.example.toml`. Ferramentas adicionais podem ser registradas pela chave `[[tools]]` (manifesto com nome, descricao, categoria, imagem, versao, runner, parser, `command_template` com o marcador `{target}`, formato de saida e `enabled`), validadas contra runners (`nmap`, `nuclei`, `generic`) e parsers (`nmap-xml`, `nuclei-jsonl`, `nikto-json`, `sqlmap-text`, `generic-text`) registrados; o nucleo resolve runner e parser pelo registry, sem comparar nomes de ferramentas. Configuracao invalida (duplicidade, campo obrigatorio ausente ou runner/parser desconhecido) falha com mensagem acionavel em pt-BR, e o procedimento de extensao esta em `docs/EXTENDING_TOOLS.md`. No modo headless, `--target` e sempre obrigatorio na CLI e substitui o `target_url` do arquivo; `--tools`, `--llm` e `--model` sobrescrevem o arquivo. No Linux, as chaves de API remota sao armazenadas no Secret Service do sistema (keyring) e nunca no TOML. O campo `provider` aceita as grafias da CLI (`ollama`, `openai`, `nvidia-nim`, `custom`) alem das canonicas; `base_url` e `model` ausentes assumem o padrao do provedor e `execution_type` ausente assume `Assisted`. O comando `scan` sempre opera como Automatico, independente do `execution_type` do arquivo. O destino do relatorio Markdown e configuravel por `--output`/`--output-dir` na CLI ou por `output_file`/`output_dir` no TOML, com precedencia da CLI.
Na Sprint 2, o TruffleHog entra no portfolio real com imagem fixada por digest (`docker.io/trufflesecurity/trufflehog@sha256:52e67fef4d054ecff5c2ce4b4ae376626d1ef54aa0898b53cac19c25e92e14db`, versao `3.97.9`) e o **runner novo `repository`**. O alvo do TruffleHog nao e um host de rede: e um repositorio, que precisa entrar no container para ser lido. O runner `generic` executa o `command_template` sem mount algum, e portanto nao atende a esse caso; o runner `repository` resolve o diretorio do repositorio, canonicaliza o caminho pelo sandbox de `code_agent::workspace` (recusando caminho relativo, `..`, diretório inexistente e symlink que escapa) e monta o alvo em **modo somente leitura** em `/alvo`, pela mesma razao pela qual os templates do Nuclei sao montados. O caminho do host viaja pelo `--volume` do executor e nunca aparece no comando do scanner, que recebe apenas `file:///alvo` ou a URI remota autorizada. Repositorio remoto autorizado (`https://`/`http://`) e repassado ao subcomando `git` do TruffleHog, sem mount algum; esquemas `ssh://` e a forma scp-like sao recusados porque a validacao de alvo da CLI ja nao os aceita. O repositorio analisado nunca e montado para escrita e nunca e escrito.

O comando do TruffleHog foi fixado por execucao real, nao por suposicao. `--json` e obrigatorio porque sem ele o scanner imprime o valor completo do segredo em texto legivel no stdout; `--no-update` e obrigatorio porque o auto-updater aborta a varredura inteira sob `--read-only`, com exit 1 e stdout vazio; `--fail-on-scan-errors` e obrigatorio porque alvo inexistente termina com exit 0 e stdout vazio, e o erro fica so no stderr. A verificacao remota fica **desligada** (`--no-verification`): ela envia o segredo detectado ao endpoint do provedor de cada detector e degrada em silencio quando a rede nao responde, sem erro e sem codigo de saida diferente. Nao ha flag de limitacao de profundidade, porque `--max-depth` suprime achados reais de forma reproduzivel. O parser `trufflehog-jsonl` e uma **allow-list**: os campos `Raw`, `RawV2`, `Redacted` e `SecretParts`, que carregam o valor do segredo, nao existem na estrutura desserializada, de modo que o valor nao pode alcançar finding, log, relatorio, evidencia versionada ou commit. A sanitizacao de `utils::redaction` tambem os remove do stdout persistido no log estruturado, e o trace ao vivo do executor e sanitizado antes de chegar a TUI e ao modo headless. Preservam-se detector, arquivo, linha, commit e estado de verificacao, com o prefixo de montagem reduzido ao caminho relativo ao repositorio. O TruffleHog nao emite severidade: ela vem do estado de verificacao publicado pelo scanner, e um `Verified: false` significa "detectado, nao validado", nunca "invalido". Saida vazia com exit status 0 e varredura limpa; registro JSONL malformado, saida diagnostica e exit status diferente de zero sao tratados como `failed` com mensagem acionavel em pt-BR. A evidencia da execucao real e das armadilhas encontradas esta em `docs/evidence/issue-18-trufflehog.md`.

A tela de configuracao da TUI deve permanecer legivel em `80x24`, separar conexao principal de confiabilidade, ocultar campos nao aplicaveis e manter a tela aberta quando houver erro de validacao ou persistencia. Todas as acoes disponiveis por teclado devem possuir equivalente por mouse. O fluxo Nmap -> decisao -> Nuclei -> auditoria -> relatorio possui roteiro E2E reproduzivel em `scripts/e2e_tui_local.sh`; a evidencia da homologacao esta em `docs/evidence/issue-53-tui-e2e.md`.

O arquivo de configuracao TOML tem modelo comentado em `smartsec.example.toml`. Ferramentas adicionais podem ser registradas pela chave `[[tools]]` (manifesto com nome, descricao, categoria, imagem, versao, runner, parser, `command_template` com o marcador `{target}`, formato de saida e `enabled`), validadas contra runners (`nmap`, `nuclei`, `generic`, `repository`) e parsers (`nmap-xml`, `nuclei-jsonl`, `nikto-json`, `trufflehog-jsonl`, `generic-text`) registrados; o nucleo resolve runner e parser pelo registry, sem comparar nomes de ferramentas. O runner `repository` exige alvo de repositorio e monta o diretorio somente leitura; seu uso por ferramenta declarada em `[[tools]]` exige que o alvo informado na CLI seja um caminho absoluto de repositorio ou uma URI remota autorizada. Configuracao invalida (duplicidade, campo obrigatorio ausente ou runner/parser desconhecido) falha com mensagem acionavel em pt-BR, e o procedimento de extensao esta em `docs/EXTENDING_TOOLS.md`. No modo headless, `--target` e sempre obrigatorio na CLI e substitui o `target_url` do arquivo; `--tools`, `--llm` e `--model` sobrescrevem o arquivo. No Linux, as chaves de API remota sao armazenadas no Secret Service do sistema (keyring) e nunca no TOML. O campo `provider` aceita as grafias da CLI (`ollama`, `openai`, `nvidia-nim`, `custom`) alem das canonicas; `base_url` e `model` ausentes assumem o padrao do provedor e `execution_type` ausente assume `Assisted`. O comando `scan` sempre opera como Automatico, independente do `execution_type` do arquivo. O destino do relatorio Markdown e configuravel por `--output`/`--output-dir` na CLI ou por `output_file`/`output_dir` no TOML, com precedencia da CLI.
Na Sprint 2, o OWASP ZAP entra no portfolio real com imagem fixada por digest (`ghcr.io/zaproxy/zaproxy:2.14.0@sha256:3280adc730131f1f4460ab226b0f85e3e9ab3301ef5a7030f745ac4dd6b6ff87`, versao `2.14.0`), runner `zap` e parser `zap-json`. O ZAP nao entrega saida estruturada no stdout: o job `report` sempre acrescenta a extensao do template ao nome do arquivo e o conjunto de parametros e fechado (`template`, `theme`, `reportDir`, `reportFile`, `reportTitle`, `reportDescription`, `displayReport`), sem parametro de saida em stdout; quatro combinacoes de `reportDir`/`reportFile` foram testadas no container real e todas produziram um caminho que o ZAP nao consegue criar, e a API e inalcancavel porque o executor remove o container logo apos a execucao. O plano de automacao e montado em memoria pelo orquestrador, gravado num diretorio temporario do host e montado em `/zap/automation` em somente leitura, como os templates do Nuclei. Como o ZAP exige `HOME` gravavel, a execucao recebe a tmpfs adicional `/home/zap` e limite de memoria de DAST (`1536m`); sem essa tmpfs o ZAP aborta antes do primeiro job com `The home path is not writable`. O comando usa `-Xmx1024m` porque o `zap.sh` ignora `JAVA_OPTS` e calcula o heap a partir da memoria do host, e `-cmd` porque sem ele o ZAP nao encerra. O parser `zap-json` preserva URL, metodo HTTP, referencia (`alertRef`, `pluginid` e CWE), rotulo de risco e confianca e evidencia minima sanitizada; o template `traditional-json` nao inclui cabecalhos nem corpos de requisicao/resposta, e a sanitizacao remove query strings e credenciais. A severidade do ZAP e autoritativa e deriva do campo estruturado `riskcode` do scanner (`0` informativa, `1` baixa, `2` media, `3` alta), sem reinterpretar o texto do alerta, e um `riskcode` ausente ou fora da faixa nunca produz severidade maior que a do scanner. JSON invalido, stdout vazio, relatorio sem site varrido, site sem alertas, artefato ausente e exit status diferente de zero sao tratados como `failed` com mensagem acionavel em pt-BR; timeout e exit status vem do executor Podman e sao preservados. A evidencia da execucao real contra alvo local esta em `docs/evidence/issue-28-zap.md`.

O executor Podman ganhou a capacidade de coletar um artefato gravado pelo container antes de remove-lo, para as ferramentas que so conseguem escrever um arquivo estruturado. O executor cria um diretorio vazio no `TMPDIR` do host com modo `0733` (necessario porque, em Podman rootless sem `keep-id`, o usuario do container e um subuid do host), monta **apenas** esse diretorio com `rw,noexec,nosuid,nodev`, le o artefato depois da execucao e antes de remover o container, e remove o diretorio ao final, inclusive nos caminhos de erro. O container permanece `--read-only`, com `--cap-drop all`, `no-new-privileges`, sem shell, sem capacidade nova e sem execucao de comando no host. Artefato ausente nao derruba a varredura, mas e reportado e nunca e lido como varredura limpa. A coleta nao usa `podman cp`: verificado empiricamente que o tmpfs do container e desmontado quando ele encerra, de modo que um artefato gravado em `/tmp` e irrecuperavel depois da saida, enquanto o bind mount ja coloca o arquivo nas maos do host.

A restricao a tmpfs da configuracao temporaria e do relatorio do scanner e **verificada em execucao**, e nao presumida: antes de criar qualquer diretorio temporario no host, o executor resolve o tipo do filesystem do caminho em `/proc/self/mountinfo` (o ponto de montagem mais especifico que contem o diretorio, sobre o caminho canonicalizado, para que um `TMPDIR` que seja symlink para disco seja avaliado no destino real) e falha com mensagem acionavel em portugues brasileiro quando o tipo nao e `tmpfs`, quando a tabela nao e legivel ou quando o ponto de montagem nao pode ser identificado. Nao existe caminho de degradacao para escrita fora da regra: sem `tmpfs`, a execucao nao acontece. O tipo `overlay` nao e aceito, por ser a camada copy-on-write do container, cujo dado gravado reside no diretorio superior, em disco do host. A verificacao vale para o diretorio de saida gravavel e para o diretorio do plano de automacao do ZAP, que e a configuracao temporaria da execucao. O tipo de filesystem e injetavel (`tmpfs::FilesystemProbe`) para que o caminho negativo, um diretorio em disco comum, seja testado sem depender da maquina de teste. As limitacoes conhecidas — namespace de montagem do processo, janela TOCTOU de symlink e kernels sem `/proc/self/mountinfo` legivel — estao documentadas em `src/orchestrator/tmpfs.rs`.

A tela de configuracao da TUI deve permanecer legivel em `80x24`, separar conexao principal de confiabilidade, ocultar campos nao aplicaveis e manter a tela aberta quando houver erro de validacao ou persistencia. Todas as acoes disponiveis por teclado devem possuir equivalente por mouse. O fluxo Nmap -> decisao -> Nuclei -> auditoria -> relatorio possui roteiro E2E reproduzivel em `scripts/e2e_tui_local.sh`; a evidencia da homologacao esta em `docs/evidence/issue-53-tui-e2e.md`.

O arquivo de configuracao TOML tem modelo comentado em `smartsec.example.toml`. Ferramentas adicionais podem ser registradas pela chave `[[tools]]` (manifesto com nome, descricao, categoria, imagem, versao, runner, parser, `command_template` com o marcador `{target}`, formato de saida e `enabled`), validadas contra runners (`nmap`, `nuclei`, `generic`, `zap`) e parsers (`nmap-xml`, `nuclei-jsonl`, `nikto-json`, `zap-json`, `generic-text`) registrados; o nucleo resolve runner e parser pelo registry, sem comparar nomes de ferramentas. Configuracao invalida (duplicidade, campo obrigatorio ausente ou runner/parser desconhecido) falha com mensagem acionavel em pt-BR, e o procedimento de extensao esta em `docs/EXTENDING_TOOLS.md`. No modo headless, `--target` e sempre obrigatorio na CLI e substitui o `target_url` do arquivo; `--tools`, `--llm` e `--model` sobrescrevem o arquivo. No Linux, as chaves de API remota sao armazenadas no Secret Service do sistema (keyring) e nunca no TOML. O campo `provider` aceita as grafias da CLI (`ollama`, `openai`, `nvidia-nim`, `custom`) alem das canonicas; `base_url` e `model` ausentes assumem o padrao do provedor e `execution_type` ausente assume `Assisted`. O comando `scan` sempre opera como Automatico, independente do `execution_type` do arquivo. O destino do relatorio Markdown e configuravel por `--output`/`--output-dir` na CLI ou por `output_file`/`output_dir` no TOML, com precedencia da CLI.
O historico de execucoes e consultavel pela CLI e pela TUI. A CLI expoe `history [--limit <N>]` (padrao 20) e `show <SCAN_ID>`; o `scan_id` tem o formato `scan_<nanos>`, que nao e adivinhavel, portanto o modo headless imprime o identificador da execucao ao final e orienta o comando de consulta. Um `scan_id` fora do padrao e recusado antes de tocar o disco, de modo que o id nunca resolve para fora de `~/.config/smartsec/scans/`. A listagem diferencia diretorio inexistente de diretorio vazio, ordena da execucao mais recente para a mais antiga e converte registros corrompidos ou parciais em itens identificaveis exibidos ao usuario, em vez de descarta-los em silencio. Um registro parcial, sem campo obrigatorio, ou gravado por uma versao anterior do formato falha com mensagem acionavel em portugues brasileiro que aponta corrupcao, incompletude e formato antigo. A TUI expoe a tela `Historico` (`AppStep::History`), aberta pela tecla `h` fora de campos de texto ou pela paleta de comandos, com lista, detalhe, navegacao por teclado e mouse, e legibilidade em `80x24`; a consulta nao altera os artefatos originais.
O relatorio e produzido em Markdown e em PDF a partir da **mesma** string Markdown ja sanitizada, de modo que o PDF nao possa exibir um segredo ou uma query string que o Markdown tenha removido. O PDF usa a Noto Sans (SIL OFL 1.1) embutida no repositorio, porque as fontes padrao do PDF nao possuem `cmap` Unicode e quebrariam os acentos do relatorio em portugues brasileiro. A geracao usa `printpdf` com `default-features = false`: as features padrao ligariam um motor de layout HTML/CSS e um binding de fontconfig, o que violaria a politica de zero dependencia de sistema de `docs/PLANO_DE_DISTRIBUICAO.md`. Com essa configuracao o `printpdf` 0.12.8 nao reduz a fonte a um subconjunto de glifos e cada PDF embute a Noto Sans completa (~290 KB comprimidos); o texto e a paginacao ficam corretos e o custo e apenas de tamanho do artefato. O conteudo dinamico vindo dos scanners e escapado antes de entrar no relatorio, de modo que um titulo, descricao ou erro de execucao nao consiga abrir uma secao, um link ou uma tag HTML no Markdown. O relatorio inclui a analise da IA e as execucoes que terminaram em erro, com ferramenta, status, duracao e mensagem; as execucoes bem-sucedidas nunca sao listadas como falha. `output_file`/`output_dir` definem o destino nos dois modos: o Markdown e o PDF sao gravados juntos, com o mesmo nome e a mesma pasta, e o diretorio e criado quando nao existe. Falha de gravacao e erro de execucao, com caminho e causa, e resulta em exit code 2 depois que o log estruturado ja foi persistido. A evidencia e a matriz de rastreabilidade de REQ16, REQ17 e REQ18 estao em `docs/evidence/issue-22-relatorio-pdf.md`.

O arquivo de configuracao TOML tem modelo comentado em `smartsec.example.toml`. Ferramentas adicionais podem ser registradas pela chave `[[tools]]` (manifesto com nome, descricao, categoria, imagem, versao, runner, parser, `command_template` com o marcador `{target}`, formato de saida e `enabled`), validadas contra runners (`nmap`, `nuclei`, `generic`) e parsers (`nmap-xml`, `nuclei-jsonl`, `nikto-json`, `generic-text`) registrados; o nucleo resolve runner e parser pelo registry, sem comparar nomes de ferramentas. Configuracao invalida (duplicidade, campo obrigatorio ausente ou runner/parser desconhecido) falha com mensagem acionavel em pt-BR, e o procedimento de extensao esta em `docs/EXTENDING_TOOLS.md`. No modo headless, `--target` e sempre obrigatorio na CLI e substitui o `target_url` do arquivo; `--tools`, `--llm` e `--model` sobrescrevem o arquivo. No Linux, as chaves de API remota sao armazenadas no Secret Service do sistema (keyring) e nunca no TOML. O campo `provider` aceita as grafias da CLI (`ollama`, `openai`, `nvidia-nim`, `custom`) alem das canonicas; `base_url` e `model` ausentes assumem o padrao do provedor e `execution_type` ausente assume `Assisted`. O comando `scan` sempre opera como Automatico, independente do `execution_type` do arquivo. O destino do relatorio Markdown e configuravel por `--output`/`--output-dir` na CLI ou por `output_file`/`output_dir` no TOML, com precedencia da CLI.
A traducao para linguagem compreensivel (REQ16) e produzida pelo mesmo servico: a analise deterministica do SmartSec resume os achados por severidade e indica a prioridade, e as orientacoes da IA sao acrescentadas como complemento, nunca substituindo a classificacao. A origem do texto de cada analise fica registrada, o que permite dizer, no relatorio e no log de auditoria, quem produziu cada orientacao. A matriz de rastreabilidade da TUI (F2) exibe a mesma linha de proveniencia que o modo headless imprime, incluindo o motivo quando a alternativa local foi usada. A evidencia reproduzivel dos dois caminhos esta em `docs/evidence/issue-23-ia-unificada.md`, gerada por `scripts/evidence_issue_23_ia.sh` com o provedor local de `scripts/evidence_fake_openai_server.py`, que nao faz parte do aplicativo.

A tela de configuracao da TUI deve permanecer legivel em `80x24`, separar conexao principal de confiabilidade, ocultar campos nao aplicaveis e manter a tela aberta quando houver erro de validacao ou persistencia. Todas as acoes disponiveis por teclado devem possuir equivalente por mouse. O fluxo Nmap -> decisao -> Nuclei -> auditoria -> relatorio possui roteiro E2E reproduzivel em `scripts/e2e_tui_local.sh`; a evidencia da homologacao esta em `docs/evidence/issue-53-tui-e2e.md`.

### Agente de codigo (REQ10, REQ16, RNF10)

Apos os scanners e a interpretacao dos logs, o pipeline executa uma fase que explora a codebase do alvo para apontar onde corrigir cada achado. A fase vive em `src/code_agent/` e tem tres partes com responsabilidades distintas: `workspace.rs` e o sandbox de leitura, `tools.rs` e o registro de ferramentas locais, e `agent.rs` e o laco de tool calling.

O sandbox e a unica superficie pela qual o SmartSec le codigo do alvo. `Workspace::resolve` rejeita `..`, canonicaliza o caminho e exige contencao na raiz, o que bloqueia tambem symlink que escape; a garantia esta em teste, inclusive para symlink. As ferramentas `list_dir`, `read_file` (com numeracao de linha), `search_code` e `run_command` sao registradas em `LocalToolRegistry` e nunca escrevem no projeto analisado. `run_command` e desabilitado por padrao porque o pipeline nunca concede allowlist: com a lista vazia, toda chamada e recusada com mensagem acionavel em pt-BR que informa a allowlist vigente. Quando habilitada, a execucao nao usa shell, roda com `stdin` nulo, `kill_on_drop` e timeout proprio. A garantia de leitura pura esta coberta por teste que compara o conteudo e a lista de arquivos do workspace antes e depois de um laco completo; ela vale para o registro vazio de comandos, que e o que o pipeline entrega.

O laco de tool calling instrui o modelo, executa as chamadas pedidas pelo registro local e devolve o resultado ao modelo no mesmo turno. A conversa segue o protocolo do Chat Completions: a mensagem do modelo com `tool_calls` e seguida dos resultados correspondentes, na mesma ordem e com o mesmo identificador. Recusas e falhas tambem voltam ao modelo, para que ele pare de repetir uma chamada proibida em vez de consumir o teto de iteracoes. Uma localizacao so e declarada quando o modelo aponta uma linha que o agente **leu de fato** durante o laco, pelo sandbox; o registro das linhas observadas e a unica fonte de aceitacao, e nao o texto do modelo. Sem essa correspondencia, o resultado honesto e `localizacao nao determinada` com o motivo registrado, e nunca um arquivo ou uma linha inventados.

O provedor sem suporte a tool calling se declara incapaz **antes** de qualquer chamada (`LLMProvider::supports_tool_calling` tem padrao `false`), e o agente cai no fallback deterministico sem inventar localizacao. O mesmo vale para a recusa de RNF10: `AIAgent::allows_target_data` e consultado antes do primeiro turno, e nenhum turno e aberto — nem um turno sem ferramentas — quando falta consentimento para provedor remoto. O consentimento e o mesmo exigido pela issue #23 para enviar logs, porque o dado protegido aqui e o codigo do alvo, que e o ativo mais sensivel do cliente. Os limites sao `CodeAgentLimits`: 64 KiB por arquivo, 50 resultados por busca, 12 iteracoes por achado, 45 s por achado (RNF04) e 10 s por comando. O prazo por achado interrompe o laco daquele achado e a fase continua nos demais, porque um achado caro nao pode privar a varredura inteira da localizacao. O registro das chamadas de ferramenta acumula fora do futuro do timeout, para que um achado que esbota o prazo nao perca as ferramentas que ja executaram.

**Mudanca de contrato.** O finding ganha `code_location` (`file`, `line`, `snippet`) e `code_remediation`, ambos com valor padrao na desserializacao: um log estruturado gravado antes desta mudanca continua carregando, e a ausencia de localizacao e um resultado legitimo. `CodeLocation` mora em `src/domain/vulnerability.rs`, e nao em `code_agent`, porque o mesmo tipo e persistido, impresso no relatorio e exibido na TUI. Os quatro parsers de scanner preenchem os campos explicitamente como vazios: um scanner nao conhece o codigo do projeto, e deixar isso implicito esconderia o limite do que cada etapa sabe. A gravacao usa o indice do relatorio da fase e nao reordena a lista nem altera a severidade, que continua autoritativa (secao 7). O relatorio ganha uma secao "Localizacao no codigo" que lista **todos** os achados, inclusive os sem origem, e declara quantos ficaram sem localizacao; omiti-los faria o relatorio parecer mais preciso do que foi. O log estruturado grava `code_project_dir`, `code_located_count`, `code_tool_calls_count`, `code_tool_calls` e `code_unavailable_reason`. O diretorio do projeto e gravado mesmo com zero achados localizados, porque e ele que distingue "a fase rodou e nao achou origem" de "a fase nunca rodou".

O projeto analisado vem de `--project <DIR>` no headless, com padrao no diretorio atual, e do campo equivalente "Projeto analisado" na tela de configuracao da TUI. O valor e validado pelo mesmo sandbox que a fase usa, tanto na CLI quanto na tela, para que o SmartSec nao aceite um caminho que a fase rejeitaria. Uma flag invalida e erro de configuracao e sai com codigo 2 antes de gastar minutos de varredura; um projeto ilegivel durante a execucao nao impede o relatorio e vira `code_unavailable_reason`. No detalhe do achado a TUI exibe arquivo, linha e passos de correcao numerados; sem origem, ela exibe `localizacao nao determinada` junto com o motivo da recusa, para que o operador diferencie uma falha do agente de uma recusa do provedor. O fluxo, os limites e os riscos estao em `docs/AGENTE_DE_CODIGO.md`; a evidencia reproduzivel esta em `docs/evidence/issue-76-code-agent.md`.

O arquivo de configuracao TOML tem modelo comentado em `smartsec.example.toml`. Ferramentas adicionais podem ser registradas pela chave `[[tools]]` (manifesto com nome, descricao, categoria, imagem, versao, runner, parser, `command_template` com o marcador `{target}`, formato de saida e `enabled`), validadas contra runners (`nmap`, `nuclei`, `generic`) e parsers (`nmap-xml`, `nuclei-jsonl`, `nikto-json`, `generic-text`) registrados; o nucleo resolve runner e parser pelo registry, sem comparar nomes de ferramentas. Configuracao invalida (duplicidade, campo obrigatorio ausente ou runner/parser desconhecido) falha com mensagem acionavel em pt-BR, e o procedimento de extensao esta em `docs/EXTENDING_TOOLS.md`. No modo headless, `--target` e sempre obrigatorio na CLI e substitui o `target_url` do arquivo; `--tools`, `--llm` e `--model` sobrescrevem o arquivo. O diretorio analisado pelo agente de codigo vem de `--project <DIR>` ou de `project_dir` no TOML, com padrao no diretorio atual. No Linux, as chaves de API remota sao armazenadas no Secret Service do sistema (keyring) e nunca no TOML. O campo `provider` aceita as grafias da CLI (`ollama`, `openai`, `nvidia-nim`, `custom`) alem das canonicas; `base_url` e `model` ausentes assumem o padrao do provedor e `execution_type` ausente assume `Assisted`. O comando `scan` sempre opera como Automatico, independente do `execution_type` do arquivo. O destino do relatorio Markdown e configuravel por `--output`/`--output-dir` na CLI ou por `output_file`/`output_dir` no TOML, com precedencia da CLI.

A TUI nao inventa progresso. Nao existe deteccao de catalogo, fase por contagem de quadros nem espera entre a analise e os resultados: o catalogo vem do registry de forma sincrona em `AppState::new`, o progresso geral e a contagem de ferramentas em estado terminal emitido pelo orquestrador (`ToolStarted`/`ToolFinished`), a fase da analise deriva de eventos reais (achados construido por `build_findings` e inicio da chamada de IA) e a tela de Resultados abre no mesmo evento `Completed` que encerra a analise. O medidor mostra porcentagem somente quando existe um valor mensuravel; durante a chamada de IA, que nao produz um, a tela mostra o estado real e o tempo decorrido em vez de um percentual fixo. O campo `ToolItem.progress` foi removido por nunca ter sido lido: o estado por ferramenta e o dado que o pipeline emite.

O canal de eventos da execucao e limitado (256 eventos) com politica explicita: eventos de controle usam `send().await` e nunca sao descartados, apenas sofrem contrapressao porque a TUI drena o canal a cada quadro, inclusive com uma camada sobreposta aberta; linhas de log usam `try_send` e, sob saturacao, sao descartadas e contadas, com a contagem exibida no titulo do painel de log. `MAX_EXEC_LOGS` continua limitando o historico retido e o descarte continua corrigindo o offset pelas linhas visuais (`visual_line_count`). O `JoinHandle` do executor nunca e aguardado dentro do laco de eventos. Cancelar aborta a tarefa e descarta o canal, de modo que nenhum evento tardio sobrescreva a decisao do usuario, e o cancelamento e registrado na auditoria como execucao encerrada.

A severidade do scanner e autoritativa tambem na leitura da lista: os achados criticos vem primeiro, o painel anuncia quantos criticos estao no topo, e a cor da severidade nunca e substituida pela cor de selecao (o destaque vem do fundo e do marcador). O detalhe do achado exibe a evidencia minima do scanner, alem de alvo, instante de deteccao e origem, com a evidencia sanitizada na exibicao; o texto completo da analise por IA permanece no relatorio e no log de auditoria, e sua primeira linha aparece no resumo de Resultados. Falha de ferramenta, falha de persistencia, falha do executor, erro de validacao, erro de exportacao e cada aviso de proveniencia da IA (falha da LLM principal, uso do modelo local alternativo, resposta descartada por contrato) sao registrados como ocorrencias com origem e exibidos na tela de Execucao e no resumo de Resultados, em vez de apenas o primeiro erro. A evidencia reproduzivel desta mudanca esta em `docs/evidence/issue-20-tui-pipeline.md`.

## 8. Macro-sprints

### Sprint 1 - Nucleo de Orquestracao e Isolamento

Prazo: 14/09/2026.

Entregar CLI, configuracao de alvo, executor Podman rootless, Nmap e Nuclei reais, logs persistentes, modelo de dados rastreavel e primeira decisao dinamica por IA remoto/local.

Issues: #2, #3, #4, #6, #7, #9, #10, #11, #12 e #13.

### Sprint 2 - Expansao, Relatorios e DevOps

Prazo: 26/10/2026.

Entregar as seis ferramentas, arquitetura extensivel, TUI ligada ao pipeline real, pausa/retomada/cancelamento, correlacao CVE/NVD, IA real na TUI e headless, historico, Markdown/PDF, exit codes e GitHub Actions. A preparacao da validacao deve comecar nesta sprint.

Issues: #14, #15, #17, #18, #19, #20, #21, #22, #23, #24, #25, #26, #27 e #28.

### Sprint 3 - Validacao Tecnica e Metricas

Prazo: 09/11/2026.

Executar validacao em DVWA 2.3 e OWASP Juice Shop 16, comparar GPT-4o e Llama 3.1, homologar CI/CD, medir eficacia e desempenho, realizar avaliacao com especialistas e publico-alvo e consolidar resultados.

Issues: #29, #30, #31, #32, #33 e #34.

## 9. Validacao e metas

### Validacao tecnica

1. Subir DVWA e Juice Shop em ambiente local isolado.
2. Registrar a matriz de vulnerabilidades conhecidas (ground truth).
3. Executar os cenarios com GPT-4o e Llama 3.1.
4. Preservar logs operacionais sanitizados, configuracao e relatorios; dados brutos de pesquisa devem permanecer isolados, com acesso controlado e tratamento de segredos.
5. Cruzar achados automatizados com o ground truth.

### Validacao DevSecOps

Executar o modo headless no GitHub Actions e comprovar os tres exit codes, os artefatos publicados e o tempo total do pipeline.

### Validacao humana

Realizar sessoes supervisionadas com especialistas e testes com estudantes/desenvolvedores generalistas. Aplicar questionario Likert de cinco pontos nas dimensoes:

- Facilidade de Uso Percebida (EU).
- Utilidade Percebida (UP).
- Intencao de Uso Futuro (IU).

O CEP nao e pre-condicao para este TCC de desenvolvimento de ferramenta, conforme orientacao registrada na reuniao. A validacao com pessoas continua obrigatoria, com consentimento, anonimizacao e tratamento responsavel dos dados.

### Metas de aceite

| Criterio | Meta |
|---|---:|
| Deteccao de vulnerabilidades conhecidas | >= 70% |
| Falsos positivos | <= 20% |
| Qualidade dos relatorios | media >= 4,0/5 |
| Participantes sem experiencia que concluem sem assistencia | >= 80% |
| Varredura completa | <= 15 minutos |
| Cenarios planejados no GitHub Actions | 100% de sucesso |
| Modelo local | execucao completa sem erros |
| Interpretacao da IA por ferramenta | <= 45 segundos |

## 10. Exit codes

- `0`: nenhuma vulnerabilidade critica encontrada.
- `1`: vulnerabilidade critica encontrada.
- `2`: erro interno, de configuracao ou de execucao.
- `130`: execucao cancelada por `SIGINT` (Ctrl+C).
- `143`: execucao cancelada por `SIGTERM`.

Erro de scanner nao pode ser convertido em sucesso. Finding critico nao e erro interno: deve retornar `1` e preservar o relatorio. No modo headless os codigos derivam do resultado consolidado (achados e falhas de execucao), nunca de mensagens de texto; a falha de execucao tem precedencia sobre o achado critico, e o relatorio e o log estruturado sao gravados antes da mensagem final.

A consulta ao historico tambem respeita este contrato. `history` retorna `0` mesmo com historico vazio, porque a listagem foi executada com sucesso. `show <SCAN_ID>` retorna `2` quando o identificador e invalido, quando viola o padrao `scan_<nanos>` ou quando nao existe registro correspondente: em automacao, um id inexistente e um erro de uso da ferramenta e nao pode ser confundido com `0` (nenhum achado critico) nem com `1` (achado critico), que significam que a varredura foi executada. Registros ilegiveis dentro de um historico listavel nao alteram o codigo de saida; eles sao reportados como aviso na saida padrao para que a listagem continue util, e essa escolha esta registrada em `docs/evidence/issue-24-historico.md` para revisao.

### Cancelamento por sinal

`SIGINT` e `SIGTERM` cancelam a execucao pelo mesmo canal de controle usado pela TUI: o container em andamento e encerrado de forma cooperativa (`podman stop --time 5`, com `podman kill` como recurso) e removido com `podman rm --force --ignore` antes da saida. O relatorio e o log estruturado **sao gravados antes da mensagem final**, inclusive no caminho de cancelamento, e o motivo fica registrado no log como `interruption.rule = "cancelado_por_sinal"`.

Os codigos `130` e `143` seguem a convencao POSIX `128 + numero do sinal`, ja interpretada por shells e pelo GitHub Actions. A decisao de **nao** reaproveitar `2` e porque `2` significa erro interno: um cancelamento pedido pelo operador nao e falha, e um pipeline de CI/CD que trata `2` como erro acabaria atribuindo ao produto um defeito que o operador causou de proposito. O segundo sinal do mesmo tipo encerra o processo imediatamente, para que o operador nao fique preso a um Podman travado; nesse caso a auditoria pode nao ser gravada.

A regra automatica de interrupcao (REQ05) nao tem codigo proprio: a varredura para por decisao do produto e o resultado segue o caminho normal, `1` quando ha achado critico, que e exatamente a condicao que disparou a regra.

## 11. Entregaveis

- Codigo da CLI, TUI e modo headless.
- Configuracao versionada e documentada.
- Orquestrador com Podman rootless.
- Integracoes com Nmap, Nuclei, ZAP, SQLMap, Nikto e TruffleHog.
- Agente LLM remoto/local e registros de decisao.
- Logs, historico e findings com proveniencia.
- Relatorios Markdown e PDF.
- Workflow GitHub Actions.
- Fixtures, testes e evidencias de validacao.
- Matriz de requisitos, metricas, limitacoes e resultados para o TCC.

## 12. Documentos de referencia

- Proposta: `docs/BES_TCC_Proposta de Desenvolvimento de Ferramenta_v2023 (final).docx`
- Plano de sprints: `docs/BES_TCC_Plano_de_Sprints_v2026_preenchido.docx`
- Reuniao de orientacao: `docs/call_8.txt`
- Distribuicao atual: `docs/PLANO_DE_DISTRIBUICAO.md`
