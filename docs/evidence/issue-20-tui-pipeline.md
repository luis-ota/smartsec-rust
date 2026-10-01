# Evidencia da TUI ligada ao pipeline real — issue #20

Data da medicao: 01/10/2026.

## Ambiente

- SmartSec `feat/issue-20-tui-pipeline`, base `integration/sprint2-tools` (commit `ccb5f54`).
- Terminal tmux com 80 colunas e 24 linhas.
- Podman 6.1.0 em modo rootless e rede `pasta`.
- Templates do Nuclei no checkout local `~/nuclei-templates`.
- Ollama local com `llama3.2:1b`.
- Alvo controlado: servidor HTTP preso a `127.0.0.1:38164`, acessado pelos
  scanners como `http://169.254.1.2:38164`.
- Configuracao e artefatos isolados por `XDG_CONFIG_HOME` temporario.

## Comando reproduzivel

O roteiro E2E oficial continua sendo o da issue #53 e passou com esta branch
(seis ferramentas reais, 20 achados reais, log de auditoria e relatorio
Markdown conferidos por `jq` e `rg`):

```bash
./scripts/e2e_tui_local.sh
```

Para medir a cadencia das telas (tempo real entre as transicoes) e capturar as
telas intermediarias, use o roteiro abaixo, que dirige a mesma TUI por teclado:

```bash
# 1. alvo autorizado preso ao loopback
mkdir -p /tmp/e2e20/alvo && printf '<!doctype html><title>ok</title>' > /tmp/e2e20/alvo/index.html
python3 -m http.server 38164 --bind 127.0.0.1 --directory /tmp/e2e20/alvo &

# 2. TUI em 80x24 com configuracao isolada
cargo build
mkdir -p /tmp/e2e20/config
tmux new-session -d -s smartsec-issue20 -x 80 -y 24 \
  "env XDG_CONFIG_HOME=/tmp/e2e20/config $PWD/target/debug/smartsec-rust"

# 3. alvo, modo automatico, configuracao da IA e inicio
tmux send-keys -t smartsec-issue20 -l 'http://169.254.1.2:38164'
tmux send-keys -t smartsec-issue20 Tab Enter Tab Tab Enter   # abre Configurar IA
tmux send-keys -t smartsec-issue20 Tab Tab Tab Tab Tab Tab Enter  # salva
tmux send-keys -t smartsec-issue20 Tab Tab Enter              # inicia a analise

# 4. captura continua, com carimbo de tempo por quadro
while true; do
  printf '%s %s\n' "$(date +%s.%N)" "$(tmux capture-pane -p -t smartsec-issue20 | head -1)"
  sleep 0.2
done | tee /tmp/e2e20/frames.txt
```

O primeiro quadro depois de `Tab Tab Enter` ja e `Ferramentas 02/05` com as
seis ferramentas do catalogo; o quadro seguinte ja e `Execucao 03/05`.

## O que era cenografico e o que foi removido

| Cenario | Antes (contador de ticks) | Agora (estado real) |
| --- | --- | --- |
| Catalogo de ferramentas | `tool_detecting` virava `true` em `AppState::new` e `false` depois de `tool_detect_tick > 50` (~50 quadros de "Verificando catálogo e disponibilidade..."), com o catalogo ja carregado do registry | `tool_detecting` e `tool_detect_tick` foram removidos do estado; o catalogo do registry e a unica fonte e aparece pronto |
| Fases da analise | `phase_state()` devolvia `25`, `55`, `85`, `100` fixos e a troca de fase dependia de `advance_analysis`, que contava caracteres revelados de um texto que ja havia chegado inteiro | `AnalysisPhase` muda por evento: `Scanning` -> `Correlating` em `RunEvent::FindingsBuilt` (emitido depois de `orchestrator.build_findings()`) -> `Generating` no primeiro `AnalysisProgress` (a chamada de IA em andamento) -> `Complete` no `Completed` |
| Medidor da analise | porcentagem fixa independente do trabalho | porcentagem so quando existe valor mensuravel (ferramentas em estado terminal, ou 100% ao concluir); durante a chamada de IA mostra a etapa e o tempo real |
| Análise -> Resultados | `analysis_tick > 30` segurava a tela (~1,5 s) depois da analise terminar | a transicao acontece no proprio evento `Completed` |
| Texto da analise | `analysis_text` revelava 5 caracteres por quadro a partir de `analysis_full_text` | campos removidos; o texto real chega uma vez e aparece no resumo de Resultados, no relatorio e na auditoria |
| Progresso por ferramenta | `ToolItem.progress` recebia `100` e nunca era lido | campo removido; o dado real e o estado por ferramenta (`ToolStatus`), e o medidor geral conta estados terminais |
| Erros | `run_error` guardava apenas o primeiro erro; a tela de Execucao nao mostrava nada disso | `run_issues` agrega toda ocorrencia com sua origem, exibida na tela de Execucao e no resumo de Resultados |
| IA | apenas a ultima entrada de `agent.execution_history` virava aviso | todas as entradas viram ocorrencias de origem `IA` (aviso), incluindo fallback e consentimento |

## Medicao da cadencia (execucao real, seis ferramentas)

```text
selecao -> tela Execução:        0.00s
Execução -> primeira Análise:    158.36s
duração real da análise (IA):    132.66s
última Análise -> Resultados:    0.25s   <- sem cadência artificial
```

`Execução -> primeira Análise` e o tempo real dos seis containers (Nmap,
Nuclei com decisao de IA, Nikto, SQLMap, TruffleHog, ZAP). A analise levou
132,66 s porque o Ollama local levou esse tempo. O intervalo entre o ultimo
quadro de `Análise` e o primeiro quadro de `Resultados` e de 0,25 s, que e o
proprio intervalo de captura do roteiro (0,2 s + captura): a TUI troca de tela
no mesmo quadro em que o evento `Completed` chega. Antes desta mudanca o mesmo
intervalo seria de no minimo 1,5 s, porque a tela so saia da analise depois de
30 quadros.

## Capturas reais em 80x24

### Catalogo real, sem "Verificando catálogo" (apos cancelar a execucao)

```text
 SmartSec  / Ferramentas  02/05  http://169.254.1.2:38164
────────────────────────────────────────────────────────────────────────────────
┌ Ferramentas de segurança ────────────────────────────────────────────────────┐
│> [x] Nmap        RECON                                                       │
│  [x] Nuclei      DAST                                                        │
│  [x] Nikto       DAST                                                        │
│  [x] SQLMap      DAST                                                        │
│  [x] TruffleHog  SECRETS                                                     │
│  [x] ZAP         DAST                                                        │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Execucao: progresso contando ferramentas em estado terminal

```text
 SmartSec  / Execucao  03/05  http://169.254.1.2:38164
────────────────────────────────────────────────────────────────────────────────
┌ Progresso geral · 0% ────────────────────────────────────────────────────────┐
│⠼ Nmap        executando                                                      │
│○ Nuclei      aguardando                                                      │
│○ Nikto       aguardando                                                      │
│○ SQLMap      aguardando                                                      │
└──────────────────────────────────────────────────────────────────────────────┘
┌ Atuação da IA ───────────────────────────────────────────────────────────────┐
│○ Aguardando evidências do Nmap                                               │
│modelo configurado: llama3.2:1b                                               │
└──────────────────────────────────────────────────────────────────────────────┘
┌ Log de saída ────────────────────────────────────────────────────────────────┐
│[Nmap] [00:56:12]                                                             │
│829abc000e7c0c897670c6e2f0fd4cb5ea30cf33f3939c37943acd52e4489bfd              │
│[Nmap] [00:56:12] container                                                   │
│829abc000e7c0c897670c6e2f0fd4cb5ea30cf33f3939c37943acd52e4489bfd criado a     │
│partir da imagem 'docker.io/instrumentisto/nmap:7.95'                         │
│[Nmap] [00:56:12] $ podman start --attach                                     │
│829abc000e7c0c897670c6e2f0fd4cb5ea30cf33f3939c37943acd52e4489bfd              │
└──────────────────────────────────────────────────────────────────────────────┘
↑↓ percorre os logs · esc também cancela                   > Cancelar varredura

 ● Executando varredura · 0/6 concluídas · 0%         f1 ajuda  ctrl+p comandos
```

### Analise: etapa e tempo reais, sem percentual fixo

```text
 SmartSec  / Análise  04/05  http://169.254.1.2:38164
────────────────────────────────────────────────────────────────────────────────
┌ Progresso da análise ────────────────────────────────────────────────────────┐
│⠇ gerando orientações · 132s                                                  │
└──────────────────────────────────────────────────────────────────────────────┘
┌ Atividade ───────────────────────────────────────────────────────────────────┐
│⠇ As orientações da IA não alteram a severidade dos scanners                  │
│                                                                              │
│modelo  llama3.2:1b   achados  20                                             │
│espera  132s                                                                   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
                                                                     > Cancelar

 ● IA em processamento · gerando orientações · 132s  f1 ajuda  ctrl+p comandos
```

O contador de achados (20) e o tempo (132 s) sao os valores reais do pipeline: os
20 achados vieram dos parsers dos seis scanners e os 132 s sao o tempo que o
Ollama local levou. Antes, a mesma tela mostrava `gerando recomendações · 85%`
com 85 fixo no codigo, sem relacao com o trabalho.

### Resultados: ocorrencia agregada, resumo da IA e lista por severidade

```text
 SmartSec  / Resultados  05/05  http://169.254.1.2:38164
────────────────────────────────────────────────────────────────────────────────
┌ Resumo ──────────────────────────────────────────────────────────────────────┐
│ferramenta: [ERRO] O container 9a8ab923bd898340502f41f0922f43b356930ce336b2f0…│
│0 críticas   0 altas   3 médias                                               │
│6 baixas   11 informativas                                                    │
│ia  Análise concluída: 20 achados (0 críticos, 0 altos, 3 médios, 6 baixos e …│
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
┌ Achados ─────────────────────────────────────────────────────────────────────┐
│> MÉDIA   Achado Nikto nikto:600720 — SimpleHTTP/0.6 appears to be outdated…  │
│  MÉDIA   ZAP zap:10038-1 cwe:693 — Content Security Policy (CSP) Header No…  │
│  MÉDIA   ZAP zap:10020-1 cwe:1021 — Missing Anti-clickjacking Header         │
│  BAIXA   Achado Nikto nikto:999957 — The anti-clickjacking X-Frame-Options…  │
│  BAIXA   Achado Nikto nikto:999102 — The X-XSS-Protection header is not de…  │
│  BAIXA   Achado Nikto nikto:999103 — The X-Content-Type-Options header is …  │
│  BAIXA   Achado Nikto nikto:007252 — #wp-config.php# file found. This file…  │
│  BAIXA   ZAP zap:10036 cwe:200 — Server Leaks Version Information via "Ser…  │
│  BAIXA   ZAP zap:10021 cwe:693 — X-Content-Type-Options Header Missing       │
│  INFORM. Porta 38164 — SimpleHTTPServer 0.6 exposto                          │
└──────────────────────────────────────────────────────────────────────────────┘
 Nova análise                                         Exportar       Explicação

 ● Execução concluída com 1 ocorrências · ferramenta [f1 ajuda  ctrl+p comandos
```

A unica ocorrencia e real: o alvo `http://169.254.1.2:38164` nao e um
repositorio Git, entao o TruffleHog falhou de verdade, como mostra a auditoria.

```text
$ jq -r '.tools_executed[] | "\(.tool_name) \(.status)"' scan_*.json
Nmap succeeded
Nuclei succeeded
Nikto succeeded
SQLMap succeeded
TruffleHog failed
ZAP succeeded
```

### Detalhe com evidencia do scanner e proveniencia

```text
 SmartSec  / Detalhe do achado  05/05  http://169.254.1.2:38164
────────────────────────────────────────────────────────────────────────────────
┌ Evidência e recomendação ────────────────────────────────────────────────────┐
│MÉDIA  Achado Nikto nikto:600720 — SimpleHTTP/0.6 appears to be outdated (curr│
│ferramenta  Nikto   alvo  http://169.254.1.2:38164                            │
│detectado  2026-10-01T00:58:51Z   origem  real                                │
│                                                                              │
│Descrição                                                                     │
│O teste nikto:600720 do Nikto foi acionado pelo método HEAD em                │
│http://169.254.1.2:38164/. Detalhe informado pelo scanner: SimpleHTTP/0.6     │
│appears to be outdated (current is at least 1.2)                              │
│                                                                              │
│Evidência                                                                     │
│nikto referencia: nikto:600720 | método: HEAD | url: http://169.254.1.2:38164/│
│| host: 169.254.1.2 | banner: SimpleHTTP/0.6 Python/3.14.7 | msg:             │
│SimpleHTTP/0.6 appears to be outdated (current is at least 1.2)               │
│                                                                              │
│Recomendação                                                                  │
│Confirme o achado no endpoint http://169.254.1.2:38164/, aplique a correção   │
│pertinente ao servidor e repita a varredura.                                  │
└──────────────────────────────────────────────────────────────────────────────┘
  Voltar                                                            Explicação

 ● Execução concluída com 1 ocorrências · ferramenta [f1 ajuda  ctrl+p comandos
```

O painel se chamava "Evidencia e recomendacao" mas nunca renderizava o campo
`evidence`; agora ele mostra a evidencia minima do scanner, o alvo, o instante
da deteccao e a origem do achado.

## Testes que sustentam a mudanca

`cargo test` (linha de base da branch: 372 testes; depois desta mudanca: 385).

Sequencia ponta a ponta do pipeline e transicao sem contagem de ticks:

```text
tui::state::tests::the_real_event_sequence_reaches_the_results_screen ... ok
tui::state::tests::the_analysis_transition_waits_for_the_pipeline_and_not_for_ticks ... ok
tui::state::tests::tool_audit_and_ai_failures_are_all_reported ... ok
tui::state::tests::critical_findings_come_first_without_touching_severities ... ok
tui::state::tests::cancel_run_stops_the_pipeline_and_keeps_the_audit ... ok
tui::state::tests::a_cancelled_run_does_not_restart_itself_in_automatic_mode ... ok
tui::state::tests::shutdown_run_aborts_the_executor_without_blocking ... ok
tui::state::tests::log_pressure_drops_instead_of_blocking_and_is_reported ... ok
tui::state::tests::disconnected_worker_surfaces_an_error_instead_of_hanging ... ok
tui::event::tests::the_tui_stays_responsive_under_a_full_log ... ok
tui::snapshot_tests::execution_screen_shows_every_registered_occurrence ... ok
tui::snapshot_tests::finding_detail_shows_long_and_sanitized_evidence ... ok
tui::snapshot_tests::critical_findings_lead_the_list_and_keep_their_color_when_selected ... ok
tui::snapshot_tests::results_summary_aggregates_occurrences_and_shows_the_ai_summary ... ok
tui::snapshot_tests::analysis_states_match_80x24_snapshots_without_neural_decoration ... ok
tui::snapshot_tests::tool_selection_ready_and_empty_match_80x24_snapshots ... ok
```

Dois pontos que valem registro:

- `a_cancelled_run_does_not_restart_itself_in_automatic_mode` nasceu da medicao
  real: ao cancelar, a TUI voltava para a selecao e o modo automatico reiniciava
  a execucao imediatamente (antes havia 50 quadros de espera entre uma coisa e
  outra). O cancelamento passou a ser estavel.
- `the_analysis_transition_waits_for_the_pipeline_and_not_for_ticks` roda 200
  quadros sem nenhum evento e exige que a tela continue em `Execucao`; um unico
  `FindingsBuilt` leva para `Analise` e um unico `Completed` leva para
  `Resultados`. Nenhuma contagem de ticks participa da decisao.

## Saida dos snapshots (80x24)

Trechos dos snapshots novos, extraidos dos testes que verificam 24 linhas e
largura maxima de 80 colunas.

```text
┌ Progresso da análise ────────────────────────────────────────────────────────┐
│⠙ gerando orientações · 0s                                                    │
└──────────────────────────────────────────────────────────────────────────────┘
┌ Atividade ───────────────────────────────────────────────────────────────────┐
│⠙ As orientações da IA não alteram a severidade dos scanners                  │
│                                                                              │
│modelo  llama3.2:1b   achados  4                                              │
│espera  0s                                                                    │
└──────────────────────────────────────────────────────────────────────────────┘
                                                                     > Cancelar

 ● IA em processamento · gerando orientações · 0s      f1 ajuda  ctrl+p comandos
```

```text
┌ Ocorrências ─────────────────────────────────────────────────────────────────┐
│ferramenta: Nmap falhou: imagem ausente no Podman                             │
│IA: A LLM principal falhou: conexão recusada; usando o Ollama local           │
│auditoria: falha ao salvar auditoria: sem permissão                           │
└──────────────────────────────────────────────────────────────────────────────┘
```

```text
┌ Achados · 1 crítico(s) no topo ──────────────────────────────────────────────┐
│> CRÍTICA Achado de teste                                                     │
│  BAIXA  Versão exposta                                                       │
└──────────────────────────────────────────────────────────────────────────────┘
```

```text
┌ Evidência e recomendação ────────────────────────────────────────────────────┐
│CRÍTICA  Achado de teste                                                      │
│ferramenta  Nuclei   alvo  https://exemplo.local                              │
│detectado  2026-09-04T14:00:00Z   origem  real                                │
│                                                                              │
│Descrição                                                                     │
│Descrição técnica                                                             │
│                                                                              │
│Evidência                                                                     │
│template: expose-config · matched-at: https://alvo.local/actuator/env ·       │
│matched-header muito longo matched-header muito longo matched-header muito    │
│longo matched-header muito longo matched-header muito longo matched-header    │
│                                                  ↑↓ rolar · linhas 1-16 de 21│
└──────────────────────────────────────────────────────────────────────────────┘
```

O teste `finding_detail_shows_long_and_sanitized_evidence` tambem rola ate o
fim e exige `[REDACTED]` no lugar da linha que continha
`Authorization: Bearer token-secreto-1234567890`: a evidencia exibida passa por
`sanitize_text`, e o mesmo dado continua aparecendo no relatorio Markdown e no
log de auditoria sem corpo HTTP nem credencial.

## Verificacoes

```text
$ cargo fmt --check
(sem saida: nada a formatar)

$ cargo clippy --all-targets -j 1 -- -D warnings
    Checking smartsec-rust v0.2.0 (/home/luis/dev/bobera/tcc/smartsec-rust/.worktrees/issue-20)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 3.00s

$ cargo test -j 1
running 328 tests   (unidades, inclui TUI e snapshots 80x24)
test result: ok. 328 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.80s
running 3 tests
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
running 6 tests
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 94.82s
running 20 tests
test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.78s
running 9 tests
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 81.41s
running 12 tests
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 139.01s
running 7 tests
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 182.22s
```

Total: 385 testes, 0 falhas. Os testes de integracao de container sao os
mesmos que ja existiam na branch de integracao e rodam scanners reais em Podman
rootless.
