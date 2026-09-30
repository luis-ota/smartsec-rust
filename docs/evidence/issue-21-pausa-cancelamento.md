# Evidencia real — pausa, retomada, cancelamento e interrupcao automatica (issue #21)

Escopo: comprovar que as ordens manuais e a regra automatica REQ05 afetam o
container real do Podman rootless, que nenhum caminho deixa container orfao e que
o modo headless reage a sinais do sistema preservando relatorio e log.

Ambiente: Linux, Podman 6.1.1 rootless, backend de rede `pasta`. Alvo: servidor
HTTP local em `127.0.0.1:38171`, publicado no container pela rede `pasta` como
`169.254.1.2:38171`. Nenhum alvo externo foi escaneado.

---

## 1. Pausa e retomada afetam o container real (TUI)

Execucao real do Nuclei contra o alvo local autorizado, com a TUI em terminal
`80x24`. Alinhado a `p`, o container real foi congelado:

```console
$ tmux send-keys -t smartsec-pausa p

 SmartSec  / Execucao  03/05  http://169.254.1.2:38171
┌ Progresso geral · 0% ────────────────────────────────────────────────────────┐
│‖ Nuclei      pausada                                                         │
│○ Nikto       aguardando                                                      │
└──────────────────────────────────────────────────────────────────────────────┘
↑↓ logs · esc cancela                      Retomar varredura  Cancelar varredura

 ● Execucao PAUSADA · 0/3 concluidas · p retoma       f1 ajuda  ctrl+p comandos
```

O estado **no Podman**, consultado fora do SmartSec:

```console
$ podman inspect --format 'paused={{.State.Paused}}' a75bdac21fde…
paused=true
```

E o evento real do engine:

```console
$ podman events --stream=false --since 30s --filter container=a75bdac21fde…
2026-09-30 19:58:52.271050311 -0300 -03 container pause a75bdac21fde… (image=docker.io/projectdiscovery/nuclei@sha256:2a11faa8…)
```

Apos o mesmo atalho `p`, a retomada:

```console
$ podman inspect --format 'paused={{.State.Paused}}' a75bdac21fde…
paused=false
$ podman events --stream=false --since 15s --filter container=a75bdac21fde…
container pause
container unpause
```

A tela voltou a `executando` e o botao a `Pausar varredura`. A pausa e um
`podman pause` de verdade, nao uma bandeira local.

## 2. Cancelamento na TUI sem orfao

Com a execucao em andamento, `c`:

```console
$ tmux send-keys -t smartsec-pausa c

 SmartSec  / Resultados  05/05  http://169.254.1.2:38171
┌ Resumo ──────────────────────────────────────────────────────────────────────┐
│Execucao cancelada: o container 26eb9f74dc5037d1878c1e10c1a19f397f6d2933f2ee0…│
│0 criticas   0 altas   0 medias                                               │
│0 baixas   0 informativas                                                     │
│auditoria  scan_1790809923153091506.json                                      │
└──────────────────────────────────────────────────────────────────────────────┘

$ podman ps -a --format '{{.ID}} {{.Names}}'
(vazio)
```

O log estruturado registra o motivo:

```console
interruption: cancelado_pelo_usuario | Execucao cancelada pelo usuario
tools: [('Nuclei', 'cancelled')]
```

## 3. Headless reagindo a SIGINT e SIGTERM (container real)

Comando, alvo local e script do scanner mantendo a execucao em andamento:

```bash
smartsec-rust scan --target http://169.254.1.2:38171 --config config/smartsec.toml
```

### SIGINT

```console
$ podman ps --format '{{.Names}} {{.Status}}'
smartsec-2471014-1790809941736990063-1 Up 12 seconds
$ kill -INT $PID
$ echo $?
130
$ podman ps -a --format '{{.ID}} {{.Names}}'
(vazio)
```

Trace operacional, com o encerramento cooperativo e a remocao:

```
[23:12:33] cancelamento recebido; encerrando o container 23886a56cd55…
[23:12:33] $ podman stop --time 5 23886a56cd55…
[23:12:38] container 23886a56cd55… encerrado por cancelamento solicitado
[23:12:38] $ podman rm --force --ignore 23886a56cd55…
[23:12:38] container 23886a56cd55… removido
```

Mensagem final — relatorio e log gravados **antes** dela:

```
  OK Relatorio exportado: relatorio.md
  OK Log estruturado: /tmp/.../cfg/smartsec/scans/scan_1790809941736990063.json
  X Interrupcao registrada: Execucao cancelada pelo sinal SIGINT; o relatorio e o log estruturado foram preservados
  X Execucao cancelada por SIGINT.
```

### SIGTERM

```console
$ kill -TERM $PID
$ echo $?
143
$ podman ps -a --format '{{.ID}} {{.Names}}'
(vazio)
```

Log correspondente:

```console
interruption: cancelado_por_sinal
Execucao cancelada pelo sinal SIGTERM; o relatorio e o log estruturado foram preservados
```

## 4. Sem container orfao em nenhum estagio

O executor emite `rm --force --ignore` em **todos** os caminhos, verificado com
`FakePodman` (`src/orchestrator/sandbox.rs`):

| Estagio do cancelamento | Teste | Evidencia |
|---|---|---|
| antes do `create` | `cancel_before_create_never_creates_a_container` | nenhum `create --name`; `rm --force --ignore smartsec-` |
| durante o `create` | `cancel_during_create_removes_the_container_by_name` | sem `start --attach`; `rm --force --ignore smartsec-` |
| apos o `start` | `cancel_after_pause_stops_and_removes_the_container` | `stop --time 5` e `rm --force --ignore container-123` |
| corrida com o fim natural | `cancel_racing_with_the_finished_container_still_removes_it` | 12 iteracoes, container sempre removido |
| com container real | `cancelling_a_real_container_stops_and_removes_it` | `podman container exists` falso |

O guard `ContainerCleanup` continua como ultima linha de defesa para erro e
queda do processo; os testes `cancellation_still_removes_container` e
`cancellation_during_creation_removes_container_by_name` seguem verdes.

Verificacao final do ambiente depois de toda a execucao:

```console
$ podman ps -a --format '{{.ID}} {{.Names}}'
(vazio)
```

## 5. Regra automatica de interrupcao (REQ05)

Duas ferramentas de teste registradas por `[[tools]]`: a primeira emite um
achado **critico real** (parser `nuclei-jsonl`, severidade vinda do scanner) e a
segunda demoraria 60 s. Alvo local autorizado.

### Dispara no limiar

```console
$ smartsec-rust scan --target http://169.254.1.2:38171 --config config/regra.toml
  Regra de interrupcao: 1 vulnerabilidades criticas
  OK (2026-09-30T23:14:40Z, 251 bytes de saida)
  OK Log estruturado: /tmp/.../scans/scan_1790810081683069981.json
  X Interrupcao registrada: Regra automatica de interrupcao: 1 vulnerabilidades criticas em Lento atingiram o limite de 1

$ grep -c "LENTO INICIADO" saida-regra-disparo.log
0
$ echo $?
1
```

A segunda ferramenta **nao chegou a iniciar** — a avaliacao entre ferramentas
preserva a evidencia recem-coletada e nao mata o container que a produziu.
Tempo total: 1,2 s, em vez dos 60 s que a ferramenta lenta exigiria.

Motivo persistido, recuperavel do log estruturado:

```json
{
  "rule": "max_critical_findings",
  "message": "Regra automatica de interrupcao: 1 vulnerabilidades criticas em Lento atingiram o limite de 1",
  "tool": "Lento",
  "critical_count": 1,
  "threshold": 1,
  "recorded_at": "2026-09-30T23:14:41Z"
}
```

### Nao dispara abaixo do limiar

Com `max_critical_findings = 2`, a ferramenta lenta **comecou** a rodar
(`grep -c "LENTO INICIADO" = 2`, contando o comando e a saida), confirmando
que a regra nao e um cancelamento unconditional.

Com `--max-critical-findings 0`, a linha "Regra de interrupcao" nem aparece na
saida e o codigo de saida e `0`: regra desativada mantem o comportamento
anterior.

### Historicos antigos continuam legiveis

`a_scan_log_written_before_this_feature_still_loads` remove o campo novo do JSON
e confirma que a desserializacao continua funcionando — `interruption` tem
`#[serde(default)]`, como os demais campos adicionados depois.

## 6. Cobertura de transicoes e condicoes de corrida

Cada transicao e cada corrida tem teste proprio, conforme o criterio de aceite.

**Transicoes** (`src/orchestrator/sandbox.rs`)

| Transicao | Teste | Comando de Podman asserido |
|---|---|---|
| executando → pausado | `pause_and_resume_issue_podman_pause_and_unpause` | `pause container-123` |
| pausado → executando | idem | `unpause container-123` |
| qualquer → cancelado | `cancel_after_pause_stops_and_removes_the_container` | `stop --time 5` + `rm --force --ignore` |
| executando → concluida | `captures_successful_execution_and_removes_container` | `rm --force --ignore container-123` |

**Corridas**

| Corrida | Teste |
|---|---|
| dupla pausa (idempotencia) | `repeated_pause_does_not_issue_a_second_pause` — um unico `pause` |
| pausa durante a subida do container | `pause_arriving_while_the_container_starts_is_applied` |
| pausa seguida de cancelamento | `cancel_after_pause_stops_and_removes_the_container` |
| cancelamento x `ToolFinished` / fim do processo | `cancel_racing_with_the_finished_container_still_removes_it` (12 iteracoes) |
| `stop` mata o scanner antes de responder | `a_stopped_container_is_cancelled_not_failed` |
| pausa recusada pelo Podman | `a_refused_pause_is_reported_and_the_scan_survives_it` |

**Canal de controle** (`src/orchestrator/control.rs`)

`pause_resume_and_cancel_travel_through_the_shared_channel`,
`a_late_subscriber_never_misses_an_order`, `repeated_pause_and_resume_are_idempotent`,
`the_pipeline_waits_while_paused_and_returns_on_cancel`,
`cancel_wins_over_pause_in_the_pipeline`,
`the_interruption_reason_travels_with_the_shared_channel`.

**Sinais** (`tests/headless_signals.rs`) — binario real, `HOME` e `XDG_CONFIG_HOME`
isolados, Podman falso no `PATH`, sem rede.

`sigint_cancels_the_scan_keeps_the_artifacts_and_leaves_no_container` e
`sigterm_cancels_the_scan_keeps_the_artifacts_and_leaves_no_container` verificam
exit code, presenca do relatorio e do log, `interruption.rule` no log e o
`rm --force --ignore` no trace. `the_help_text_documents_the_cancellation_exit_codes`
trava 130, 143 e `--max-critical-findings` no `--help`.

**TUI** (`src/tui/event.rs`, `src/tui/state.rs`, `src/tui/snapshot_tests.rs`)

- `p_toggles_pause_and_c_cancels_with_keyboard_and_mouse_parity` — paridade
  teclado/mouse no botao, verificada por `click_action` no hitbox real.
- `pause_and_cancel_shortcuts_are_ignored_inside_overlays` — `p` e `c` nao
  vazam para overlays.
- `the_execution_palette_exposes_pause_resume_and_cancel`.
- `the_paused_execution_state_is_legible_in_80x24` — snapshot em 80x24 exige
  `Execucao PAUSADA`, `pausada`, `Retomar varredura` e `Cancelar varredura`, e
  confirma que ambos os botoes tem hitbox clicavel.
- `the_running_execution_state_offers_the_pause_button`.
- `cancel_run_uses_the_control_channel_instead_of_aborting_the_task`.
- `the_cancelled_run_is_recorded_for_audit_without_creating_findings`.

## 7. Verificacoes automatizadas

```
$ cargo fmt --check
(codigo de saida 0)

$ cargo clippy --all-targets -j 1 -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s)

$ cargo test -j 1
     Running unittests src/main.rs (target/debug/deps/smartsec_rust-…)
test result: ok. 243 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

     Running tests/headless_exit_codes.rs
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

     Running tests/headless_signals.rs
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

     Running tests/nikto_integration.rs
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

     Running tests/podman_executor.rs
test result: ok. 30 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

## 8. Notas de decisao que a auditoria pode questionar

1. **A-bandeira `paused` foi removida, nao alimentada.** A auditoria apontou que
   `Orchestrator.paused` nunca recebia `true`. Alimenta-la teria deixado duas
   fontes de verdade (bandeira e canal) discordando. O canal `ControlChannel` e a
   unica fonte; `run_control_label()` expoe o estado **real** do container, e nao a
   intencao do usuario — se o Podman recusar o pause, a tela mostra o log de
   falha em vez de prometer uma pausa.

2. **O motivo da interrupcao mora no canal, e nao no `Orchestrator`.** A TUI e a
   task de execucao sao dois `Orchestrator` distintos ligados apenas pelo canal.
   Com o motivo no orquestrador, o log gravado pela task perdia o cancelamento da
   TUI — exatamente o bug observado na primeira verificacao real.

3. **A execucao sintetica `cancelled` continua existindo na TUI.** Ela e
   fabricada a partir do estado da tela e existe **apenas** para a auditoria:
   nao executa scanner algum e nao gera finding (coberto por
   `the_cancelled_run_is_recorded_for_audit_without_creating_findings`). Quando o
   executor ja registrou a execucao real com o trace do Podman, a sintetica nao e
   duplicada.

4. **`ExecutionStatus::Cancelled` corrige uma corrida real.** Quando o
   `podman stop` mata o scanner, o `start --attach` encerra antes de o aviso do
   controlador chegar, e o status virava `Failed(137)` — uma falha de scanner que
   nunca ocorreu. Agora o canal consultado decide, e a execucao fica registrada
   como cancelada.

5. **A regra avalia entre ferramentas, e nao durante a varredura.** Interromper
   no meio do scan mataria o container que esta produzindo a evidencia do achado
   critico. O TCC pede "interromper a execucao", e o requisito e sobre o pipeline,
   nao sobre descartar evidencia parcial.
