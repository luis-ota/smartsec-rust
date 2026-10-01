# Evidencia — Issue #24 [S2] Historico consultavel de execucoes

Branch: `feat/issue-24`
Requisito: REQ19 (manter historico consultavel para auditoria)
Sprint 2 — Expansao, Relatorios e DevOps

## 1. Resumo do que foi entregue

| Criterio de aceite | Status | Evidencia |
|---|---|---|
| CLI lista e abre execucoes por ID | Atendido | secao 3 |
| TUI oferece consulta ao historico | Atendido | secao 4 |
| Registros parciais e versoes anteriores falham de forma segura | Atendido | secao 5 |
| A consulta nao altera os artefatos originais | Atendido | secao 6 |
| Testes cobrem historico vazio, completo e corrompido | Atendido | secao 7 |

O achado central da auditoria previa foi confirmado: a **consulta** ja existia em
`src/orchestrator/scan_logger.rs` e estava 100% morta (`#[allow(dead_code)]` em
`list_scan_logs_from_dir`, `ScanRecordSummary` e `load_scan_log_from_file`). Nao
ha indice em disco; a listagem e uma varredura de `~/.config/smartsec/scans/`.
O que faltava era oILO de falha honesta, a conexao com CLI e TUI e a comunicacao
do `scan_id` ao usuario.

## 2. Contrato alterado

### 2.1 Novos subcomandos da CLI

```text
smartsec history [--limit <N>]      # lista as execucoes (padrao 20)
smartsec show <SCAN_ID>             # abre uma execucao pelo identificador
```

O `scan_id` tem o formato `scan_<nanos>` e **nao e adivinhavel**. Sem exibi-lo, o
historico seria inutil para quem executou um scan headless. O modo headless agora
imprime o identificador e o comando de consulta ao final da execucao
(`src/main.rs`, `run_headless`).

### 2.2 `scan_id` exibido ao usuario (saida real)

```text
  OK Relatório exportado: smartsec-report.md
  OK Log estruturado: /home/user/.config/smartsec/scans/scan_1757000000000000000.json
  OK ID da execução: scan_1757000000000000000
     consulte depois com: smartsec show scan_1757000000000000000
```

### 2.3 Exit codes

`TCC_SPEC.md` secao 10 foi atualizada. Decisao e justificativa:

- `history` retorna `0` mesmo com historico vazio: a listagem foi executada com
  sucesso, e `0` e o codigo de "nenhum achado critico", que tambem descreve um
  historico sem registros.
- `show <SCAN_ID>` retorna **`2`** para identificador invalido, fora do padrao ou
  inexistente. Justificativa: em automacao, um id inexistente e um **erro de uso
  da ferramenta**. Retornar `0` faria um pipeline de CI com id errado passar como
  "varredura limpa"; retornar `1` confundiria com "achado critico", que so faz
  sentido quando uma varredura foi executada. O codigo `2` ja e o contrato
  existente para "erro de configuracao ou de execucao", portanto nenhuma regra
  nova foi inventada.
- **Decisao pendente de review:** registros ilegiveis *dentro* de um historico
  listavel nao alteram o codigo de saida; eles sao impressos como `ATENCAO` na
  saida padrao. Falhar o comando inteiro por um registro corrompido entre varios
  validos inutilizaria a listagem em auditoria, mas tambem poderia esconder uma
  perda de dados em CI. A alternativa (exit `2` quando houver registro ilegivel)
  esta registrada aqui para decisao do revisor.

## 3. CLI — listagem e detalhe

Execucao real com `XDG_CONFIG_HOME` isolado, um registro valido e um corrompido:

```console
$ smartsec history
═══════════════════════════════════════════════════════════
  SmartSec — Histórico de execuções
═══════════════════════════════════════════════════════════
  1 de 1 execuções (limite 20)

  scan_1757000000000000001
    alvo         http://alvo.local/
    concluída em 2026-09-06T10:05:00Z
    execução     Auto · 1 achado · 0 críticas · 1 alta · 0 médias · 0 baixas · 0 informativas

  ATENÇÃO: 1 registro ilegível foi ignorado na listagem:
    - scan_1757000000000000002.json: conteúdo inválido ou incompleto: key must be a string at line 1 column 2

  Detalhe de uma execução: smartsec show <SCAN_ID>
═══════════════════════════════════════════════════════════
$ echo $?
0
```

O registro corrompido **aparece** com nome e motivo. Antes da mudanca ele sumia
em silencio por causa do `if let Ok(...) { if let Ok(...) { ... } }`.

```console
$ smartsec show scan_1757000000000000001
═══════════════════════════════════════════════════════════
  SmartSec — Execução scan_1757000000000000001
═══════════════════════════════════════════════════════════
  alvo         http://alvo.local/
  iniciada em  2026-09-06T10:00:00Z
  concluída em 2026-09-06T10:05:00Z
  modo         Auto · provedor Ollama
  achados      1 achado · 0 críticas · 1 alta · 0 médias · 0 baixas · 0 informativas
  registros    1

  Ferramentas executadas:
    Nmap         succeeded  1500 ms

  Achados:
    ALTA         Versao desatualizada [Nmap]
    INFORMATIVA  Cookie sem flag [Nuclei]

  Análise da IA:
    │ A superficie web expoe servicos com versoes antigas.
═══════════════════════════════════════════════════════════
$ echo $?
0
```

### 3.1 Seguranca do path traversal

`scan_log_path` (`src/orchestrator/scan_logger.rs`) valida o identificador
**antes de tocar o disco**:

```rust
pub fn is_valid_scan_id(scan_id: &str) -> bool {
    let Some(digits) = scan_id.strip_prefix("scan_") else {
        return false;
    };
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}
```

Decisao de seguranca: aceitar apenas `scan_` seguido de digitos ASCII e
estruturalmente insuficiente para expressar um caminho — nao existe `/`, nem `.`,
nem `\`. Portanto um id fora do padrao **nao pode** ser convertido em um caminho
arbitrario, e nao existe sanitizacao parcial que "esqueca" um caso. Em vez de
tentar bloquear `../` (lista infinita de bypasses: `%2e%2e`, `..%2f`, caminho
absoluto, barra inicial), o padrao fecha a classe inteira do problema. Um
`debug_assert_eq!(path.parent(), Some(dir.as_path()))` mantem a invariante perto
do ponto de construcao do caminho.

Rejeicoes verificadas em
`tests/history_cli.rs::show_rejects_path_traversal_and_ids_outside_the_pattern`:

```console
$ smartsec show ../../segredo
Erro: identificador de execução inválido: ../../segredo; esperado no formato scan_<nanos>
$ echo $?
2
```

Ids testados e recusados: `../../segredo`, `../../../etc/passwd`,
`scan_../../segredo`, `..%2fsegredo`, `/etc/passwd`, `scan_`, `scan_abc`,
`scan_1757000000000000001.json` e a string vazia. O teste tambem verifica que um
arquivo `segredo.json` semeado **fora** do diretorio de historico nunca e lido.

## 4. TUI — tela de historico

Buffers renderizados a 80x24 (RNF07), com tres registros e um corrompido:

```text
 SmartSec  / Histórico  06/06  sem alvo                                         
────────────────────────────────────────────────────────────────────────────────
┌ Execuções anteriores ────────────────────────────────────────────────────────┐
│> scan_1757000000000000002  2026-09-08T10:05:00Z                              │
│    http://alvo2.local/  2 ach.  C0 A1 M0 B0 I1                               │
│  scan_1757000000000000001  2026-09-07T10:05:00Z                              │
│    http://alvo1.local/  2 ach.  C0 A1 M0 B0 I1                               │
│  scan_1757000000000000000  2026-09-06T10:05:00Z                              │
│    http://alvo0.local/  2 ach.  C0 A1 M0 B0 I1                               │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│ 1 registro ilegível: scan_1757000000000000009.json                           │
└──────────────────────────────────────────────────────────────────────────────┘
  Voltar                                                                > Abrir 
                                                                                
 ● 3 execuções · 1 ilegível                           f1 ajuda  ctrl+p comandos 
```

Detalhe da execucao selecionada, mesmo terminal:

```text
 SmartSec  / Histórico  06/06  sem alvo                                         
────────────────────────────────────────────────────────────────────────────────
┌ Detalhe da execução ─────────────────────────────────────────────────────────┐
│scan_1757000000000000002  Auto                                                │
│alvo  http://alvo2.local/                                                     │
│conclusão  2026-09-08T10:05:00Z   início  2026-09-06T10:00:00Z                │
│provedor IA  Ollama                                                           │
│                                                                              │
│Ferramentas executadas                                                        │
│  Nmap         succeeded  1500 ms                                             │
│                                                                              │
│Achados                                                                       │
│  ALTA        Versão desatualizada                                            │
│                                                                              │
│Análise da IA                                                                 │
│  A superfície web expõe serviços antigos.                                    │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
  Voltar                                                                Voltar  
                                                                                
 ● Detalhe da execução · esc volta para a lista       f1 ajuda  ctrl+p comandos 
```

### 4.1 Integracao com o fluxo existente

- `AppStep::History` em `src/tui/state.rs`; render em
  `src/tui/screens/history.rs`, declarado em `screens/mod.rs` e `tui/mod.rs`.
- `FocusTarget::HistoryList`, `HistoryDetail`, `HistoryBack` e
  `SemanticAction::OpenHistory`, `OpenHistoryRecord(usize)` em
  `src/tui/interaction.rs`.
- Entrada na paleta de comandos em `src/tui/commands.rs`, junto as demais acoes
  globais, com atalho `h`.
- Binding de tecla `h` em `src/tui/event.rs`, guardado por `!accepts_text(app)`
  (mesmo padrao do `?`): na tela inicial o `h` continua digitando no alvo.
- Item de ajuda `h — consultar o historico de execucoes` em
  `src/tui/screens/overlays.rs`. O texto "pause ou cancele a execucao" da ajuda
  nao foi tocado: a pausa pertence a issue #21.
- O contador de passos do cabecalho passou de `/05` para `/06`.
  **Decisao pendente de review:** `F2` continua se chamando "rastreabilidade da
  Sprint 1" e lista 5 requisitos. Incluir o REQ19 exigiria renomear o overlay e
  mexer no orcamento de espaco do `80x24`, com teste de snapshot proprio, entao
  foi deixado para a Sprint 3 (validacao). O REQ19 foi rastreado em
  `TCC_SPEC.md` secao 4.

### 4.2 Decisao de UX: por que `h` nao abre durante a execucao

Abrir o historico durante `AppStep::Execution` trocaria o `step` enquanto o
`RunEvent::Completed` pendente ainda pode sobrescreve-lo com `AppStep::Analysis`,
tirando o usuario do historico sem aviso. A paleta de comandos oferece "Consultar
historico de execucoes" desabilitada durante a execucao, e a tecla `h` tambem e
ignorada nesse `step`. Em Splash e Results a consulta fica disponivel.

**Decisao pendente de review:** a auditoria sugeria colocar a entrada da paleta
ao lado de "Cancelar execucao", dentro do ramo `AppStep::Execution`. Optamos por
uma entrada global desabilitada durante a execucao, por coerencia com as demais
acoes globais ("Abrir ajuda", "Abrir configuracoes") e pelo motivo de UX acima.

## 5. Registros parciais, corrompidos e de versao anterior

| Cenario | Comportamento |
|---|---|
| JSON quebrado | Nao entra na listagem; aparece como "N registro(s) ilegivel(is)" com nome do arquivo e motivo |
| Registro parcial (campo obrigatorio ausente) | `show` falha com mensagem acionavel; a listagem o marca como ilegivel |
| Versao anterior sem `info_count`, `decisions`, `podman_trace` | Carrega normalmente; campos ausentes assumem o padrao (`0` / vazio) |
| Diretorio inexistente | Mensagem "Nenhuma execucao registrada ainda" |
| Diretorio vazio | Mensagem "O historico esta vazio" (diferente do inexistente) |

Mensagem de falha para registro parcial/corrompido:

```text
Erro: Falha ao interpretar o registro de execução em ".../scan_...json": o arquivo pode estar corrompido, incompleto ou em uma versão anterior do formato: missing field `target_url` at line 1 column 51
```

O contexto em portugues brasileiro nomeia as tres causas provaveis; a causa
tecnica do `serde` continua na cadeia de contexto, visivel porque a CLI imprime
com `eprintln!("Erro: {error:#}")`.

## 6. Criterio (d) — a consulta nao altera os artefatos

Este era o criterio sem nenhuma cobertura de teste na auditoria. A verificacao
fotografa o diretorio **byte a byte** antes e depois da consulta:

```rust
let before = snapshot_bytes(&dir);          // Vec<(nome, Vec<u8>)> ordenado
// ... lista e abre todos os registros ...
assert_eq!(
    snapshot_bytes(&dir),
    before,
    "a consulta ao historico nao pode alterar os artefatos originais (criterio d)"
);
```

Cobertura:

- `complete_history_is_ordered_by_completion_without_touching_the_files`
  (3 registros, listagem + abertura de todos).
- `corrupted_record_is_reported_instead_of_disappearing` (o arquivo quebrado
  tambem nao pode ser reescrito).
- `partial_record_fails_with_an_actionable_message`.
- `history_lists_executions_from_the_newest_to_the_oldest`,
  `history_reports_unreadable_records_instead_of_hiding_them` e
  `show_opens_a_recorded_execution_with_its_findings_analysis_and_tools`
  (`tests/history_cli.rs`, ponta a ponta com o binario).

Nenhum caminho de leitura abre o arquivo para escrita: `list_scan_logs_from_dir`
e `load_scan_log_from_file` usam apenas `fs::read_to_string`.

## 7. Testes

```console
$ cargo test -j 1 --bin smartsec-rust scan_logger
running 8 tests
test orchestrator::scan_logger::tests::empty_and_missing_history_are_distinguishable ... ok
test orchestrator::scan_logger::tests::partial_record_fails_with_an_actionable_message ... ok
test orchestrator::scan_logger::tests::scan_id_rejects_path_traversal_and_out_of_pattern_values ... ok
test orchestrator::scan_logger::tests::persisted_scan_removes_http_payloads_and_credentials ... ok
test orchestrator::scan_logger::tests::previous_version_without_new_fields_is_readable ... ok
test orchestrator::scan_logger::tests::corrupted_record_is_reported_instead_of_disappearing ... ok
test orchestrator::scan_logger::tests::test_save_and_load_scan_log ... ok
test orchestrator::scan_logger::tests::complete_history_is_ordered_by_completion_without_touching_the_files ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 213 filtered out; finished in 0.01s
```

```console
$ cargo test -j 1 --test history_cli
running 11 tests
test help_documents_the_history_contract ... ok
test history_lists_executions_from_the_newest_to_the_oldest ... ok
test history_of_an_empty_directory_explains_how_to_create_records ... ok
test history_reports_unreadable_records_instead_of_hiding_them ... ok
test history_respects_the_configured_limit ... ok
test history_without_a_limit_is_rejected_instead_of_hiding_records ... ok
test show_fails_with_code_2_when_the_id_does_not_exist ... ok
test show_opens_a_recorded_execution_with_its_findings_analysis_and_tools ... ok
test show_reads_a_previous_version_of_the_record_format ... ok
test show_rejects_path_traversal_and_ids_outside_the_pattern ... ok
test unknown_verb_still_reports_the_known_options ... ok

test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
```

`tests/history_cli.rs` isola `XDG_CONFIG_HOME`/`HOME` e `current_dir` por teste,
seguindo `tests/headless_exit_codes.rs`, e semeia registros em `smartsec/scans/`.
Nenhum teste depende da maquina de quem executa.

## 8. Verificacoes

Executadas no worktree `/home/luis/dev/bobera/tcc/smartsec-rust/.worktrees/issue-24`
com `-j 1` (a maquina nao sustenta `-j 2`).

```console
$ cargo fmt --check
(sem saida — formatacao ok)

$ cargo clippy --all-targets -j 1 -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 19s

$ cargo test -j 1
running 221 tests
test result: ok. 221 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.76s
running 3 tests   (tests/headless_exit_codes.rs)
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.11s
running 11 tests  (tests/history_cli.rs)
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
running 6 tests   (tests/nikto_integration.rs)
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 204.27s
running 12 tests  (tests/podman_executor.rs)
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.87s
```

## 9. Diff

Arquivos tocados, todos dentro do escopo da issue #24. Em `src/main.rs`,
`src/orchestrator/scan_logger.rs` e `TCC_SPEC.md` — arquivos que outros agentes
editam em paralelo — o diff e aditivo e nao reformata nada: nas remocoes, em
`src/main.rs` constam apenas as tres linhas de `--help` que o novo contrato exige,
em `scan_logger.rs` apenas as funcoes de listagem/carga e os tres
`#[allow(dead_code)]` que deixaram de ser necessarios, e `src/tui/state.rs`,
`src/tui/interaction.rs`, `src/tui/chrome.rs` e `src/tui/mod.rs` nao tiveram
nenhuma linha removida.

| Arquivo | Natureza |
|---|---|
| `src/orchestrator/scan_logger.rs` | `ScanHistory`, `ScanSeverityCounts`, `UnreadableScanRecord`, listagem honesta, validacao de `scan_id`, carga por id, 6 testes |
| `src/main.rs` | verbos `history`/`show`, `--limit`, comunicacao do `scan_id`, `--help` |
| `tests/history_cli.rs` | novo: 11 testes de integracao da CLI |
| `src/tui/screens/history.rs` | novo: tela de lista e detalhe |
| `src/tui/state.rs` | `AppStep::History`, estado do historico, carga somente leitura |
| `src/tui/event.rs` | binding `h`, foco, navegacao, `Back`, scroll, 4 testes |
| `src/tui/interaction.rs` | `FocusTarget` e `SemanticAction` do historico |
| `src/tui/commands.rs` | entrada na paleta |
| `src/tui/screens/overlays.rs` | linha de ajuda e contexto da tela |
| `src/tui/screens/mod.rs`, `src/tui/mod.rs`, `src/tui/chrome.rs` | registro do modulo, render, numeracao `06/06` |
| `src/tui/snapshot_tests.rs` | 3 snapshots do historico em `80x24` |
| `TCC_SPEC.md`, `README.md` | contrato de CLI/TUI, exit codes, rastreabilidade do REQ19 |

Sem dependencia nova, sem mock no fluxo real e sem `Box::leak`.
