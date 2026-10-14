# Handoff — smartsec-rust, PR #105

Branch `feat/auditoria-codigo-ia` → `main`. Tudo commitado e pushed. PR #105 aberto e MERGEABLE.

## Regras do projeto (leia antes de editar)

`AGENTS.md` na raiz. As duas que mais quebram:

- **Comentário: no máximo 2 linhas, só para o *por que* não óbvio.** O usuário reclamou duas vezes nesta sessão por comentários enormes. Comentário que repete o código é ruído. Se um comportamento é verificável, escreve teste, não comentário.
- **Nenhum teste toca `~/.config/smartsec/`, keyring real ou rede real.** Já causou 2 incidentes. Para testar log/trilha, use `orchestrator.scan_metadata()` (monta o `ScanMetadata` sem gravar) ou um `temp_dir()` próprio.

## Estado atual

Branch limpa, `35db5d2` no topo. Validação local: **640 testes unitários verdes**, `cargo fmt --check` limpo, `cargo clippy --all-targets -- -D warnings` com 0 avisos.

Commits desta sessão:
- `35db5d2` — trilha de auditoria da IA + IA local fora do padrão + lista de provedores reordenada + `scan_metadata`
- `e127c89` — IA local desligada por padrão
- `5083e65` — corrige o `--help` (faltavam `--max-critical-findings`, "ferramenta desconhecida", "comando desconhecido")
- `4fa59b1` — desliga a regra de SQLi (100% FP medido) → issue #104
- `39b7a35` — assistente de configuração + corrige help duplicado
- `afd2d1e` — corrige duas regras da auditoria de código

## O que está pronto

**IA opcional.** `LlmConfig::default()` nasce sem provedor local. `is_configured()` devolve falso quando o endpoint é vazio e `validate()` retorna `Ok` nesse caso — sem IA o scan funciona com a análise determinística local. O CI pegou o problema: 5 testes do Nikto quebravam com `Erro: Nenhuma IA configurada`, porque `build_config` exigia provedor e os scanners não dependem dele.

**Lista de provedores.** `all_labels()` = `["Personalizado", "OpenAI", "NVIDIA NIM", "llama.cpp"]`. API primeiro, servidor local por último. `LlmProviderKind::index()` deriva a posição da lista — substitui dois `match` manuais em `src/tui/state.rs` (linhas ~331 e ~1457) que dessincronizavam ao reordenar.

**Trilha de auditoria da IA** (`src/code_agent/audit_trail.rs`, novo). Cada ação da IA vira uma linha JSON escrita e descarregada no instante, em `~/.config/smartsec/agent-trails/<scan_id>.jsonl`. Existe porque o log estruturado só é gravado no fim: fase interrompida não deixava registro nenhum. `smartsec trace <SCAN_ID>` imprime; o `ScanMetadata` ganhou `agent_trail_path` apontando para ela. Trilha e log compartilham o `scan_id` do orquestrador.

O repasse disco↔TUI é uma tarefa que lê o mesmo canal que a TUI lê (`analyze_code` em `pipeline.rs`), então os dois não divergem. Best effort: diretório não gravável cai para `temp_dir()` em vez de derrubar o scan.

Dois caminhos da fase **não registravam nada** e um teste pegou os dois: recusa por consentimento e diretório de projeto ilegível. Ambos gravam `CodeAgentEvent::Finished` agora.

## O bloqueio real do E2E — não é a IA

**Isto é o que ninguém resolveu ainda e vale mais que qualquer outra tarefa.**

`correlate_and_enrich_findings` roda **antes** da fase de IA (`src/main.rs` ~linha 732) e consulta a NVD **em série**: `MIN_INTERVAL_SEM_CHAVE` = 6 s entre requisições + `REQUEST_TIMEOUT` = 10 s cada (`src/orchestrator/nvd.rs` linhas 50–62). Com N CVEs são N × 16 s de espera, e sem rede cada uma vira os 10 s inteiros. Sem cache (`~/.config/smartsec/nvd-cache` está vazio aqui) o primeiro scan paga tudo.

Nenhum scan chegou à fase de IA em ~6 tentativas. O sintoma é sempre o mesmo: para logo depois de `[1/4] Executando ferramentas`, processo `State: R (running)` com 9 threads, sem conexão de rede ativa. Não é o modelo, não é a NIM.

O que já confirmei da fase de IA por outro caminho: `nvidia/nemotron-3-super-120b-a12b` responde tool calling em 1,5 s via curl. `meta/llama-3.3-70b-instruct`, `qwen/qwen2.5-coder-32b-instruct` e `meta/llama-3.1-8b-instruct` estão **fora de linha** (HTTP 410). Dos 15 `:free` do OpenRouter só `nvidia/nemotron-3-super-120b-a12b:free` faz tool calling.

O servidor reinicia e mata processos longos a cada ~5 min. Lance com `setsid --fork nohup ... </dev/null` e acompanhe por log. `/tmp` às vezes é limpo por outro agente.

## Chaves

Os valores **não** ficam neste arquivo — a regra do repositório barra
qualquer segredo em commit, e com razão. Eles estão no keyring do usuário,
serviço `smartsec`:

```
groq-api-key
openrouter-api-key
nvidia-nim-api-key
llm-api-key           (a ativa; hoje aponta para a chave da NIM)
```

Para ler: `secret-tool lookup service smartsec username <nome>`

Configs de teste: `/tmp/ss-nim.toml` (NIM, `nvidia/nemotron-3-super-120b-a12b`), `/tmp/ss-groq.toml`, `/tmp/ss-or.toml`, `/tmp/ss-sem-ia.toml` (sem IA nenhuma).

Alvo: `/tmp/app-vuln/app.py` na porta 3001, alcançável do container rootless via `http://169.254.1.2:3001`.

## Comandos

```bash
flock .git/smartsec-build.lock -c 'cargo build -j 1 --release'
cargo fmt --check
flock .git/smartsec-build.lock -c 'cargo clippy --all-targets -j 1 -- -D warnings'
flock .git/smartsec-build.lock -c 'cargo test -j 1 --bin smartsec'
```

**NUNCA** `cargo test` sem `--bin`: a suíte de integração executa o binário real contra Ollama e trava a máquina. Binário chama-se `smartsec`.

`pkill -f <padrão>` mata o próprio shell se o padrão casar a própria linha — use classe de caractere (`ss-prox[y]`) ou mate por PID.

## Próximos passos, em ordem

1. **Investigar e corrigir o custo do enriquecimento NVD antes da IA.** Opções: teto de tempo total para o enriquecimento, consulta paralela dentro do intervalo publicado, ou mover a fase para depois da IA. Com um teste que prove que o scan com CVEs fecha em tempo aceitável.
2. Fechar o E2E da fase de IA com a NIM e confirmar relatório + `smartsec trace` com ações reais.
3. Verificar os 2 jobs do CI do PR #105.
4. Mergear #105 e fechar as issues de Sprint 2. Só Sprint 3 fica aberta (#104, SQLi sobre `ast`, FP como critério de merge).

## O que não fazer de novo

Rodar só `--bin smartsec` deixou o `--help` sem cobertura e o CI pegou três lacunas minhas. As suítes de integração que não tocam scanner (`tests/headless_signals.rs`, `tests/headless_exit_codes.rs`, `tests/history_cli.rs`, `tests/code_agent_integration.rs`, `tests/report_cli.rs`) leem o help e precisam rodar.

`tests/nikto_integration.rs` roda o binário real — foi ela que pegou a mudança de "IA obrigatória".

O worktree `review-77b` (detached, `e36be1d`) tem commits fora da `main`. Não mexer.