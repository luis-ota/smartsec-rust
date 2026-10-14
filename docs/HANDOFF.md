# Handoff — smartsec-rust, PR #105

> **Este arquivo descreve uma sessão numa máquina específica.** Na máquina nova
> nada abaixo existe ainda — nem o keyring, nem os arquivos em `/tmp`, nem os
> worktrees. A seção "Reconstituindo o ambiente" diz o que precisa ser refeito.
> Qualquer caminho citado fora do repositório é da máquina antiga, não um fato
> sobre o projeto.

Branch `feat/auditoria-codigo-ia` → `main`. Tudo commitado e pushed. PR #105 aberto e MERGEABLE.

```bash
git clone https://github.com/luis-ota/smartsec-rust.git
cd smartsec-rust
git fetch origin
git checkout feat/auditoria-codigo-ia   # 41bcd62
```

## Regras do projeto (leia antes de editar)

`AGENTS.md` na raiz. As duas que mais quebram:

- **Comentário: no máximo 2 linhas, só para o *por que* não óbvio.** O usuário reclamou duas vezes nesta sessão por comentários enormes. Comentário que repete o código é ruído. Se um comportamento é verificável, escreve teste, não comentário.
- **Nenhum teste toca `~/.config/smartsec/`, keyring real ou rede real.** Já causou 2 incidentes. Para testar log/trilha, use `orchestrator.scan_metadata()` (monta o `ScanMetadata` sem gravar) ou um `temp_dir()` próprio.

## Estado atual

Branch limpa, `41bcd62` no topo. Validação local: **640 testes unitários
verdes**, `cargo fmt --check` limpo, `cargo clippy --all-targets -D warnings`
com 0 avisos.

Commits desta sessão (do mais recente para o mais antigo):
- `41bcd62` — este handoff
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

`correlate_and_enrich_findings` roda **antes** da fase de IA (`src/main.rs` ~linha 732) e consulta a NVD **em série**: `MIN_INTERVAL_SEM_CHAVE` = 6 s entre requisições + `REQUEST_TIMEOUT` = 10 s cada (`src/orchestrator/nvd.rs` linhas 50–62). Com N CVEs são N × 16 s de espera, e sem rede cada uma vira os 10 s inteiros. Sem cache (`~/.config/smartsec/nvd-cache` nasce vazio) o primeiro scan paga tudo.

Nenhum scan chegou à fase de IA em ~6 tentativas. O sintoma é sempre o mesmo: para logo depois de `[1/4] Executando ferramentas`, processo `State: R (running)` com 9 threads, sem conexão de rede ativa. Não é o modelo, não é a NIM.

O que já confirmei da fase de IA por outro caminho: `nvidia/nemotron-3-super-120b-a12b` responde tool calling em 1,5 s via curl. `meta/llama-3.3-70b-instruct`, `qwen/qwen2.5-coder-32b-instruct` e `meta/llama-3.1-8b-instruct` estão **fora de linha** (HTTP 410). Dos 15 `:free` do OpenRouter só `nvidia/nemotron-3-super-120b-a12b:free` faz tool calling.

## Chaves

Os valores **não** ficam neste arquivo — a regra do repositório barra
qualquer segredo em commit, e com razão. Na máquina anterior estavam no
keyring do usuário, serviço `smartsec`, com estes nomes de usuário:

```
groq-api-key
openrouter-api-key
nvidia-nim-api-key
llm-api-key           (a ativa; aponta para a chave da NIM)
```

**Na máquina nova o keyring está vazio** e os valores precisam ser pedidos ao
usuário de novo. Ele não tem como recuperá-los deste repositório, por
propósito. Para gravar:

```bash
printf '%s' "$CHAVE" | secret-tool store \
  --label='NVIDIA NIM API key' service smartsec username nvidia-nim-api-key
secret-tool lookup service smartsec username nvidia-nim-api-key   # confere
```

`secret-tool` vem do `libsecret` — na Arch: `pacman -S libsecret`. Sem um
keyring do sistema (D-Bus de sessão) o `secret-tool` falha; nesse caso use a
variável de ambiente que o projeto lê, ou rode num ambiente com sessão
gráfica.

## Reconstituindo o ambiente de teste

Nada disto foi commitado, e tudo precisa ser refeito:

**Configs TOML de teste.** Ficavam em `/tmp`, que é volátil. O conteúdo de
`/tmp/ss-nim.toml`:

```toml
target_url = "http://169.254.1.2:3001"
output_dir = "/tmp/ss-nim-e2e"

[llm]
provider = "NVIDIA NIM"
base_url = "https://integrate.api.nvidia.com/v1"
model = "nvidia/nemotron-3-super-120b-a12b"
remote_consent = true
timeout_secs = 45
```

`provider` aceita minúsculo e variações de separador (`"personalizado"`).

**Alvo de teste.** `/tmp/app-vuln/app.py`, um servidor HTTP na porta 3001 com
SQLi concatenada em `db.execute(...)` e `DB_PASSWORD = "..."` em `db.py`. Não
está no repositório. O endereço `169.254.1.2` é o gateway do host visto de
dentro do container rootless — **o número muda conforme a rede da máquina**;
descubra com `ip route` em vez de assumir.

Para subir de novo: `python3 app.py &` no diretório, e o scan aponta para
`http://<gateway-da-máquina>:3001`.

## Ferramentas

Presentes na máquina anterior, a confirmar na nova:

```
cargo 1.98.1 (Arch Linux, rust 1:1.98.1-1)
podman 6.1.1
```

`podman` é obrigatório — os scanners rodam em container rootless. Sem ele a
varredura não sai.

## Ambiente de execução

Alguns problemas da máquina anterior **não são do projeto** e não valsem na
nova: o servidor reiniciava e matava processos longos a cada ~5 min (por isso
as execuções longas eram lançadas com `setsid --fork nohup ... </dev/null` e
acompanhadas por log), e o `/tmp` às vezes era limpo por outro agente. Se a
máquina nova for estável, ignore isso e rode direto.

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

Os worktrees `.worktrees/audit-ast` e `.worktrees/review-77b` são locais da
máquina anterior e **não vêm no clone** (`.worktrees/` está no
`.git/info/exclude`). Confirmei que nenhum tem trabalho perdido:
`audit-ast` aponta para `afd2d1e`, sem commit próprio, e `review-77b` aponta
para `e36be1d`, que já está em branches no remoto. Se a máquina nova precisar
deles, `git worktree add .worktrees/<nome> <ref>`.