# Handoff — smartsec-rust, PR #105

Branch `feat/auditoria-codigo-ia` → `main`. Tudo commitado e pushed. PR #105 aberto e MERGEABLE.

## Onde o trabalho está

Rodando na máquina **`luis-arch`** (Tailscale, `100.85.152.39`), acessível da
máquina de origem por `ssh luis-arch` com chave — sem senha. O repositório
local de lá é `~/dev/tcc/smartsec-rust` (sem o `bobera` no caminho), na branch
`feat/auditoria-codigo-ia`, em `1b28f3d`.

Para retomar de lá:

```bash
ssh luis-arch
cd ~/dev/tcc/smartsec-rust
```

A máquina de origem é `/home/luis/dev/bobera/tcc/smartsec-rust`; os dois
cópios estão na mesma branch e no mesmo commit, então qualquer um serve.

O que já está pronto lá: chaves no keyring (NIM gravada e lida com sucesso),
`cargo 1.97.1`, `podman 6.1.3`, `secret-tool`, alvo de teste em
`~/dev/app-vuln` rodando na porta 3001, TOML em `/tmp/ss-nim.toml` e
`/tmp/ss-sem-ia.toml`, e os 640 testes unitários verdes.

O caminho do repositório e o IP do alvo são **daquela máquina**. Numa terceira
máquina, `git clone` e refaça o alvo.

## Regras do projeto (leia antes de editar)

`AGENTS.md` na raiz. As duas que mais quebram:

- **Comentário: no máximo 2 linhas, só para o *por que* não óbvio.** O usuário reclamou duas vezes nesta sessão por comentários enormes. Comentário que repete o código é ruído. Se um comportamento é verificável, escreve teste, não comentário.
- **Nenhum teste toca `~/.config/smartsec/`, keyring real ou rede real.** Já causou 2 incidentes. Para testar log/trilha, use `orchestrator.scan_metadata()` (monta o `ScanMetadata` sem gravar) ou um `temp_dir()` próprio.

## Estado atual

640 testes unitários verdes, `cargo fmt --check` limpo, `cargo clippy
--all-targets -D warnings` com 0 avisos — **validado nas duas máquinas**.

Commits (do mais recente para o mais antigo):
- `1b28f3d` — handoff apontando para `luis-arch` e o ambiente montado lá
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

**Na `luis-arch` a chave da NIM já está gravada** e foi lida com sucesso de lá.
Groq e OpenRouter **não** — se forem necessárias, peça os valores ao usuário.
Numa máquina nova os valores precisam ser pedidos de novo: não há como
recuperá-los deste repositório, por propósito. Para gravar:

```bash
printf '%s' "$CHAVE" | secret-tool store \
  --label='NVIDIA NIM API key' service smartsec username nvidia-nim-api-key
secret-tool lookup service smartsec username nvidia-nim-api-key   # confere
```

`secret-tool` vem do `libsecret` — na Arch: `pacman -S libsecret`. Sem um
keyring do sistema (D-Bus de sessão) o `secret-tool` falha; nesse caso use a
variável de ambiente que o projeto lê, ou rode num ambiente com sessão
gráfica.

## Ambiente de teste

Está montado em `luis-arch`, não commitado:

**Alvo.** `~/dev/app-vuln/` com `app.py` (HTTP na 3001, SQLi concatenada em
`db.execute(...)`) e `db.py` (`DB_PASSWORD = "Sup3rS3nh4!"`). Para subir:
`cd ~/dev/app-vuln && setsid --fork python3 app.py </dev/null`.

O endereço na config é `http://192.168.1.58:3001` — o IP da máquina na LAN,
**não** o gateway. Scanear exige que o container rootless alcance o host, e o
caminho muda conforme a rede. Numa máquina nova descubra com `ip -4 addr`.

Na máquina de origem o mesmo alvo usava `169.254.1.2`, que é um endereço de
link-local. A diferença é a prova de que o número não pode ser assumido de uma
máquina para outra.

**TOML.** `/tmp/ss-nim.toml` (NIM com `remote_consent = true`) e
`/tmp/ss-sem-ia.toml` (mesmo alvo, provedor vazio — para provar que o scan
funciona sem IA). `provider` aceita minúsculo e variações de separador
(`"personalizado"`).

**Ferramentas** em `luis-arch`: `cargo 1.97.1`, `podman 6.1.3`, `secret-tool`.
`podman` é obrigatório — os scanners rodam em container rootless.

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