# Handoff — smartsec-rust, estado pós-v0.2.2 (sessão de 15–16/10/2026)

Sessão encerrada com **tudo mergeado**: zero PRs abertos, `main` em `99c19b7`,
release **v0.2.2 publicada e instalada**. CI/CD está **desligado de propósito**
(cota de Actions). Este documento é para a próxima IA: leia inteiro antes de
editar, valide o estado ponta a ponta e proponha melhorias com evidência.

Leitura obrigatória antes de mexer: `AGENTS.md`, `TCC_SPEC.md`,
`docs/CONFIGURACAO.md`, `docs/cyberrag.md`, `docs/INSTALACAO.md`.
(`docs/PROMPT-CONTINUACAO.md` está **desatualizado** — descreve a branch antiga
`feat/auditoria-codigo-ia`; ignore-o.)

## 1. Onde o trabalho está

- Máquina **`luis-arch`** (Tailscale `100.85.152.39`, `ssh luis-arch`), repo em
  `~/dev/tcc/smartsec-rust`, working tree limpo na `main`.
- `main` = `99c19b7` (merge do #125). Tags publicadas: `v0.2.0`, `v0.2.1`,
  `v0.2.2`.
- Binário instalado: `~/.local/bin/smartsec` → **`smartsec 0.2.2`** (instalador
  `curl | sh` conferiu checksum e templates). É o que o usuário roda.
- Zero PRs abertos. Issues abertas: **#27** (S2, protocolo de validação),
  **#29–#34** (Sprint 3), **#104** (SQLi sobre o parser Python), **#108** (o
  agente de código cita ponto que não é o do achado).
- CI/CD **desligado**: `SmartSec CI` e `SmartSec Release` estão
  `disabled_manually` (cota de Actions ~90% usada; reseta **01/11/2026**).
  Reative só pelo tempo de um run de release (ver §6). O workflow "Copilot" só
  desabilita em Settings → Copilot.

## 2. O que foi feito nesta sessão (tudo mergeado)

- **#105** — correção do tool calling da IA (A1–A3): com a NIM o modelo não
  chamava ferramenta nenhuma; a correção força `tool_choice:"required"` até a
  1ª ferramenta, com nudge (teto 2) e prompt endurecido. CI verde, E2E real
  3/3 runs.
- **#106** — limpeza cirúrgica de comentários em `src/` (regra das 2 linhas).
- **#107** — micro-fix: fase duplicada no headless + typo.
- **#110/#111/#112** — **CyberRAG** (Tarefa B): corpus + BM25 + ontologia;
  serviço com embeddings + trilha/`ScanMetadata`; botão **"Explicar (IA)"** no
  detalhe do achado. Validação **simbólica determinística** (não é o juiz-LLM
  do artigo), sob demanda. Créditos em `docs/cyberrag.md`. E2E com NIM: 2/3
  aprovados + 1 recusa honesta por timeout.
- **#113/#115** — **instalador `curl | sh`**: bootstrap `install.sh` publicado
  como asset; `reqwest` com rustls (binário sem libssl); runners `ubuntu-22.04`
  (x86_64) e `ubuntu-22.04-arm` (aarch64 nativo, glibc 2.35).
- **#114** — navegação de configuração na TUI.
- **#116** — desempenho dos hot paths.
- **#117** — **fix do OOM** da execução: tetos de captura no sandbox (2 MB por
  stream, linha sem terminador fechada no teto, `\r` como terminador, 5.000
  linhas de trace, 64 KB de log por ferramenta) + parser do Nuclei tolerante a
  ruído não-JSON + mensagem clara quando os templates não são um clone git.
- **#118** — hover do mouse em botões/linhas/campos.
- **#119** — pré-seleção de ferramentas por perfil do projeto, com motivo por
  linha.
- **#120** — painel **"Atividade da IA"** na Execução (linha do tempo ao vivo;
  tecla `i`).
- **#121** — guarda de versão no workflow de release (binário × tag iguais).
- **#122** — **"Configurar IA"** redesenhada: grupos, ajuda do campo em foco,
  exemplos em cinza, resumo "Se salvar: ...".
- **#123** — **fix do teto de linha**: o teto de 16 KB cortava o JSON do Nikto
  (21 KB numa linha única) e a ferramenta falhava; o teto da linha agora é o do
  stream (2 MB). Prova: Nikto `OK`, 21.592 bytes, **169 achados** no Juice Shop.
- **#124** — **versões mais recentes** (digests re-verificados por pull real):
  Nmap **7.98** (+ pin por digest), Nuclei **v3.11.1**, TruffleHog **3.99.2**,
  ZAP **2.16.0**. Nikto e SQLMap mantidos (sem versão mais nova empacotada).
  Pin dos templates do Nuclei mantido (`b98e6097...`).
- **#125** — bump para **0.2.2** e release: guarda de versão passou, 5 assets
  publicados (`install.sh`, `SHA256SUMS`, 2 tar.gz, .deb), run de ~8 min.

## 3. Estado validado

- **760 testes** `cargo test --bin smartsec` (2 ignorados) na main — última
  medição. Suítes de integração (30 testes): `headless_signals`,
  `headless_exit_codes`, `history_cli`, `code_agent_integration`, `report_cli`.
- `cargo fmt --check` e `cargo clippy --all-targets -D warnings` limpos na
  última rodada completa.
- Releases vivas: `v0.2.0`, `v0.2.1`, `v0.2.2` (5 assets cada). One-liner para
  amigos: `curl -fsSL https://github.com/luis-ota/smartsec-rust/releases/latest/download/install.sh | sh`.
- Evidências visuais da TUI em `docs/evidence/tui-*` (PNGs das telas novas).

## 4. Ambiente de validação já montado (não commitado)

**Alvo demo.** OWASP Juice Shop no podman, container `juice-shop` (host:
`http://127.0.0.1:3000`). Os scanners rodam em container rootless e alcançam o
host por **`http://169.254.1.2:3000`** (link-local do gateway). Fonte em
`~/dev/juice-shop`. Após reboot: `podman start juice-shop`.

**Config global** `~/.config/smartsec/config.toml` (backup `.bak` ao lado):

```toml
target_url = "http://169.254.1.2:3000"
project_dir = "/home/luis/dev/juice-shop"
active_tools = ["Nmap", "Nuclei", "Nikto"]
provider = "NvidiaNim"
model = "nvidia/nemotron-3-super-120b-a12b"
remote_consent = true
```

Para ver os **motivos da pré-seleção** de ferramentas na TUI, `active_tools`
precisa estar **vazio** (lista explícita desliga a recomendação).

**Templates do Nuclei.** `~/nuclei-templates` é um **clone git** no commit
pinado `b98e6097cb84e73e7a480436062d685a8f898824` — precisa ser clone (o
SmartSec valida); zip não serve. Backup do antigo:
`~/nuclei-templates.zip-bak-20261015`.

**TOMLs de teste** em `/tmp` (recriar se o /tmp for limpo): `ss-demo.toml`,
`ss-nim.toml`, `ss-sem-ia.toml`, `ss-nuclei.toml`, `ss-nikto.toml`.

**Keyring.** Segredos no `Default_keyring` (não `login.keyring`), com a chave
ativa em `service smartsec username llm-api-key`. **Na última verificação
estava travado** (o `secret-tool lookup` ficou pendurado aguardando o diálogo
do gcr) — sem destravar, a IA fica determinística (não é bug do SmartSec).
Destravar: rodar num terminal **gráfico**

```bash
secret-tool lookup service smartsec username llm-api-key   # dispara o diálogo do gcr
```

PAM/lightdm só destrava o login keyring; logout de verdade:
`loginctl terminate-session "$XDG_SESSION_ID"`.

## 5. Roteiro de validação ponta a ponta

0. **Preflight**: `podman ps | grep juice-shop` (senão `podman start
   juice-shop`); destravar o keyring (acima) se for validar IA.

1. **Build e testes** (máquina tem 7,9 GB de RAM — sempre serializado):

```bash
flock .git/smartsec-build.lock -c 'cargo build -j 1 --release'
cargo fmt --check
flock .git/smartsec-build.lock -c 'cargo clippy --all-targets -j 1 -- -D warnings'
flock .git/smartsec-build.lock -c 'cargo test -j 1 --bin smartsec'
flock .git/smartsec-build.lock -c 'cargo test -j 1 --test headless_signals --test headless_exit_codes --test history_cli --test code_agent_integration --test report_cli'
```

2. **Headless contra o demo** (esperado: relatório em `/tmp/ss-demo-saida`):

```bash
smartsec scan --target http://169.254.1.2:3000 --config /tmp/ss-demo.toml --output-dir /tmp/ss-demo-saida
# prova do fix do teto de linha (esperado: OK, ~21,5 KB, ~169 achados):
smartsec tool Nikto --target http://169.254.1.2:3000 --config /tmp/ss-nikto.toml
smartsec history           # lista execuções
smartsec trace <SCAN_ID>   # ações da IA na execução
```

3. **TUI** (`smartsec` sem argumentos). Checklist:
   - **Configurar IA**: grupos, ajuda do campo em foco, exemplos em cinza,
     linha "Se salvar: ..." (`chave salva` quando o keyring estiver destravado);
   - **Ferramentas**: motivo da pré-seleção por linha (com `active_tools = []`);
   - **Hover**: botões, linhas e campos acendem com o mouse;
   - **Execução**: tecla `i` (ou clique no bloco de IA) abre o painel
     **Atividade da IA** ao vivo; `esc` fecha;
   - **Nikto/ZAP rodando os ~2 min** sem estourar a memória (antes o OOM matava
     a TUI com 9,6 GB); Nuclei conclui com achados;
   - **"Explicar (IA)"** no detalhe de um achado (RAG + ontologia; precisa de
     keyring destravado + consentimento, ambos configurados).

4. **Instalador** (quando quiser provar o fluxo de fábrica):

```bash
curl -fsSL https://github.com/luis-ota/smartsec-rust/releases/latest/download/install.sh | sh
smartsec --version   # esperado: smartsec 0.2.2
```

## 6. Como publicar uma release (só quando necessário)

Cada run custa ~8 min de Actions — com a cota a ~90%, reative o workflow só
pelo run e desligue depois. A **guarda de versão** exige binário == tag:

```bash
# 1) PR de bump (Cargo.toml + Cargo.lock; cargo check sincroniza o lock) → merge
gh workflow enable "SmartSec Release"
git fetch origin main && git tag v0.2.3 <merge-sha> && git push origin v0.2.3
# 2) aguardar ~8 min (x86_64 + aarch64 em paralelo; a guarda confere a versão)
gh run list --workflow "SmartSec Release" --limit 1
gh release view v0.2.3          # 5 assets esperados
gh workflow disable "SmartSec Release"
# 3) atualizar a máquina:
curl -fsSL https://github.com/luis-ota/smartsec-rust/releases/latest/download/install.sh | sh
```

## 7. Pendências e follow-ups

- **Keyring travado** bloqueia a validação da IA (ação do usuário, §4).
- **Feature pedida e NÃO iniciada**: expandir as ocorrências detalhadas
  (`run_issues`) e **copiar textos** (logs, evidências, explicações) para o
  clipboard.
- **NVD, opção (a)** (proposta, sem decisão): esperar só em cache miss —
  medição: 10 CVEs levaram 54 s; com cache quente, ~0,02 s.
- **Candidatos a issue**: `smartsec.example.toml` cita
  `docker.io/zaproxy/zap:2.14.0` (404 hoje — atualizar para 2.16.0); SQLMap
  upstream 1.10.10 sem imagem oficial; aviso de deprecação do Node 20 nas
  actions de artefato; `docs/PROMPT-CONTINUACAO.md` desatualizado.
- **#108**: localização errada citada pelo agente de código (follow-up).
- **Worktrees** em `.worktrees/` (config-ia, hover-mouse, ia-log,
  limpeza-comentarios, perf-upgrade, tool-preselect, tui-upgrade, versoes):
  trabalho 100% mergeado; podem ser removidos com `git worktree remove`.

## 8. Regras e armadilhas que mais quebram

- `AGENTS.md` manda; issue primeiro, branch por tarefa (`feat/issue-N-...`),
  PR com `Closes #N`, nunca push na `main`.
- **Comentário: no máximo 2 linhas, só o *por que* não óbvio.** Comportamento
  verificável vira teste, não comentário.
- **NUNCA** `cargo test` sem `--bin smartsec` (a suíte de integração completa
  executa o binário real e trava a máquina). Sempre `flock
  .git/smartsec-build.lock` e `-j 1` (máquina de 7,9 GB).
- `pkill -f <padrão>` mata o próprio shell se o padrão casar a própria linha —
  use classe de caractere (`ss-prox[y]`) ou mate por PID.
- Segredos nunca em commit/log/relatório; mascarar achados do TruffleHog; não
  enviar logs para LLM remoto sem consentimento.
- Strings de interface/log/relatório em **pt-BR**; identificadores de código em
  inglês. Dados demo/mock só opt-in e rotulados.
- Subagentes: não rodar dois no mesmo worktree; sessões órfãs duplicadas já
  aconteceram — cancele as repetidas antes de relançar.

## 9. Como propor melhorias

- Mudança fora do escopo da issue: **abra issue antes** de codar; não misture
  refatoração/estilo com feature.
- Todo PR com testes (incluindo erros, timeout, cancelamento e entrada
  inválida quando aplicável) e **evidência reproduzível** no corpo (comandos +
  resultado) para mudanças de TUI/CLI/pipeline/relatório.
- Se mudar contrato público (findings, CLI, config, exit codes, logs),
  atualize `TCC_SPEC.md`, testes e a matriz de rastreabilidade no mesmo PR.
- Issues de validação preservam dados brutos e distinguem antes/depois.
- Não feche issue com workaround sem abrir follow-up.
