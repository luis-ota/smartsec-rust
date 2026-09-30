# HANDOFF — Sprint 2 · SmartSec

**Data:** 30/09 · **main local:** `14943cb` (PR #81 Nikto mergeado, issue #14 fechada)

Leia isto antes de tocar em qualquer coisa. Tudo abaixo foi verificado em container
real, não é suposição.

---

## 1. Panorama

13 issues da Sprint 2 estavam abertas. Hoje:

| Issue | Situação |
|---|---|
| #14 Nikto | **CONCLUÍDA** — PR #81, mergeada |
| #79 TOML silencioso | **PR #82 aberto**, aguardando merge |
| #28 ZAP | Em investigação, **bloqueio provável** (ver §5) |
| #22 Relatórios PDF | **Bloqueio de escopo, precisa de decisão** (ver §4) |
| #15 #18 #19 #20 #21 #23 #24 #26 #76 | Não iniciadas |
| #27 Protocolo validação | **Não tocar** (ver §3) |
| #68 TUI config inválida | **Não tocar** (ver §3) |

**Concluído: 2. Restam 11 de código.**

---

## 2. O que já está no GitHub (não perder)

```
feat/issue-14-nikto            f4af8f2
fix/issue-79-toml-silencioso   08cc376
```

- **PR #81** — https://github.com/luis-ota/smartsec-rust/pull/81 (mergeado)
- **PR #82** — https://github.com/luis-ota/smartsec-rust/pull/82 (aberto, precisa de merge)

### #14 Nikto — o que foi feito

Manifesto embutido, `ParserKind::NiktoJson` (parser `nikto-json`, `output_format`
`json`) e `src/orchestrator/nikto_parser.rs`. URL, método HTTP, referência (ID Nikto
+ OSVDB) e evidência mínima sanitizada preservados. 229 testes. Evidência real em
`docs/evidence/issue-14-nikto.md`.

**Dois achados que só apareceram executando de verdade** — reutilize esse método nas
próximas ferramentas:

1. O modo JSON do Nikto **exige arquivo de saída**: sem `-o` ele aborta com
   `+ ERROR: Output file format specified without a name`. Resolvido sem shell com
   `-o -`, que faz o próprio scanner escrever no stdout.
2. `-ask no` é **obrigatório**. Sem ele o prompt "submit this information to
   CIRT.net" vaza para o stdout e corrompe o JSON.

Imagem: `docker.io/alpine/nikto:2.2.0@sha256:eb2fe88217ec32695f3843f67c7a7f1628b484b653e99015aac69c586eb2a88b`
versão `2.1.6`. Runner `generic`.

**Decisão de severidade (vale review):** o Nikto não emite campo `severity`. Derivei
da taxonomia de IDs das bases do scanner mais a referência OSVDB, sem interpretar o
texto da mensagem, para manter a severidade do scanner autoritativa como exige o
`TCC_SPEC.md`.

### #79 TOML silencioso — o que foi feito

`load_config_file` engolia qualquer erro de leitura/parsing do `config.toml` global e
devolvia `PersistedConfig::default()`. Um erro de digitação fazia a ferramenta perder
alvo, ferramentas e provedor sem mensagem nenhuma.

Agora: arquivo ausente usa padrões, válido carrega, inválido **falha citando caminho e
causa** em pt-BR. A leitura nunca sobrescreve o arquivo (teste byte a byte). A
assinatura pública foi preservada; `try_load_config_file` expõe o erro para a TUI.
237 testes.

---

## 3. O que NÃO tocar

### #27 — não é código, e está fora de escopo por decisão sua

O plano da Sprint 2 registra explicitamente: *"Fora deste escopo: #27 (protocolo de
validação) e Sprint 3."*

O conteúdo confirma: recrutamento de participantes, consentimento, CEP, questionários
Likert/TAM, agendamento de sessões. Critérios de aceite: "participantes confirmados",
"sessões agendadas", "instruments revisados pela orientação". Prazo 26/10.

Nenhum repositório, teste ou commit fecha isso. Fechar com PR seria marcar como
concluída sem critério de aceite atendido — exatamente o que o `AGENTS.md` proíbe.

### #68 — não é da S2 e tem trabalho de outra pessoa

Sem milestone, worktree ativa em `fix/issue-68-tui-config-invalida`, e existe uma
auditoria não commitada em `.worktrees/review-77b/`. Colidir seria reescrever trabalho
já em andamento por outra frente.

---

## 4. BLOQUEIO #22 — relatório PDF (precisa de decisão do orquestrador)

**Achado:** `export_to_pdf()` em `src/report/generator.rs:100` é um stub que retorna
erro *"a exportação para PDF ainda não foi implementada"*. PDF não existe.

Outros gaps contra os critérios de aceite:

- a análise da IA (`last_log`) **não entra** no relatório Markdown — `generate()`
  recebe só `vulns` + `decisions`;
- não há escape de conteúdo dinâmico;
- não há teste comparando saídas esperadas.

**O bloqueio:** PDF exige dependência nova (`printpdf`/`genpdf`) e a tarefa proíbe
*"sem dependências novas"*. Opções:

| | Opção | Consequência |
|---|---|---|
| **(a)** | Só Markdown + escape + IA no relatório agora; follow-up documentado para o PDF | Entrega 3 de 5 critérios, não inventa arquitetura. **Recomendado** |
| (b) | Autorizar a dependência com licença, versão e impacto justificados no PR | Precisa de decisão explícita |
| (c) | PDF via ferramenta externa (wkhtmltopdf/weasyprint) | Quebra o modelo "sem comandos no host" que o TCC exige |

**Nenhuma alteração foi feita.** Worktree `.worktrees/issue-22` está parada em `e36be1d`
(pré-Nikto) e vazia — precisa de `git pull`/rebase na base antes de usar.

---

## 5. BLOQUEIO #28 ZAP — investigação detalhada

**Estado:** worktree `.worktrees/issue-28`, branch `feat/issue-28-zap` em `14943cb`.
**Sem código escrito** — só scratch em `.zap/` (não versionado).

**Imagem avaliada:**
`ghcr.io/zaproxy/zaproxy:2.14.0`
digest `sha256:aec6c9f65d69570aadec0d15ad0d3a24ffd2c7de5a262436c34e5009c5aa2e66`
Sem ENTRYPOINT (`cmd=["bash"]`), `user=zap`, 2.0 GB.

### O que já foi descoberto (tudo verificado em container)

1. O executor roda com `--read-only` e tmpfs só em `/tmp` e `/root/.config`. O ZAP
   aborta com `The home path is not writable: /home/zap/.ZAP/`. **Precisa de tmpfs
   gravável em `/home/zap`.** É limite do executor, não do ZAP.
2. tmpfs em `/zap` (padrão do ZAP) **não serve**: o selenium tem `15.15.0.zap` e estoura
   o tmpfs (`no space left on device`).
3. **JVM:** o ZAP ignora `JAVA_OPTS` e usa `-Xmx3942m`. Com `--memory 1g` o run morre
   com rc=137 (OOM do host). Funciona com `--memory 1536m`.
4. `-autorun` exige YAML, e o formato só funciona depois de quatro tentativas:
   - o arquivo precisa ser **mapa**, não lista — senão
     `class java.util.ArrayList cannot be cast to LinkedHashMap`;
   - precisa de `env.contexts` com `urls`/`includePaths` — senão `No contexts defined`;
   - `authentication.method` **quebra** com `Invalid authentication method` —
     **omitar o bloco**;
   - o parâmetro `template` do `outputSummary` **não é reconhecido** nesta versão.

### Configuração que FUNCIONA

```bash
podman run --rm -i \
  --network "pasta:--map-host-loopback=169.254.1.2" \
  --memory 1536m --cpus 1 --pids-limit 256 \
  --cap-drop all --security-opt no-new-privileges --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --tmpfs /home/zap:rw,nosuid,nodev,size=512m \
  -v "$PWD/.zap/automation":/home/zap/automation:ro \
  ghcr.io/zaproxy/zaproxy@sha256:aec6c9f65d69570aadec0d15ad0d3a24ffd2c7de5a262436c34e5009c5aa2e66 \
  zap.sh -cmd -autorun /home/zap/automation/scan.yaml
```

`scan.yaml`:

```yaml
env:
  contexts:
    - name: default
      urls:
        - http://169.254.1.2:3000
      includePaths:
        - .*
      excludePaths: []
  vars: {}
jobs:
  - type: spider
    parameters:
      context: default
      user: ""
  - type: outputSummary
    parameters:
      summaryFile: /tmp/zap-report.json
```

**Saída real dessa configuração:**

```
Job spider requesting URL http://169.254.1.2:3000
Job spider found 3 URLs
Job spider finished, time taken: 00:00:01
Job outputSummary started
Job outputSummary finished, time taken: 00:00:00
Automation plan succeeded!
```

### Onde travar

`outputSummary` exige `summaryFile` e **escreve em arquivo**. Não há JSON no stdout.
Tentei `/home/zap/reports` com volume → `no write access` (o `user=zap` não enxerga o
volume por UID). Escreve bem em `/tmp` (tmpfs), **mas o executor só captura stdout**.

### Próximos passos possíveis

1. Verificar se existe job/API do ZAP que emita JSON no stdout.
2. Estender o executor para copiar `/tmp/zap-report.json` para o stdout ao final —
   **isso é mudança no sandbox, escopo de outra issue**.
3. **Parar e reportar** que o ZAP não cabe no executor read-only atual sem mudar o
   sandbox.

**Não use volume para contornar**: viola o TCC (sem mounts fora do tmpfs, sem
privilégios).

---

## 6. Ordem sugerida para continuar

Considerando o padrão já estabelecido pela #14 (manifesto + parser + fixtures + teste
de integração com fake podman) e a dependência de todas da arquitetura da #17:

1. **#28 ZAP** ou **#15 SQLMap** ou **#18 TruffleHog** — três integrações de ferramenta,
   mesma arquitetura. A #28 tem a investigação pronta.
2. **#20 #21 #23 #24** — parecem **parcialmente feitas** (já existem `execute_tool`,
   `paused`/`cancelled`, `analyze_logs`, `save_scan_log`). Audite o que falta contra
   os critérios de aceite antes de codificar.
3. **#19** correlação/dedup/CVE — depende de ter os parsers prontos.
4. **#26** GitHub Actions e **#76** code-agent — independentes.
5. **#22** — só depois da decisão (§4).

---

## 7. Infraestrutura (aprendi na dor, economiza tempo)

**Lock de build** (dentro do repo, sem prompt de permissão):

```bash
flock /home/luis/dev/bobera/tcc/smartsec-rust/.git/smartsec-build.lock -c 'cargo test -j 1'
```

### OOM — o problema nº 1 desta máquina

`cargo` com `-j 2` é **morto pelo kernel** (signal 9) durante o link e durante o
clippy. A máquina tem 15 Gi com ~3.6 GiB livres. **Use `-j 1` para clippy e testes.**
`cargo fmt --check` não problematiza.

```bash
# pode falhar com OOM:
cargo clippy --all-targets -- -D warnings
# funciona:
cargo clippy --all-targets -j 1 -- -D warnings
```

### Outros pontos

- **Artefatos temporários dentro do worktree** — não usar `/tmp` para arquivos de
  trabalho do projeto.
- **Disco em 97%** (9 GB livres). Imagens de teste grandes precisam ser removidas
  depois: `podman rmi -f <img>`.
- **Servidor de alvo local** — sem `setsid` o processo morre entre comandos:

  ```bash
  mkdir -p /tmp/smartsec-www
  printf '<html><body><h1>Alvo de teste SmartSec</h1></body></html>\n' > /tmp/smartsec-www/index.html
  setsid --fork python3 -m http.server 3000 --bind 127.0.0.1 --directory /tmp/smartsec-www \
    >/tmp/httpd.log 2>&1 < /dev/null
  ```

  O alvo dentro do container é `http://169.254.1.2:3000` (mapeamento `pasta`).
- **Push ao GitHub sempre** — só conta como salvo o que está no remote.
- **Não** use `CARGO_TARGET_DIR` compartilhado entre worktrees: o cargo reutiliza
  binários de outros checkouts e os testes passam a rodar código errado.

---

## 8. Como registrar o progresso ao encerrar uma fatia

Ao terminar uma fatia, registre na issue e no PR:

- issue, branch, URL do PR;
- saída de `fmt` / `clippy` / `test`;
- evidência real (comando + trecho sanitizado);
- bloqueios.

Padrão usado nas issues anteriores: resultado objetivo, achados que só apareceram em
execução real destacados, e decisões que precisam de review explicitadas.
