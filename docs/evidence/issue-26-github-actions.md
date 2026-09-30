# Evidencia da integracao com o GitHub Actions — issue #26

Data da execucao local: 30/09/2026.
Branch: `feat/issue-26-github-actions`, derivada da `main` no commit `14943cb`.
Plataforma da validacao: Arch Linux, `rustc 1.98.1`, Podman 6.1.1 rootless,
8 vCPU, 15 GiB de RAM.

> **O que esta evidencia NAO prova.** O workflow **nao foi executado no GitHub
> Actions** no momento em que esta evidencia foi escrita. Tudo abaixo foi
> verificado localmente, executando os mesmos scripts de shell que o YAML
> invoca e o mesmo binário que o job compila. A secao "O que ainda precisa de
> verificacao no primeiro run" lista o que so o runner hospedado pode
> confirmar.

---

## 1. Escopo

Arquivos alterados, todos dentro do escopo acordado da issue:

| Arquivo | Natureza |
|---|---|
| `.github/workflows/ci.yml` | novo — pipeline de CI |
| `README.md` | secao "GitHub Actions" |
| `docs/evidence/issue-26-github-actions.md` | este arquivo |

Nenhum arquivo de `src/` foi tocado. A issue nao alterou a CLI, os exit codes,
o formato do relatorio nem o layout do log estruturado, portanto nao houve
mudanca de contrato publico a propagar para `TCC_SPEC.md`.

---

## 2. O contrato do CLI, lido do codigo

Fonte: `src/main.rs:99-162` (parse) e `src/main.rs:387-398`
(`headless_exit_code`).

Comandos: `scan` e `tool <FERRAMENTA>`. Sem subcomando, o binario abre a TUI.
Opcoes aceitas: `--target`/`-t` (obrigatoria), `--config`, `--tools`, `--llm`,
`--model`, `--output`/`-o`, `--output-dir`, `--help`/`-h`, `--version`/`-V`.
Qualquer outro token produz erro — o parseador nao ignora argumento
desconhecido (`src/main.rs:147-149`).

### Saida literal do `--help`

```console
$ ./target/debug/smartsec-rust --help
SmartSec - Plataforma de análise de segurança
Uso: smartsec <scan|tool> --target <ALVO> [OPÇÕES]

Comandos:
  scan              Executa uma varredura não interativa.
  tool <FERRAMENTA> Executa manualmente uma ferramenta.

Opções:
  -t, --target <ALVO>  IP, domínio ou URL
      --config <ARQUIVO>  Configuração TOML
      --tools <LISTA>  Ferramentas reais separadas por vírgulas
      --llm <PROVEDOR>  ollama, openai, nvidia-nim ou custom
      --model <MODELO>  Modelo da IA
  -o, --output <ARQUIVO>  Relatório Markdown (padrão: smartsec-report.md)
      --output-dir <DIRETORIO>  Diretório de saída do relatório
  -h, --help
  -V, --version

Códigos de saída:
  0  nenhuma vulnerabilidade crítica
  1  vulnerabilidade crítica encontrada
  2  erro de configuração ou de execução
$ echo $?
0
```

### Exit codes, com a precedencia confirmada por execucao

`headless_exit_code` da precedencia a falha de execucao: se qualquer execucao de
ferramenta tem `execution_error`, o resultado e `2`, mesmo havendo achado
critico. O teste `classifies_headless_exit_codes` em `src/main.rs:562-585`
afirma isso, e a execucao real abaixo confirma.

```console
$ ./target/debug/smartsec-rust scan --target http://127.0.0.1:1 --foo bar
Erro: argumento desconhecido: --foo; use --help para ver as opções
$ echo $?
2

$ ./target/debug/smartsec-rust scan --target http://127.0.0.1:1 --tools Inexistente
Erro: ferramenta desconhecida: Inexistente
$ echo $?
2

$ ./target/debug/smartsec-rust scan --target "alvo inválido"
Erro: o alvo não pode estar vazio nem conter espaços
$ echo $?
2

$ ./target/debug/smartsec-rust scan
Erro: o argumento --target é obrigatório
$ echo $?
2

$ ./target/debug/smartsec-rust inventado --target http://127.0.0.1:1
Erro: comando desconhecido: inventado; use --help para ver as opções
$ echo $?
2
```

Erro de execucao de scanner, com Podman indisponivel (simulado por um `podman`
que sai com 125 no `PATH`):

```console
$ env PATH="$FAKE:$PATH" ./target/debug/smartsec-rust scan \
    --target http://169.254.1.2:38177 --tools Nmap --llm ollama \
    --output relatorio-falha.md --output-dir "$SAIDA_FALHA"
...
═══════════════════════════════════════════════════════════
  OK Relatório exportado: /tmp/.../saida-falha/relatorio-falha.md
  OK Log estruturado: /tmp/.../config/smartsec/scans/scan_1790795674363082563.json
  FALHA Varredura concluída com erros: Não foi possível iniciar a varredura real
  de Nmap: Podman está instalado, mas indisponível: ...
═══════════════════════════════════════════════════════════
$ echo $?
2
```

**Achado que so apareceu em execucao real:** o relatorio e o log estruturado sao
gravados mesmo com `2`. E por isso que o passo de publicacao de artefatos do
workflow usa `if: always()`: se a publicacao dependesse do passo da varredura
terminar com sucesso, a evidencia de uma varredura com falha de scanner
sumiria do CI.

### O destino do relatorio e do log estruturado

- `--output-dir` controla **apenas o relatorio Markdown** (`resolve_report_path`,
  `src/main.rs:401-424`, que cria o diretorio se preciso).
- O log estruturado JSON **nao** obedece ao `--output-dir`.
  `scan_logger::save_scan_log` (`src/orchestrator/scan_logger.rs:196-215`) grava
  sempre em `scans_dir()`, que e
  `dirs::config_dir()/smartsec/scans` — ou seja,
  `$XDG_CONFIG_HOME/smartsec/scans/`. **Nao existe flag no CLI para mudar esse
  destino.**

Consequencia pratica: o job exporta `XDG_CONFIG_HOME="$RUNNER_TEMP/xdg"` para
coletar o JSON sem tocar em `src/`. Verificacao local:

```console
$ ls /tmp/.../runner/artefatos/relatorio.md
/tmp/.../runner/artefatos/relatorio.md
$ ls /tmp/.../runner/xdg/smartsec/scans/
scan_1790795936556200705.json
```

Esse acoplamento e uma decisao de design do SmartSec que a issue #25 nao
cobriu; esta registrada aqui como observacao para a issue, nao como bloqueio
desta issue (o job contorna por `XDG_CONFIG_HOME`).

---

## 3. Alvo autorizado: nenhum alvo externo

O TCC proibe rodar scanners no host. O job `varredura` reproduz o mesmo desenho
do `scripts/e2e_tui_local.sh` ja homologado na issue #53:

1. `python3 -m http.server $SMARTSEC_ALVO_PORTA --bind 127.0.0.1` sobe no
   proprio runner;
2. o alvo passado ao SmartSec e `http://169.254.1.2:38177`, que e o endereco
   que `--network pasta:--map-host-loopback=169.254.1.2`
   (`src/orchestrator/sandbox.rs:12`) mapeia para o loopback do host;
3. o servidor HTTP nao esta exposto na rede do runner.

Execucao real do passo *Publicar o alvo autorizado controlado*, extraido do YAML
e executado como bash:

```console
$ bash target-step.sh
Alvo autorizado no ar em 127.0.0.1:38177
$ echo $?
0
$ cat $RUNNER_TEMP/alvo/index.html
<!doctype html>
<html lang="pt-BR">
<head><meta charset="utf-8"><title>Alvo autorizado do CI</title></head>
<body><h1>SmartSec</h1><p>Fixture local usada pelo GitHub Actions.</p></body>
</html>
```

### Scan headless real, executando o script do passo do CI

O script do passo *Executar a varredura headless* foi extraido do YAML e
executado sem alteracao, com `SMARTSEC_ALVO_PORTA=38177`,
`SMARTSEC_FERRAMENTAS=Nmap`, `SMARTSEC_PROVEDOR_IA=ollama`:

```console
$ bash scan-step.sh
$ echo $?          # rc do passo, com continue-on-error
0
$ cat $GITHUB_OUTPUT
exit_code=0
$ ls $RUNNER_TEMP/artefatos $RUNNER_TEMP/xdg/smartsec/scans $RUNNER_TEMP/smartsec.log
relatorio.md
scan_1790795936556200705.json
smartsec.log
```

Trecho da saida real do SmartSec (o `podman create` aparece no trace, com a rede
pasta e os limites do sandbox):

```text
  Alvo:   http://169.254.1.2:38177
  Modo:   Automático
  Dados:  REAL
  LLM:    Ollama (llama3.2:1b)
  Scanners: Podman sem privilégios de root

[1/3] Executando ferramentas de segurança...
  [ 1/ 1] Nmap
  │ [19:18:48] $ podman create --name smartsec-... --network pasta:--map-host-loopback=169.254.1.2 --memory 512m --cpus 1 --pids-limit 256 --cap-drop all --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m docker.io/instrumentisto/nmap:7.95 -Pn -sT -sV -oX - -p 38177 169.254.1.2
  │ [19:18:54] <port protocol="tcp" portid="38177"><state state="open" .../><service name="http" product="SimpleHTTPServer" version="0.6" .../></port>
  OK (2026-09-30T19:18:48Z, 1379 bytes de saída)

[3/3] Resumo
  Total de achados: 1
  CRÍTICAS: 0   ALTAS: 0   MÉDIAS: 0   BAIXAS: 0   INFORMATIVAS: 1
```

### Condicao do runner sem IA: fallback determinístico

Na maquina de desenvolvimento ha Ollama rodando, o que nao e a condicao do
runner. Para reproduzir a condicao do CI, o `base_url` do TOML apontou para uma
porta loopback fechada (`http://127.0.0.1:11435/v1`). O agente caiu no fallback
local e o exit code nao mudou:

```console
$ XDG_CONFIG_HOME=... DBUS_SESSION_BUS_ADDRESS='disabled:' \
  ./target/debug/smartsec-rust scan --target http://169.254.1.2:38177 \
  --config ci-local.toml --output relatorio.md --output-dir artefatos3
[2/3] Análise da IA (1 achados):
  │ Análise concluída: 1 achados (0 críticos, 0 altos, 0 médios, 0 baixos e 1 informativos).
  │ Os achados são informativos; valide a exposição e aplique hardening quando pertinente.
$ echo $?
0
```

`DBUS_SESSION_BUS_ADDRESS='disabled:'` e usado no workflow para impedir
autolaunch de D-Bus: o binario tenta ler a chave no Secret Service
(`crate::config::persistence::load_api_key`) e, sem sessao D-Bus, a falha e
ignorada por `if let Ok(key)`. Verificado localmente que `--help` e o scan
continuam funcionando com essa variavel.

**Achado que so apareceu em execucao real:** `--llm <provedor>` sobrescreve
sempre o `base_url` do TOML pelo padrao do provedor
(`src/main.rs:464-471`, `config.llm.base_url = kind.default_base_url()`). Com
`--llm ollama`, um `base_url` customizado e descartado. Por isso o passo do CI
usa `--llm ollama` explicitamente para nao depender de TOML nenhum.

### Smoke test do Podman e da rede pasta

O passo *Verificar o Podman rootless e a rede pasta* foi reproduzido localmente
com os mesmos comandos:

```console
$ podman --version
podman version 6.1.1
$ podman info --format '{{.Host.Security.Rootless}}'
true
$ podman run --rm --network 'pasta:--map-host-loopback=169.254.1.2' \
    docker.io/instrumentisto/nmap:7.95 -V
Nmap version 7.95 ( https://nmap.org )
Platform: x86_64-unknown-linux-gnu
RC=0
```

O `Podman rootless confirmado.` e o smoke test com `-V` validam, antes da
varredura, exatamente as duas condicoes que o TCC exige: Podman rootless e a
rede `pasta` com o mapeamento do loopback do host.

---

## 4. A decisao de exit code

Mapeamento implementado no passo *Aplicar o veredito do exit code*:

| Exit code | Veredito | Job | Justificativa |
|---:|---|---|---|
| `0` | `ok` | verde | a varredura rodou e nao achou nada critico |
| `1` | `critico` | **verde** com `::warning::` | achado critico e resultado valido da varredura, nao defeito do pipeline |
| `2` | `erro` | vermelho | a varredura e inconfiavel; o resultado nao pode ser aproveitado |
| outro | `inesperado` | vermelho | panic, OOM killer ou sinal nao podem ser lidos como sucesso |

Argumentos, todos verificaveis no codigo:

1. O `TCC_SPEC.md` secao 10 e explicito: "Finding critico nao e erro interno:
   deve retornar `1` e preservar o relatorio" e "Erro de scanner nao pode ser
   convertido em sucesso". O proprio contrato do projeto separa os dois casos, e
   o CI precisa respeitar essa separacao.
2. O alvo do CI e uma fixture local servida pelo proprio runner. Com
   `--tools Nmap` ela so produz achados **informativos** — o proprio passo de
   contrato da CLI registra isso. Falhar o merge por um achado sobre um alvo que
   ninguem autorizou a corrigir seria um falso positivo no gate.
3. Tratar "qualquer nao-zero falha" seria errado nos dois sentidos: esconderia o
   `1` atras do `2` (a falha de execucao tem precedencia no codigo) e deixaria
   um `137` de OOM killer passar como sucesso.
4. O modo bloqueante existe e e uma variavel, nao um patch: a variavel de
   repositorio `SMARTSEC_BLOQUEIA_CRITICO=true` faz o `1` falhar o job. E o que
   se deve usar quando o alvo do CI for uma aplicacao autorizada, e nao uma
   fixture.

### Simulacao do veredito

O script do veredito foi extraido do YAML e executado com todos os exit codes
relevantes e nas duas politicas:

```console
exit=0    bloqueia=nao   -> rc=0 veredito=ok
exit=0    bloqueia=true  -> rc=0 veredito=ok
exit=1    bloqueia=nao   -> rc=0 veredito=critico
exit=1    bloqueia=true  -> rc=1 veredito=critico
exit=2    bloqueia=nao   -> rc=1 veredito=erro
exit=2    bloqueia=true  -> rc=1 veredito=erro
exit=101  bloqueia=nao   -> rc=1 veredito=inesperado
exit=101  bloqueia=true  -> rc=1 veredito=inesperado
exit=137  bloqueia=nao   -> rc=1 veredito=inesperado
exit=137  bloqueia=true  -> rc=1 veredito=inesperado
```

### Pratica comum comparada

A pratica dominante em scanners no GitHub Actions combina as duas metades:

- o **scan roda com `continue-on-error`** (ou `exit-code` do proprio scanner),
  para que o passo de upload rode mesmo com o gate vermelho — e e exatamente o
  que o Trivy faz ao separar o passo de scan do upload de SARIF, e o que os
  pipelines de SAST fazem com `continue-on-error: true` seguido de um passo
  "fail if critical issues found";
- o **veredito fica em um passo separado**, com `exit 1` explicito, e nao
  implícito no status do runner.

O que o SmartSec faz de diferente, e por que: em vez de deixar `1` reprovar o
job (o padrao do Trivy com `exit-code: 1`), o `1` reprova por padrao
**nao**, porque o alvo do CI e uma fixture. A politica de bloqueio fica em uma
variavel de repositorio, o que mantem o comportamento DevSecOps a um clique de
distancia sem transformar o PR do TCC em-blocking por um achado sobre um
servidor HTTP de teste.

---

## 5. Acoes fixadas e cache

Todas as acoes sao referenciadas por SHA imutavel, com a tag equivalente no
 comentario ao lado. Nenhuma referencia a `@main`.

| Ação | SHA | Tag | Origem do SHA |
|---|---|---|---|
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | v7.0.1 | `gh api repos/actions/checkout/commits/v7.0.1` |
| `dtolnay/rust-toolchain` | `6bed0761d98439e5a578e2877258200ad565ba87` | `stable` (2026-09-03) | `gh api repos/dtolnay/rust-toolchain/commits/stable` |
| `Swatinem/rust-cache` | `6323deb102c322ba6fcbdcafc7e3dddab59af2b6` | v2.9.2 | `gh api repos/Swatinem/rust-cache/tags` |
| `actions/upload-artifact` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | v7.0.1 | `gh api repos/actions/upload-artifact/commits/v7.0.1` |

Escolhas:

- **Toolchain:** `dtolnay/rust-toolchain` em vez de
  `actions-rust-lang/setup-rust-toolchain`, porque resolve a toolchain pelo
  manifesto oficial do rust-lang e habilita `rustfmt` e `clippy` na mesma
  declaracao, sem lista separada de componentes. Versao fixada em **1.98.1**,
  a mesma com que a suite foi validada localmente e acima do minimo de Rust
  1.80+ do README. A publicacao existe no canal oficial:
  `channel-rust-1.98.1.toml` responde `HTTP/2 200`.
- **Cache:** `Swatinem/rust-cache` em vez de `actions/cache`, porque ja deriva a
  chave do hash de `Cargo.toml`, `Cargo.lock` e da toolchain e limpa artefatos
  intermediarios antes de salvar; com `actions/cache` a chave teria de ser
  montada a mao e erra quando o lock muda. `shared-key: smartsec-rust-ci`
  compartilha a entrada entre os jobs `qualidade` e `varredura`.
- **Runner:** `ubuntu-24.04` fixado, nao `ubuntu-latest` — o runner faz parte do
  ambiente de validacao do TCC e nao pode trocar de underlie sem registro.

`-j 1` em todos os comandos do cargo esta justificado em comentario no topo do
YAML: e o comando homologado localmente; `cargo -j 2` e morto pelo OOM killer
nesta maquina.

---

## 6. Secrets e pull request de fork

Secret declarado: `SMARTSEC_LLM_API_KEY` (opcional). O valor nunca e impresso,
nunca vai para o relatorio e nunca e gravado no repositorio; o passo *Verificar a
disponibilidade da chave de IA* publica apenas se a chave existe e o motivo.

**Bloqueio registrado:** a chave e inerte hoje. Fontes:

- `src/config/llm_config.rs:84` — `#[serde(skip)]` em `api_key`, ou seja, a
  chave **nao** e lida do TOML;
- `src/config/configuration.rs:168-171` — a unica origem e
  `crate::config::persistence::load_api_key`, que acessa o keyring do sistema
  operacional (Secret Service);
- `grep -rn "env::var" src/` nao retorna **nenhuma** ocorrencia: o binario nao
  le variavel de ambiente alguma.

O runner hospedado nao tem Secret Service, entao o segredo nao alcanca o
provedor remoto. Torna-lo utilizavel exige alteracao em `src/` — fora do escopo
desta issue. O workaround adotado e o fallback deterministico local, com o exit
code inalterado, comprovado na secao 3.

Resolucao para fork: `github.event.pull_request.head.repo.fork` desliga a
chave e fixa a analise local deterministica, com o motivo registrado no *job
summary*. O restante da validacao continua rodando. O workflow usa
`pull_request` (nao `pull_request_target`) e `permissions: contents: read`.

---

## 7. Validacao local

```console
$ cd .worktrees/issue-26
$ cargo fmt --all --check
$ cargo clippy --all-targets -j 1 -- -D warnings
$ cargo test -j 1
```

### `cargo fmt --all --check`

```text
$ cargo fmt --all --check
rc=0
```

Sem saida: nenhum arquivo precisa de reformatação.

### `cargo clippy --all-targets -j 1 -- -D warnings`

```text
    Checking ratatui v0.29.0
    Checking chrono v0.4.45
    Checking reqwest v0.12.28
    Checking keyring v3.6.3
    Checking anyhow v1.0.102
    Checking toml v0.8.23
    Checking quick-xml v0.38.4
    Checking smartsec-rust v0.2.0 (.../.worktrees/issue-26)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 38s
rc=0
```

Nenhum aviso de lint. `-D warnings` nao converteu nada em erro.

### `cargo test -j 1`

```text
     Running unittests src/main.rs (target/debug/deps/smartsec_rust-...)
running 208 tests
test result: ok. 208 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.69s

     Running tests/headless_exit_codes.rs (target/debug/deps/headless_exit_codes-...)
running 3 tests
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.19s

     Running tests/nikto_integration.rs (target/debug/deps/nikto_integration-...)
running 6 tests
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 134.66s

     Running tests/podman_executor.rs (target/debug/deps/podman_executor-...)
running 12 tests
test sandbox::tests::reports_missing_podman_with_remediation ... ok
test sandbox::tests::cancellation_during_creation_removes_container_by_name ... ok
test sandbox::tests::returns_nonzero_status_and_still_removes_container ... ok
test sandbox::tests::cancellation_still_removes_container ... ok
test sandbox::tests::captures_successful_execution_and_removes_container ... ok
test sandbox::tests::trace_sink_receives_the_complete_podman_lifecycle ... ok
test sandbox::tests::exposes_cleanup_failure_with_manual_remediation ... ok
test sandbox::tests::times_out_kills_and_removes_container ... ok
test isolates_process_captures_io_and_removes_container ... ok
test redaction::tests::redacts_sensitive_text_lines ... ok
test redaction::tests::removes_credentials_query_and_fragment_from_urls ... ok
test redaction::tests::strips_http_payloads_and_redacts_nested_secrets_from_jsonl ... ok

test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.44s

rc=0
```

229 testes, 0 falhas. `tests/podman_executor.rs` exercita o executor Podman de
verdade, e `tests/headless_exit_codes.rs` cobre o contrato da secao 10 — sao os
dois arquivos que sustentam o mapeamento de exit code usado pelo workflow.

Nota de tempo: `tests/nikto_integration.rs` levou 134 s sozinho por causa dos
timeouts de execucao em container. Com `-j 1` a suite completa leva alguns
minutos, o que justifica o timeout de 60 min do job `qualidade` com folga.

---

## 8. YAML final

O arquivo completo e `.github/workflows/ci.yml`. Trechos que concentram as
decisoes:

Gatilhos:

```yaml
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:
```

Veredito:

```yaml
          case "$codigo" in
            0)  echo "veredito=ok" >> "$GITHUB_OUTPUT" ;;
            1)  echo "veredito=critico" >> "$GITHUB_OUTPUT"
                if [ "$SMARTSEC_BLOQUEIA_CRITICO" = "true" ]; then exit 1; fi ;;
            2)  echo "veredito=erro" >> "$GITHUB_OUTPUT"; exit 1 ;;
            *)  echo "veredito=inesperado" >> "$GITHUB_OUTPUT"; exit 1 ;;
          esac
```

Publicacao que roda em falha:

```yaml
      - name: Publicar relatório, log estruturado e saída da varredura
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: smartsec-varredura-${{ github.run_id }}
          if-no-files-found: warn
          retention-days: 30
          path: |
            ${{ runner.temp }}/artefatos/*.md
            ${{ runner.temp }}/xdg/smartsec/scans/*.json
            ${{ runner.temp }}/smartsec.log
```

Validacao sintatica do YAML e de todos os blocos `run` (extraidos e passados
por `bash -n`):

```text
YAML OK — jobs: ['qualidade', 'varredura']
OK  qualidade :: rustfmt
OK  qualidade :: clippy
OK  qualidade :: testes
OK  varredura :: Compilar o binário headless
OK  varredura :: Verificar a disponibilidade da chave de IA
OK  varredura :: Verificar o Podman rootless e a rede pasta
OK  varredura :: Verificar o contrato de exit codes da CLI
OK  varredura :: Publicar o alvo autorizado controlado
OK  varredura :: Executar a varredura headless
OK  varredura :: Aplicar o veredito do exit code
OK  varredura :: Resumir o resultado no job
OK  varredura :: Encerrar o alvo local e os containers do SmartSec
```

---

## 9. O que ainda precisa de verificacao no primeiro run

Tudo abaixo **nao** foi verificado: exige o runner hospedado do GitHub.

1. **Existencia e versao do Podman no `ubuntu-24.04`.** O passo *Verificar o
   Podman rootless e a rede pasta* falha com mensagem acionavel se o Podman nao
   estiver instalado ou nao estiver rootless. Se a imagem do runner mudar, o
   job inteiro cai aqui — e a primeira coisa a olhar.
2. **Disponibilidade do backend `pasta` com a flag
   `--map-host-loopback=169.254.1.2`.** O smoke test
   `podman run --rm --network 'pasta:--map-host-loopback=169.254.1.2' <imagem> -V`
   cobre isso antes da varredura. Localmente o Podman 6.1.1 fornece o backend;
   a versao do runner pode ser outra.
3. **Limites de cgroup do runner.** O executor pede `--memory 512m --cpus 1
   --pids-limit 256 --cap-drop all`. O runnerhospedado atende; um
   `podman create` que falhe por cgroup aparece como exit code `2` do SmartSec.
4. **Egresso de rede para o registro.** O `podman pull` de
   `docker.io/instrumentisto/nmap:7.95` depende de acesso ao Docker Hub. Falha de
   rede aparece no smoke test, antes da varredura.
5. **Resolucao das actions por SHA.** Os quatro SHA foram obtidos por `gh api`
   em 30/09/2026 e apontam para commits que existem, mas nenhuma execucao
   comprovou que eles rodam neste workflow. Se alguma action major nova
   (`checkout` v7, `upload-artifact` v7) tiver mudado entrada ou comportamento,
   o primeiro run acusa.
6. **Tempo de build com `-j 1`.** O timeout do job `qualidade` e de 60 minutos.
   O build completo com `-j 1` nao foi cronometrado de ponta a ponta; o cache
   compartilhado deve tornar o segundo run bem mais rapido.
7. **Exit code `1` em execucao real.** O alvo de fixture com `--tools Nmap` so
   produz achados informativos, entao o `1` **nao foi observado** em execucao.
   O mapeamento dele foi validado pela simulacao do veredito (secao 4), nao por
   um scan que estourou em severidade critica. Se a politica
   `SMARTSEC_BLOQUEIA_CRITICO` for exercitada, ela precisa de um alvo que
   gere achado critico de verdade.
8. **Injecao de secret.** Nao ha como verificar o consumo do secret ate existir
   um caminho de leitura em `src/` (secao 6). O que se verifica no primeiro run
   e apenas a ausencia de vazamento: o secret nao pode aparecer em nenhum log
   nem no artifact.
9. **Leitura do resumo do job.** O `job summary` recebe a tabela de veredito e o
   relatorio Markdown; a renderizacao no PR so pode ser conferida no primeiro
   run.

## 10. Bloqueio registrado

Ver secao 6: a chave de IA do secret nao alcanca o binario porque
`src/config/persistence.rs` so le o keyring do sistema operacional e nao existe
leitura de variavel de ambiente em `src/`. **Nenhuma alteracao em `src/` foi
feita nesta issue.** Correcao exige abrir issue de follow-up decidindo entre
ler `SMARTSEC_LLM_API_KEY` do ambiente no headless e criar uma entrada de
keyring no runner.
