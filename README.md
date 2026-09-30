# SmartSec

Plataforma de analise de seguranca — prototipo escrito em Rust com interface de terminal.

## Documentacao do TCC

- [Especificacao completa, requisitos, sprints e metas](TCC_SPEC.md)
- [Regras para agentes, branches, PRs e Definition of Done](AGENTS.md)
- [Distribuicao atual da Sprint 1](docs/PLANO_DE_DISTRIBUICAO.md)

# Demonstracao

Video completo da demonstracao: [`docs/demo-completo.mp4`](docs/demo-completo.mp4)

## Modo Assistido (TUI)
![Modo Assistido](docs/assistido.gif)

## Decisao da IA no relatorio
![Decisao da IA no relatorio](docs/decisao-ia.gif)

## Modo Headless (CI/CD)
![Modo Headless](docs/headless.gif)


## Aviso

Este e um **prototipo / prova de conceito**. O catalogo atual oferece Nmap,
Nuclei e Nikto reais, executados somente em containers Podman rootless; os
binarios dos scanners nunca sao chamados diretamente no host. As demais ferramentas
previstas no TCC ainda nao fazem parte do catalogo executavel.

## Funcionalidades

- **TUI** construida com [ratatui](https://crates.io/crates/ratatui) + [crossterm](https://crates.io/crates/crossterm)
- **Modo headless** via `scan --target <alvo>`
- **Nmap real** via Podman rootless, com portas e serviços extraídos do XML
- **Suporte a mouse** — todos os botoes e listas sao clicaveis
- **Nuclei real** — imagem fixada por digest, templates montados somente-leitura e plano Nmap/IA aplicado aos argumentos
- **Nikto real** — imagem fixada por digest e relatorio JSON escrito no stdout sem shell e sem arquivo
- **Analise IA** com Ollama local por padrao e suporte a OpenAI / NVIDIA NIM
- **Exportacao de relatorio** — gera `smartsec-report.md` com findings, recomendacoes e explicacoes didaticas
- **Evidencia segura** — preserva template, matcher, endpoint, host, URL e tags, sem corpos HTTP, credenciais ou query strings

## Requisitos

- Rust 1.80+
- [Podman](https://podman.io/) configurado em modo rootless
- Podman com suporte ao backend de rede rootless `pasta` (o Podman 6.1 usado
  na validacao local ja o fornece; versoes recentes removeram o backend
  obsoleto `slirp4netns`)
- Templates do Nuclei em `~/nuclei-templates`, no commit esperado configurado; o caminho e commit podem ser definidos no TOML

O executor sempre usa `--network pasta` em containers rootless. Essa rede
mantem o isolamento do container sem exigir privilegios de root e evita o
backend removido `slirp4netns`; nao ha fallback silencioso para outro driver.
O endereco reservado `169.254.1.2` dentro dos scanners aponta para o loopback
do host. Assim, uma aplicacao autorizada publicada somente em `127.0.0.1:3000`
pode ser analisada com `--target http://169.254.1.2:3000` sem ser exposta na
rede local.

## Uso rapido

```bash
# Ajuda e versão
cargo run -- --help
cargo run -- --version

# TUI interativa
cargo run

# Headless — scan automático com relatório
cargo run -- scan --target https://httpbin.org

# Headless — executar apenas o Nmap
cargo run -- scan --target https://example.com --tools Nmap

# Executar manualmente uma ferramenta específica
cargo run -- tool Nmap --target 192.0.2.10

# Usar configuração TOML e substituir opções pela CLI
cargo run -- scan --target example.com --config ./smartsec.toml --llm ollama --model llama3.1:8b

# Escolher arquivo e diretório do relatório
cargo run -- scan --target https://example.com --output relatorio.md --output-dir ./saida

# Na TUI em modo assistido, marque ou desmarque ferramentas com Espaco
```

### Exit codes do modo headless

| Código | Significado |
|---:|---|
| 0 | nenhuma vulnerabilidade crítica |
| 1 | vulnerabilidade crítica encontrada |
| 2 | erro de configuração ou de execução |

O relatório e o log estruturado são gravados antes da mensagem final. Falha de
scanner retorna `2` mesmo que o relatório preserve achados; achado crítico
retorna `1` e não é tratado como erro interno.

## GitHub Actions

O workflow [`ci.yml`](.github/workflows/ci.yml) roda a validação do SmartSec no
GitHub Actions. Ele tem dois jobs:

| Job | O que faz | Quando falha |
|---|---|---|
| `qualidade` | `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` e `cargo test` | sempre que o código estiver fora do padrão |
| `varredura` | executa o SmartSec em modo headless contra um alvo autorizado local e publica os artefatos | conforme o [mapeamento de exit code](#exit-code-do-smartsec-e-o-resultado-do-job) |

No runner `ubuntu-24.04`, `qualidade` leva 2m50s e `varredura` 2m29s. A evidência
completa, incluindo o que o runner mostrou e o que ainda não foi verificado,
está em
[`docs/evidence/issue-26-github-actions.md`](docs/evidence/issue-26-github-actions.md).

### Quando o workflow dispara

```yaml
on:
  push:            # só na main, para não duplicar a execução com a do pull request
    branches: [main]
  pull_request:    # gate de integração
    branches: [main]
  workflow_dispatch:  # execução manual
```

Para validar branches de trabalho também, acrescente o nome em `push.branches`
(por exemplo `[main, develop]`). Para disparar por tag, acrescente
`tags: ['v*']` no bloco `push`. O gatilho `pull_request` é mantido em vez de
`pull_request_target` de propósito: `pull_request_target` roda com acesso ao
repositório e aos secrets mesmo em pull requests de fork.

### Alvo autorizado

O job `varredura` **nunca** escaneia um alvo externo. Ele sobe um servidor HTTP
preso a `127.0.0.1` no próprio runner e aponta os scanners para
`http://169.254.1.2:$SMARTSEC_ALVO_PORTA`, que é o endereço que o Podman
rootless mapeia para o loopback do host
(`--network pasta:--map-host-loopback=169.254.1.2`, fixado em
`src/orchestrator/sandbox.rs`). Os scanners continuam rodando em container
rootless, como exige o TCC — nenhum binário de scanner é chamado no host.

O alvo e as ferramentas são controlados por variáveis de ambiente no topo do
workflow: `SMARTSEC_ALVO_PORTA`, `SMARTSEC_FERRAMENTAS` (padrão `Nmap`) e
`SMARTSEC_IMAGEM_NMAP`, que espelha `NMAP_IMAGE` de `src/tools/nmap.rs`.
Alterar a imagem no código exige atualizar a variável, ou o smoke test do
passo de pré-requisitos passa a validar a imagem errada.

### Exit code do SmartSec e o resultado do job

O passo da varredura roda com `continue-on-error: true` e grava o exit code em
um output. Um passo separado, **Aplicar o veredito do exit code**, decide o
resultado do job com um mapeamento explícito:

| Exit code | Significado no SmartSec | Resultado do job |
|---:|---|---|
| `0` | nenhuma vulnerabilidade crítica | verde |
| `1` | vulnerabilidade crítica encontrada | **verde**, com `::warning::`, relatório publicado e contagem no resumo |
| `2` | erro interno, de configuração ou de execução | vermelho |
| qualquer outro | panic, OOM killer ou sinal | vermelho |

Por que `1` não vira falha por padrão: achado crítico é um **resultado válido da
varredura**, não um defeito do pipeline. O `TCC_SPEC.md` (seção 10) é explícito:
"finding crítico não é erro interno: deve retornar `1` e preservar o relatório".
No CI o alvo é uma fixture local servida pelo próprio runner, que não produz
achados críticos com o Nmap — bloquear o merge por um achado sobre um alvo que
ninguém autorizou a corrigir seria um falso positivo no gate. Já o `2` significa
que a varredura é inconfiável: o resultado não pode ser aproveitado e o job
precisa falhar. Tratar "tudo não-zero é falha" também esconderia o `1` atrás do
`2`, porque no código a falha de execução tem precedência sobre o achado crítico.

Para o modo DevSecOps que bloqueia o merge, crie a **variável de repositório**
`SMARTSEC_BLOQUEIA_CRITICO` com valor `true`
(*Settings > Secrets and variables > Actions > Variables*). Aí o `1` passa a
falhar o job e o `0` continua verde. A variável é do repositório, e não um
secret, porque ela não é credencial.

O passo da varredura não decide nada sozinho justamente para que o log da
execução, o relatório Markdown e o log estruturado sejam gravados **antes** do
veredito. O passo de publicação roda com `if: always()`, então os artefatos saem
da pipeline mesmo com achado crítico e mesmo com erro de execução.

Esse desenho já foi exercitado por um caso real: em um run do
[PR #84](https://github.com/luis-ota/smartsec-rust/pull/84) o SmartSec devolveu
`2` porque o crun do runner não conseguiu subir o container, o job ficou
vermelho **e** os três artefatos foram publicados e baixados normalmente. É a
evidência de que `2` reprova e de que a evidência não se perde.

### Artifacts

Sempre que existirem, com retenção de 30 dias:

- `relatorio.md` — relatório Markdown, gravado por `--output-dir`;
- `scan_*.json` — log estruturado do scan;
- `smartsec.log` — saída completa da execução headless.

O log estruturado **não** obedece ao `--output-dir`: `save_scan_log` em
`src/orchestrator/scan_logger.rs` sempre grava em
`$XDG_CONFIG_HOME/smartsec/scans/`. Por isso o job exporta `XDG_CONFIG_HOME`
para dentro de `$RUNNER_TEMP` — é o que torna o arquivo coletável sem tocar em
`src/`. Também é por isso que o `XDG_CONFIG_HOME` é isolado: o runner não
enxerga, e não é contaminado por, um `~/.config/smartsec/config.toml` de
desenvolvedor.

O relatório também é injetado no *job summary*, junto com a tabela de veredito,
para que o resultado fique legível na página do PR sem abrir o artifact.

### Secrets

O workflow consome **um** secret, opcional:

| Secret | Para quê |
|---|---|
| `SMARTSEC_LLM_API_KEY` | habilitaria o provedor de IA remoto |

**Limitação real:** hoje a chave é inerte. O binário carrega a credencial
apenas do keyring do sistema operacional — `llm.api_key` é `#[serde(skip)]` no
TOML (`src/config/llm_config.rs`) e a leitura acontece em
`crate::config::persistence::load_api_key`, ou seja, no Secret Service. Não
existe leitura de variável de ambiente em `src/`, e o runner hospedado não tem
Secret Service. Na prática, o CI roda com `--llm ollama` (loopback) e, como não
há Ollama no runner, o agente cai no **fallback determinístico local**
(`local_analysis` em `src/ai/agent.rs`): a análise sai em português, sem
reclassificar severidades, e o exit code não muda. O passo *Verificar a
disponibilidade da chave de IA* publica apenas se a chave existe — o valor
nunca é impresso, nunca vai para o relatório e nunca é gravado no repositório.
Habilitar a IA remota de verdade exige alteração em `src/`, registrada como
bloqueio na issue #26.

O provedor remoto também exigiria `remote_consent` e HTTPS na base URL; sem a
chave no keyring, `LlmConfig::validate` reprovaria a configuração e o scan
terminaria com `2`.

### Pull requests de fork

O GitHub não injeta secrets em pull requests de fork. Em vez de desabilitar o
job inteiro, o workflow degrada de forma explícita: o passo *Verificar a
disponibilidade da chave de IA* detecta
`github.event.pull_request.head.repo.fork` e fixa a análise local determinística,
registrando o motivo no *job summary*. O restante da validação — formatação,
clippy, testes e scanners em container contra o alvo local — continua rodando
normalmente. As permissões do workflow são somente `contents: read`.

### Limitações no runner hospedado

Estas limitações são reais e foram **medidas** no runner `ubuntu-24.04` do
GitHub, não presumidas. Três pré-requisitos de ambiente precisam ser atendidos
pelo workflow, e nenhum deles era previsível lendo o código:

- **`pasta` compilado pelo workflow.** O Podman do runner é o 4.9.3, e o `pasta`
  dele **não aceita** a opção `--map-host-loopback=169.254.1.2` que
  `src/orchestrator/sandbox.rs` fixa para toda execução:

  ```text
  /usr/bin/pasta: unrecognized option '--map-host-loopback=169.254.1.2'
  Error: pasta failed with exit code 1
  ```

  Sem essa opção não existe caminho para o container alcançar um serviço preso
  ao loopback do host: o loopback do container é o próprio container, e o
  endereço do gateway não responde pelo serviço. O workflow compila o `pasta`
  de um commit fixado e o instala em `/usr/local/bin`, que precede `/usr/bin` no
  `PATH`. O commit é conferido com `git rev-parse HEAD` antes do build, então a
  origem do binário é verificável pelo hash do próprio commit. Isso é ajuste de
  ambiente, não de código: a exigência é do projeto.

  A mesma causa já fazia **`cargo test` falhar no runner hospedado**, em
  `tests/podman_executor.rs::isolates_process_captures_io_and_removes_container`
  (`Failed(Some(125))`), porque o executor usa a mesma flag de rede. É um bug de
  ambiente pré-existente a esta issue, agora resolvido no CI.

- **Headers do D-Bus.** O `keyring` usa a feature `sync-secret-service` no
  Linux, que puxa `libdbus-sys`; o build script dele chama
  `pkg-config --libs --cflags 'dbus-1 >= 1.6'`. O runner não traz os headers de
  desenvolvimento, então sem `libdbus-1-dev` o build morre com exit `101` antes
  de chegar ao clippy.

- **Barramento D-Bus disponível durante o scan.** O crun do runner usa o systemd
  como gerenciador de cgroup e precisa do barramento da sessão para subir o
  container. Desabilitar `DBUS_SESSION_BUS_ADDRESS` para evitar a leitura da
  chave no keyring faz o scan falhar com
  `crun: sd-bus call: Interactive authentication required` e exit `125`. A
  leitura da chave já é tolerante: sem Secret Service ela falha e o código
  segue, sem prompt e sem espera.

Outras limitações que continuam valendo:

- **Rede de saída.** O runner hospedado tem acesso à internet. O `podman pull`
  da imagem do Nmap e a rede `pasta` dependem disso; sem acesso ao registro, o
  smoke test falha com mensagem de rede explícita antes da varredura. O
  container também ganha acesso de saída — o TCC não permite fechar isso sem
  alterar `src/orchestrator/sandbox.rs`, que fixa `--network pasta`.
- **Keyring.** Não há Secret Service no runner, então provedores remotos de IA
  não funcionam (ver *Secrets*).
- **Templates do Nuclei.** O Nuclei exige um checkout Git de templates no commit
  configurado; o CI não faz esse checkout e por isso roda apenas com
  `--tools Nmap`. Para incluir o Nuclei, é preciso clonar
  `projectdiscovery/nuclei-templates` e fixar `nuclei_templates_path` e
  `nuclei_templates_commit` no job.
- **Recursos.** O executor pede `--memory 512m --cpus 1 --pids-limit 256` e
  `--cap-drop all`; o runner hospedado atende, mas um runner self-hosted sem
  delegação de cgroup v2 faz o `podman create` falhar — e a falha aparece como
  exit code `2` do SmartSec, com mensagem de configuração do Podman.
- **`-j 1` em todos os comandos do cargo.** O `cargo -j 2` é morto pelo kernel
  OOM killer nas máquinas de desenvolvimento (15 GiB de RAM, ~4 GiB livres). O
  CI mantém `-j 1` para executar exatamente a linha de comando homologada
  localmente e produzir evidência comparável, ao custo de tempo de build.
  Medido no runner: `qualidade` leva 2m50s e `varredura` 2m29s, com o cache
  compartilhado já aquecido.
- **Cache.** `Swatinem/rust-cache` é usado no lugar de `actions/cache` porque
  já deriva a chave do hash de `Cargo.toml`, `Cargo.lock` e da toolchain e
  limpa artefatos intermediários antes de salvar; com `actions/cache` a chave
  teria de ser montada à mão. A chave é compartilhada entre os dois jobs
  (`shared-key: smartsec-rust-ci`) para o binário compilado ser reaproveitado.
  As toolchain e todas as actions são fixadas por SHA, com a tag equivalente no
  comentário ao lado — nenhuma referência a `@main`.
- **Rust fixado em 1.98.1** (`dtolnay/rust-toolchain`, escolhido por resolver a
  toolchain pelo manifesto oficial do rust-lang sem lista separada de
  componentes), a mesma versão com que a suíte foi validada localmente e acima do
  mínimo de Rust 1.80+ declarado abaixo.

### Rodando a validação sem o GitHub

```bash
cargo fmt --all --check
cargo clippy --all-targets -j 1 -- -D warnings
cargo test -j 1
```

O script [`scripts/e2e_tui_local.sh`](scripts/e2e_tui_local.sh) reproduz o
alvo autorizado local fora do CI, pela TUI. A evidência da integração está em
[`docs/evidence/issue-26-github-actions.md`](docs/evidence/issue-26-github-actions.md).

### Arquivo de configuração TOML

O modelo comentado [`smartsec.example.toml`](smartsec.example.toml) mostra o
schema mínimo: `target_url`, `active_tools`, `execution_type` e a tabela
`[llm]`. Regras:

- `--target` é sempre obrigatório na CLI; o `target_url` do arquivo é usado
  pela TUI e substituído pela CLI no headless.
- `--tools`, `--llm` e `--model` sobrescrevem os valores do arquivo.
- `provider` aceita as grafias da CLI (`ollama`, `openai`, `nvidia-nim`,
  `custom`) além das canônicas (`Ollama`, `NvidiaNim`, `OpenAI`, `Custom`).
- `base_url` e `model` ausentes assumem o padrão do provedor;
  `execution_type` ausente assume `Assisted`.
- `scan` headless sempre opera como Automático, independente de
  `execution_type`.
- `output_file` e `output_dir` definem o destino do relatório Markdown; as
  flags `--output`/`--output-dir` têm precedência sobre o arquivo.

### Configuracao da IA na TUI

A tela `Configurar IA` separa conexao principal de confiabilidade e mostra
somente os campos aplicaveis. Provedores remotos exibem chave e consentimento;
o Ollama local os oculta. `Tab` percorre os campos e acoes, `←`/`→` alteram
selecoes, `Espaco` alterna opcoes e `Ctrl+U` limpa o campo atual. Valores
invalidos mantem a tela aberta com uma mensagem acionavel. Chaves ficam no
keyring do sistema e nunca sao gravadas no TOML. No Linux o keyring usa o
Secret Service (por exemplo, gnome-keyring ou KWallet), que precisa estar
ativo para salvar e ler chaves de provedores remotos.

### E2E real da TUI

O roteiro abaixo abre a TUI em um terminal `80x24`, serve um alvo autorizado
somente em `127.0.0.1`, executa Nmap e Nuclei via Podman rootless, salva a
auditoria, exporta o Markdown, procura dados sensiveis e confirma a remocao dos
containers:

```bash
./scripts/e2e_tui_local.sh
```

Ele exige `bash`, `cargo`, `curl`, `jq`, `podman`, `python3`, `rg`, `tmux`,
Ollama local com `llama3.2:1b` e o checkout versionado em
`~/nuclei-templates`. Os artefatos temporarios ficam no caminho informado ao
fim da execucao. A evidencia homologada desta mudanca esta em
[`docs/evidence/issue-53-tui-e2e.md`](docs/evidence/issue-53-tui-e2e.md).

Para uma execucao real, a configuracao TOML pode definir `nuclei_templates_path` e
`nuclei_templates_commit`. O SmartSec rejeita o scan se o diretorio nao for um
checkout Git no commit esperado. A imagem usada e
`docker.io/projectdiscovery/nuclei@sha256:2a11faa83464d769a888f1abb9396d5b4d8640619dfc6310086bf5c0d4003481`.

## Arquitetura

```
src/
  main.rs              Ponto de entrada (CLI + TUI + headless)
  tui/                 Interface de terminal (telas, estado, eventos, mouse)
  orchestrator/        Pipeline de execucao, sandbox, parsers
  tools/               Runners reais das ferramentas (Nmap, Nuclei e Nikto)
  ai/                  Agente IA (prompt LLM + analise)
  llm/                 Provedores LLM (openai, ollama, nvidia-nim)
  domain/              Modelos de dados (vulnerabilidade, severidade, ferramentas)
  config/              Persistencia de configuracao (~/.config/smartsec/)
  report/              Gerador de relatorio Markdown
  utils/               Auxiliares de texto
```
## Navegacao

| Tecla     | Acao                     |
|-----------|--------------------------|
| Tab       | Mover o foco              |
| Enter     | Confirmar / Iniciar / Rodar |
| Espaco    | Selecionar/deselecionar ferramenta |
| Esc       | Sair / Voltar            |
| F1        | Abrir ajuda               |
| Ctrl+P    | Abrir paleta de comandos  |
| Ctrl+V    | Colar do clipboard       |
| Ctrl+U    | Limpar o campo atual na configuracao |
| Mouse     | Clicar botoes, selecionar ferramentas, rolar listas |

## Licenca

Prototipo academico (TCC).
