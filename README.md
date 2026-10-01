# SmartSec

Plataforma de analise de seguranca — prototipo escrito em Rust com interface de terminal.

## Documentacao do TCC

- [Especificacao completa, requisitos, sprints e metas](TCC_SPEC.md)
- [Regras para agentes, branches, PRs e Definition of Done](AGENTS.md)
- [Distribuicao atual da Sprint 1](docs/PLANO_DE_DISTRIBUICAO.md)

## Configuracao

- [Arquivo TOML, tela Configurar IA e comportamento da TUI](docs/CONFIGURACAO.md)
- [Agente de codigo: fluxo, limites e riscos](docs/AGENTE_DE_CODIGO.md)
- [Como adicionar uma ferramenta ao catalogo](docs/EXTENDING_TOOLS.md)

## Demonstracao

Video completo: [`docs/demo-completo.mp4`](docs/demo-completo.mp4)

| Modo Assistido (TUI) | Decisao da IA no relatorio | Modo Headless (CI/CD) |
|---|---|---|
| ![Modo Assistido](docs/assistido.gif) | ![Decisao da IA](docs/decisao-ia.gif) | ![Modo Headless](docs/headless.gif) |

## Aviso

Este e um **prototipo / prova de conceito**. O catalogo atual oferece Nmap,
Nuclei, Nikto, SQLMap, TruffleHog e OWASP ZAP reais, executados somente em
containers Podman rootless; os binarios dos scanners nunca sao chamados
diretamente no host. As demais ferramentas previstas no TCC ainda nao fazem
parte do catalogo executavel.

## Funcionalidades

- **TUI** com [ratatui](https://crates.io/crates/ratatui) + [crossterm](https://crates.io/crates/crossterm), navegavel por teclado e mouse
- **Modo headless** via `scan --target <alvo>`, com exit codes proprios para CI
- **Seis scanners reais**, cada um com imagem fixada por digest, rodando em container rootless
- **Analise IA** com Ollama local por padrao e suporte a OpenAI / NVIDIA NIM / endpoint customizado
- **Agente de codigo** que aponta `arquivo:linha` de cada achado depois dos scanners, em modo somente leitura
- **Relatorio Markdown e PDF** com a mesma base sanitizada, entao os dois nao divergem
- **Historico consultavel** por CLI e pela TUI, com log estruturado por execucao
- **Evidencia segura** — sem corpos HTTP, credenciais ou query strings

## Requisitos

- Rust 1.80+
- [Podman](https://podman.io/) em modo rootless, com o backend de rede `pasta`
- Templates do Nuclei em `~/nuclei-templates`, no commit esperado configurado

O executor sempre usa `--network pasta`, que mantem o isolamento do container sem
exigir privilegios de root. O endereco reservado `169.254.1.2` dentro dos
scanners aponta para o loopback do host, entao uma aplicacao autorizada
publicada so em `127.0.0.1:3000` pode ser analisada sem ser exposta na rede
local.

Detalhamento em [docs/CONFIGURACAO.md](docs/CONFIGURACAO.md).

## Uso rapido

```bash
# TUI interativa
cargo run

# Headless — scan automatico com relatorio
cargo run -- scan --target https://example.com

# Apenas uma ferramenta
cargo run -- scan --target https://example.com --tools Nmap

# Analisar o codigo de um projeto (padrao: diretorio atual)
cargo run -- scan --target https://example.com --project ./minha-aplicacao

# Historico de execucoes
cargo run -- history
cargo run -- show scan_1757000000000000000

# Alvo local autorizado, a partir de um servidor preso ao loopback
cargo run -- scan --target http://169.254.1.2:3000
```

O arquivo TOML e as flags sao detalhados em
[docs/CONFIGURACAO.md](docs/CONFIGURACAO.md).

## Relatorios

Cada execucao gera **dois** arquivos com o mesmo nome e na mesma pasta:

```text
saida/relatorio.md
saida/relatorio.pdf
```

O PDF e montado a partir da **mesma** string Markdown ja sanitizada que vai para
o `.md`, entao os dois nao podem divergir. O destino vem de
`--output`/`--output-dir` ou do TOML, e o PDF sai ao lado com a extensao trocada.

## Exit codes do modo headless

| Codigo | Significado |
|---:|---|
| 0 | nenhuma vulnerabilidade critica |
| 1 | vulnerabilidade critica encontrada |
| 2 | erro de configuracao, de execucao ou de gravacao do relatorio |
| 130 | cancelado por `SIGINT` (Ctrl+C) |
| 143 | cancelado por `SIGTERM` |

O relatorio e o log estruturado sao gravados **antes** da mensagem final, mesmo
quando a execucao e cancelada ou um scanner falha. Na consulta ao historico,
`history` retorna `0` mesmo vazio e `show <SCAN_ID>` retorna `2` para
identificador invalido — um id errado em automacao e erro de uso, nao varredura
limpa.

## Pausar e cancelar

Na tela de execucao, `p` pausa e retoma e `c` cancela, tambem pelo mouse e pela
paleta de comandos (`Ctrl+P`). Pausar atua no **container real** (`podman pause`);
cancelar encerra o processo e remove o container, sem deixar orfao. Cancelamento
tem codigo proprio para nao ser confundido com erro interno.

`max_critical_findings` no TOML interrompe a varredura ao atingir a quantidade
configurada, avaliado entre ferramentas para preservar a evidencia recem-coletada.

## Arquitetura

```
src/
  main.rs          Ponto de entrada (CLI + TUI + headless)
  tui/             Interface de terminal (telas, estado, eventos, mouse)
  orchestrator/    Pipeline de execucao, sandbox, parsers, historico de scans
  tools/           Runners reais das ferramentas
  ai/              Agente IA e servico unico de analise (TUI e headless)
  code_agent/      Agente de codigo: sandbox read-only e tool calling
  llm/             Provedores LLM (openai, ollama, nvidia-nim)
  domain/          Modelos de dados (vulnerabilidade, severidade, ferramentas)
  config/          Persistencia de configuracao (~/.config/smartsec/)
  report/          Gerador de relatorio Markdown e PDF
```

## Validacao

```bash
cargo fmt --all --check
cargo clippy --all-targets -j 1 -- -D warnings
cargo test -j 1
```

`-j 1` e obrigatorio: o `cargo -j 2` e morto pelo OOM killer nas maquinas de
desenvolvimento. Como o CI valida e documentado em
[docs/GITHUB_ACTIONS.md](docs/GITHUB_ACTIONS.md).

## Navegacao

| Tecla     | Acao                     |
|-----------|--------------------------|
| Tab       | Mover o foco              |
| Enter     | Confirmar / Iniciar / Rodar |
| Espaco    | Selecionar/deselecionar ferramenta |
| Esc       | Sair / Voltar            |
| P         | Pausar / retomar a execucao |
| C         | Cancelar a execucao       |
| F1        | Abrir ajuda               |
| Ctrl+P    | Abrir paleta de comandos  |
| Ctrl+U    | Limpar o campo atual na configuracao |
| H         | Abrir o historico de execucoes |
| Mouse     | Clicar botoes, selecionar ferramentas, rolar listas |

## Licenca

Prototipo academico (TCC).

A fonte Noto Sans usada no relatorio PDF e distribuida sob a SIL Open Font
License 1.1, em `assets/fonts/LICENSE`.