# SmartSec

Plataforma de analise de seguranca — prototipo escrito em Rust com interface de terminal.

## Documentacao do TCC

- [Especificacao completa, requisitos, sprints e metas](TCC_SPEC.md)
- [Regras para agentes, branches, PRs e Definition of Done](AGENTS.md)
- [Distribuicao atual da Sprint 1](docs/PLANO_DE_DISTRIBUICAO.md)

# Demonstracao
## Modo Assitido
![Modo Assistido](docs/assistido.gif)

## Modo Automatico
![Modo Automatico](docs/auto.gif)

## Modo Headless (CI/CD)
![Modo Headless](docs/headless.gif)


## Aviso

Este e um **prototipo / prova de conceito**. O catalogo atual oferece Nmap e
Nuclei reais, executados somente em containers Podman rootless; os binarios dos
scanners nunca sao chamados diretamente no host. As demais ferramentas
previstas no TCC ainda nao fazem parte do catalogo executavel.

## Funcionalidades

- **TUI** construida com [ratatui](https://crates.io/crates/ratatui) + [crossterm](https://crates.io/crates/crossterm)
- **Modo headless** via `scan --target <alvo>`
- **Nmap real** via Podman rootless, com portas e serviços extraídos do XML
- **Suporte a mouse** — todos os botoes e listas sao clicaveis
- **Nuclei real** — imagem fixada por digest, templates montados somente-leitura e plano Nmap/IA aplicado aos argumentos
- **Analise IA** com Ollama local por padrao e suporte a OpenAI / NVIDIA NIM
- **Exportacao de relatorio** — gera `smartsec-report.md` com findings, recomendacoes e explicacoes didaticas

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

# Na TUI em modo assistido, marque ou desmarque ferramentas com Espaco
```

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
  tools/               Runners reais das ferramentas (Nmap e Nuclei)
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
| Mouse     | Clicar botoes, selecionar ferramentas, rolar listas |

## Licenca

Prototipo academico (TCC).
