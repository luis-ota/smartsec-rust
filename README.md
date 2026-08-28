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

Este e um **prototipo / prova de conceito**. A maioria das ferramentas de seguranca sao emuladas (mock), mas o **Nuclei executa de verdade** em um container Podman rootless e produz findings a partir da saida JSONL.

## Funcionalidades

- **TUI** construida com [ratatui](https://crates.io/crates/ratatui) + [crossterm](https://crates.io/crates/crossterm)
- **Modo headless** via `--auto --url <alvo>`
- **Suporte a mouse** — todos os botoes e listas sao clicaveis
- **Nuclei real** — escaneia alvos usando 968+ templates de misconfiguracao, extrai findings com classificacao de severidade
- **Analise IA** (integracao com LLM — mock por padrao, suporta OpenAI / Ollama / NVIDIA NIM)
- **Exportacao de relatorio** — gera `smartsec-report.md` com findings, recomendacoes e explicacoes didaticas

## Requisitos

- Rust 1.80+
- Podman rootless
- Templates do Nuclei `v10.2.9`, commit `8adc92372034777469dcef575af21ba56e336f9d`

O binario nao e executado no host. A imagem esta fixada pelo digest multi-arquitetura de `projectdiscovery/nuclei:v3.4.10`. Instale os templates fixados no diretorio padrao antes da primeira varredura real:

```bash
mkdir -p ~/.local/share/smartsec
git clone https://github.com/projectdiscovery/nuclei-templates.git ~/.local/share/smartsec/nuclei-templates-v10.2.9
git -C ~/.local/share/smartsec/nuclei-templates-v10.2.9 checkout --detach 8adc92372034777469dcef575af21ba56e336f9d
```

Concorrencia, timeout de requisicao, timeout total, diretorio e selecao de templates podem ser ajustados em `~/.config/smartsec/config.toml`:

```toml
[nuclei]
concurrency = 25
request_timeout_seconds = 5
scan_timeout_seconds = 900
templates_directory = "/home/usuario/.local/share/smartsec/nuclei-templates-v10.2.9"
templates = ["http/misconfiguration/"]
```

## Uso rapido

```bash
# TUI interativa
cargo run

# Headless — scan automatico com relatorio
cargo run -- --auto --url https://httpbin.org

# Para ativar o Nuclei real:
# Na TUI: C-x s → Real Nuclei → Enable → Save
# Depois execute normalmente que o Nuclei vai rodar de verdade
```

## Arquitetura

```
src/
  main.rs              Ponto de entrada (CLI + TUI + headless)
  tui/                 Interface de terminal (telas, estado, eventos, mouse)
  orchestrator/        Pipeline de execucao, sandbox, parsers
  tools/               Runners das ferramentas (nuclei, mocks)
  ai/                  Agente IA (prompt LLM + analise)
  llm/                 Provedores LLM (mock, openai, ollama, nvidia-nim)
  domain/              Modelos de dados (vulnerabilidade, severidade, ferramentas)
  config/              Persistencia de configuracao (~/.config/smartsec/)
  report/              Gerador de relatorio Markdown
  utils/               Auxiliares de texto
```
## Navegacao

| Tecla     | Acao                     |
|-----------|--------------------------|
| Tab       | Alternar modo (Auto/Assistido) |
| Enter     | Confirmar / Iniciar / Rodar |
| Espaco    | Selecionar/deselecionar ferramenta |
| Esc       | Sair / Voltar            |
| C-x s     | Abrir configuracoes      |
| C-x p     | Pausar execucao          |
| C-x c     | Cancelar execucao        |
| C-x q     | Sair                     |
| Ctrl+V    | Colar do clipboard       |
| Mouse     | Clicar botoes, selecionar ferramentas, rolar listas |

## Licenca

Prototipo academico (TCC).
