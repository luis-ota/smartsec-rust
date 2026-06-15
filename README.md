# SmartSec

Plataforma de analise de seguranca — prototipo escrito em Rust com interface de terminal.

# Demonstracao
## Modo Assitido
[▶ Assistir demonstracao do modo assistido](https://github.com/luis-ota/smartsec-rust/releases/download/demo/assistido.mp4)

## Modo Automatico
[▶ Assistir demonstracao do modo automatico](https://github.com/luis-ota/smartsec-rust/releases/download/demo/auto.mp4)

## Modo Headless (CI/CD)
[▶ Assistir demonstracao do modo headless](https://github.com/luis-ota/smartsec-rust/releases/download/demo/headless.mp4)


## Aviso

Este e um **prototipo / prova de conceito**. A maioria das ferramentas de seguranca sao emuladas (mock), mas o **Nuclei executa de verdade** — roda o binario real contra o alvo e faz parsing dos findings a partir da saida JSON.

## Funcionalidades

- **TUI** construida com [ratatui](https://crates.io/crates/ratatui) + [crossterm](https://crates.io/crates/crossterm)
- **Modo headless** via `--auto --url <alvo>`
- **Suporte a mouse** — todos os botoes e listas sao clicaveis
- **Nuclei real** — escaneia alvos usando 968+ templates de misconfiguracao, extrai findings com classificacao de severidade
- **Analise IA** (integracao com LLM — mock por padrao, suporta OpenAI / Ollama / NVIDIA NIM)
- **Exportacao de relatorio** — gera `smartsec-report.md` com findings, recomendacoes e explicacoes didaticas

## Requisitos

- Rust 1.80+
- [Nuclei](https://github.com/projectdiscovery/nuclei) (para escaneamento real)
- Templates do Nuclei (`nuclei -update-templates`)

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

## O que e real vs mock

| Componente        | Status |
|-------------------|--------|
| Scanner Nuclei    | **Real** — executa binario `nuclei`, faz parsing da saida JSONL |
| Outros scanners   | Mock — emulados com saida placeholder |
| Sandbox           | Mock — gera IDs de container falsos |
| Analise IA        | Configuravel — mock por padrao, real via OpenAI/Ollama/NIM |
| Relatorio         | Real — gera arquivo `smartsec-report.md` |
| Configuracao      | Real — persistida em `~/.config/smartsec/config.toml`, API key no keyring do SO |

## Como o Nuclei funciona no SmartSec

1. Quando `Real Nuclei` esta ativado nas configuracoes, o orquestrador executa o binario `nuclei`
2. Templates de `~/nuclei-templates/http/misconfiguration/` sao usados (~968 templates)
3. O scan roda com `-c 200 -timeout 2` para performance
4. A saida JSONL e parseada em structs `Vulnerability` com classificacao de severidade
5. Os findings reais sao mesclados com a biblioteca interna de vulnerabilidades (16 CVEs mock para demonstracao)
6. Todos os findings aparecem na lista de resultados e sao incluidos no relatorio exportado

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
