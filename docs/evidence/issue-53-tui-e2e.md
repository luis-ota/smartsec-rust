# Evidencia E2E da TUI — issue #53

Data da homologacao: 10/09/2026.

## Ambiente

- SmartSec `fix/issue-53-hardening-tui-e2e`, derivada da `main` no commit `35964dc`.
- Terminal tmux com 80 colunas e 24 linhas.
- Podman 6.1.0 em modo rootless e rede `pasta`.
- Nmap 7.95 e Nuclei v3.4.10 executados em containers.
- Templates do Nuclei no commit `b98e6097cb84e73e7a480436062d685a8f898824`.
- Ollama local com `llama3.2:1b`.
- Alvo controlado: servidor HTTP preso a `127.0.0.1:38153`, acessado pelos scanners como `http://169.254.1.2:38153`.
- Configuracao e artefatos isolados por `XDG_CONFIG_HOME` temporario.

## Comando reproduzivel

```bash
./scripts/e2e_tui_local.sh
```

O roteiro dirige a TUI por teclado, abre e salva a nova tela de configuracao,
seleciona o modo automatico, executa os scanners reais, aguarda a tela
`Resultados 05/05`, exporta o relatorio e valida os artefatos com `jq` e `rg`.

## Resultado observado

```text
SmartSec / Configuracoes de IA / 01/05
Conexao principal                  Confiabilidade
Provedor: Ollama                   Tempo limite: 45 segundos
URL base: localhost:11434/v1       Retentativas: 2
Modelo: llama3.2:1b                Alternativa local: desativada
Descartar | Limpar campo           Salvar alteracoes
```

```text
SmartSec / Resultados / 05/05
0 criticas | 0 altas | 0 medias | 0 baixas | 11 informativas
Nmap: succeeded (6,5 s)
Nuclei: succeeded (27,8 s)
11 achados com source=Real
```

O arquivo `tui.stderr` ficou vazio. A auditoria JSON e o relatorio Markdown
foram criados. A comparacao de `podman ps -a` antes/depois nao encontrou nenhum
container `smartsec-*` residual.

## Assercoes automatizadas

- exatamente um registro de Nmap e um de Nuclei, ambos com `status=succeeded`;
- nenhum finding com origem diferente de `Real`;
- evidencia de todo achado Nuclei com template, matcher, endpoint, host, URL e tags;
- analise iniciada em portugues e sem termos de reclassificacao de severidade;
- nenhum campo bruto `request`, `response` ou `curl-command` nos artefatos;
- nenhuma ocorrencia de cabecalho de autorizacao, bearer token, API key,
  cookie de resposta ou query string com token/secret/password;
- relatorio Markdown exportado e nao vazio;
- ausencia de containers residuais;
- terminal e servidor local encerrados pelo trap, inclusive em caso de falha.

Durante a primeira homologacao, uma URL malformada emitida pelo Nuclei revelou
recursao no sanitizador e causou stack overflow no worker. A rotina passou a
sanitizar URLs invalidas sem chamar a si propria; um teste de regressao cobre
credenciais, query e fragmento nesse caso. A repeticao completa produziu os
resultados acima, sem erro no worker.
