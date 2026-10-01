# Configuração

O arquivo TOML, a tela `Configurar IA` e o comportamento da TUI durante uma
execução.

Esta página saiu do [`README.md`](../README.md): são regras de uso que fazem
sentido ao configurar, não ao entender o que o projeto é. O modelo comentado
com schema mínimo está em [`smartsec.example.toml`](../smartsec.example.toml).

## Onde a configuração mora

| O quê | Onde |
|---|---|
| Opções da IA e do scan | `~/.config/smartsec/config.toml` |
| Chave de provedor remoto | **keyring do sistema** — nunca no TOML |
| Logs estruturados de cada execução | `~/.config/smartsec/scans/<scan_id>.json` |

A chave fora do TOML é deliberada: `llm.api_key` é `#[serde(skip)]`, então
mesmo alguém com acesso ao arquivo de configuração não lê a credencial dali.

## Arquivo de configuração TOML

O modelo comentado [`smartsec.example.toml`](../smartsec.example.toml) mostra o
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
- `output_file` e `output_dir` definem o destino do relatório Markdown e do PDF
  (o PDF sai ao lado, com a extensão trocada); as flags
  `--output`/`--output-dir` têm precedência sobre o arquivo.

## Configuracao da IA na TUI

A tela `Configurar IA` separa conexao principal de confiabilidade e mostra
somente os campos aplicaveis. Provedores remotos exibem chave e consentimento;
o Ollama local os oculta. `Tab` percorre os campos e acoes, `←`/`→` alteram
selecoes, `Espaco` alterna opcoes e `Ctrl+U` limpa o campo atual. Valores
invalidos mantem a tela aberta com uma mensagem acionavel. Chaves ficam no
keyring do sistema e nunca sao gravadas no TOML. No Linux o keyring usa o
Secret Service (por exemplo, gnome-keyring ou KWallet), que precisa estar
ativo para salvar e ler chaves de provedores remotos.

## Progresso, achados e ocorrencias na TUI

A TUI nao mostra progresso inventado. O catalogo de ferramentas ja aparece
pronto (ele vem do registry, nao de uma "deteccao"), o medidor da execucao
conta apenas ferramentas que o orquestrador ja encerrou e a tela de analise
acompanha a etapa real do pipeline com o tempo que a IA leva. Quando a analise
termina, os resultados abrem na hora.

Os achados criticos ficam no topo da lista, o painel anuncia quantos sao, e a
cor da severidade do scanner continua visivel mesmo na linha selecionada. O
detalhe do achado mostra a evidencia minima do scanner, o alvo, o instante da
deteccao e a origem do achado.

Falhas nao somem: a tela de Execucao e o resumo de Resultados listam cada
ocorrencia com a sua origem (ferramenta, auditoria, IA, executor, validacao,
exportacao). Avisos da IA, como a queda da LLM principal e o uso do modelo
local alternativo, aparecem como aviso, sem virar falha da varredura.

## Histórico de execuções

Cada execucao grava um registro JSON em `~/.config/smartsec/scans/<scan_id>.json`
com os metadados, as ferramentas executadas (incluindo o trace do Podman), os
achados, as contagens por severidade, a analise da IA e as decisoes. O registro
e sanitizado antes de ser gravado.

O `scan_id` tem o formato `scan_<nanos>` e nao e adivinhavel. Por isso o modo
headless imprime o identificador ao final da execucao, e a TUI abre a lista com
`h` ou pela paleta de comandos (`Ctrl+P`).

Regras de seguranca e de robustez:

- A consulta e **somente leitura**: nenhum artefato original e criado, reescrito
  ou removido ao listar ou abrir uma execucao.
- Um `scan_id` fora do padrao `scan_<nanos>` e recusado antes de tocar o disco.
  Como o padrao nao aceita `/` nem `.`, o identificador nunca resolve para fora
  de `~/.config/smartsec/scans/` — path traversal.
- Diretorio inexistente e diretorio vazio sao mensagens diferentes.
- Registros corrompidos ou incompletos aparecem como aviso na listagem em vez de
  sumirem em silencio; abre-los falha com mensagem acionavel em portugues.
- Registros gravados por versoes anteriores do formato, sem os campos mais
  novos, continuam legiveis.

Para ver o comportamento com um registro corrompido semeado de proposito:

```bash
printf '{quebrado' > ~/.config/smartsec/scans/scan_1757000000000000009.json
cargo run -- history
```

## E2E real da TUI

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
[`docs/evidence/issue-53-tui-e2e.md`](evidence/issue-53-tui-e2e.md).

Para uma execucao real, a configuracao TOML pode definir `nuclei_templates_path` e
`nuclei_templates_commit`. O SmartSec rejeita o scan se o diretorio nao for um
checkout Git no commit esperado. A imagem usada e
`docker.io/projectdiscovery/nuclei@sha256:2a11faa83464d769a888f1abb9396d5b4d8640619dfc6310086bf5c0d4003481`.
