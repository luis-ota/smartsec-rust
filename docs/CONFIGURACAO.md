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

### Cadastrar, conferir e remover a chave pela CLI

O caminho principal é o cofre do sistema, e o próprio SmartSec é a interface para
ele. Não é preciso `opencode auth export`, `auth.json` nem outra CLI:

```bash
smartsec auth set      # entrada oculta, sem eco no terminal
smartsec auth status   # provedor, modelo, tamanho e final mascarado
smartsec auth remove   # apaga a chave do cofre
```

`auth set` valida que a chave não está vazia, não tem quebra de linha e grava no
Secret Service via `keyring`. Em CI, a chave entra pela entrada padrão:

```bash
smartsec auth set --stdin < /run/secrets/smartsec-api-key
```

### Sessão SSH/TTY sem prompt gráfico

Em SSH ou TTY puro não existe janela para o `gcr-prompter`, e o
`Default keyring` fica bloqueado para sempre. O SmartSec usa o keyring
**Login** no Linux, que é o mesmo que o PAM desbloqueia. Para desbloquear:

```bash
read -rsp 'Senha do login/keyring: ' K; echo
printf '%s\n' "$K" | gnome-keyring-daemon --replace --unlock
unset K
smartsec auth status
```

Se o `auth status` continuar dizendo que o cofre está bloqueado, a senha do
keyring é diferente da senha de login; nesse caso use o override de sessão
abaixo ou recrie o keyring em um ambiente gráfico.

O `--stdin` é recusado quando a entrada é um terminal, justamente para não ecoar
a digitação. A chave não é aceita como argumento de linha de comando e nunca é
impressa inteira: `auth status` mostra apenas o tamanho e os últimos quatro
caracteres, e chaves com até quatro caracteres aparecem totalmente mascaradas.
O código de saída de `status` é `0` quando há chave utilizável (cofre ou override
de sessão), `1` quando não há chave e `2` quando o cofre está bloqueado ou
indisponível. `set` e `remove` retornam `0` em sucesso e `2` em falha.

Se o cofre estiver bloqueado ou indisponível, a mensagem pede para desbloquear o
Secret Service do sistema (por exemplo, gnome-keyring ou KWallet) e executar o
comando de novo. Nada é gravado no TOML em nenhum dos caminhos.

### Override de sessão/CI (`SMARTSEC_API_KEY`)

`SMARTSEC_API_KEY` existe **apenas** como override explícito de CI/sessão, não
como caminho principal. Quando o cofre do sistema está bloqueado ou não existe
(CI, container, TTY sem prompt gráfico), a chave pode vir da variável:

Prefira o cofre, inclusive na TUI:

```bash
smartsec auth set
smartsec
```

Em CI, a variável deve vir do secret do runner, nunca digitada no histórico do
shell:

```bash
# o runner define SMARTSEC_API_KEY a partir do secret
smartsec scan --target http://169.254.1.2:3000
```

Essa chave **não é gravada** no TOML nem no keyring: vale só para o processo.
Ela tem precedência sobre a chave do keyring e é removida do ambiente dos
processos filhos (Podman, `run_command` do agente e `git`), para não vazar para
os scanners. Na TUI, o resumo mostra `chave da sessão (SMARTSEC_API_KEY)`. Para
persistir, use `smartsec auth set` com o keyring desbloqueado.

## Arquivo de configuração TOML

O modelo comentado [`smartsec.example.toml`](../smartsec.example.toml) mostra o
schema mínimo: `target_url`, `active_tools`, `execution_type` e a tabela
`[llm]`. Regras:

- `--target` é sempre obrigatório na CLI; o `target_url` do arquivo é usado
  pela TUI e substituído pela CLI no headless.
- `--tools`, `--llm` e `--model` sobrescrevem os valores do arquivo.
- `provider` aceita o rótulo exibido na TUI (`llama.cpp`, `NVIDIA NIM`,
  `OpenAI`, `Personalizado`), os nomes canônicos (`LlamaCpp`, `NvidiaNim`,
  `OpenAI`, `Custom`) e as grafias da CLI, sem diferenciar caixa nem separador
  (`llama_cpp`, `nvidia nim`, `personalizado`). `ollama` e `Mock` continuam
  válidos como alias, para as configurações já gravadas.
- `base_url` e `model` ausentes assumem o padrão do provedor;
  `execution_type` ausente assume `Assisted`.
- `scan` headless sempre opera como Automático, independente de
  `execution_type`.
- `output_file` e `output_dir` definem o destino do relatório Markdown e do PDF
  (o PDF sai ao lado, com a extensão trocada); as flags
  `--output`/`--output-dir` têm precedência sobre o arquivo.

## Assistente de primeira execução

Na primeira execução — quando `~/.config/smartsec/config.toml` ainda não existe
— a TUI abre no assistente de configuração em vez de cair direto na tela de
análise. A partir da segunda execução o assistente só aparece por pedido
explícito: `Ctrl+P` → *Executar assistente de configuração*, ou o subcomando
`smartsec onboarding`.

São cinco passos, e a ordem responde ao que a máquina offers e ao que o provedor
exige:

1. **Ambiente.** Antes de perguntar qualquer coisa, o SmartSec verifica se há
   servidor de IA local respondendo (`localhost:8080` para llama.cpp,
   `localhost:11434` para Ollama), se o cofre de segredos do sistema está
   disponível e se o Podman está presente e rootless. Cada item diz o que foi
   achado e o que aquilo significa. A verificação acontece uma vez, em task
   assíncrona com timeout curto; nada é consultado durante a renderização de um
   quadro. Sem cofre de segredos, o caminho remoto é fechado na hora com aviso
   explícito, porque uma chave que não pode ser salva não sobrevive à próxima
   sessão.
2. **Provedor.** A escolha usa os mesmos campos, o mesmo rascunho e a mesma
   validação da tela `Configurar IA` — inclusive o botão para abri-la e ajustar
   o que falta.
3. **Credencial.** Só para provedor remoto, e mascarada na tela. A chave vai
   para o keyring; ela nunca passa pelo arquivo de configuração.
4. **Consentimento.** Só para provedor remoto. O texto diz o que sai da máquina:
   alvo, logs das ferramentas, achados com suas evidências e o código do projeto
   escolhido. Recusar não deixa o fluxo inválido: o assistente volta para o
   modelo local, apaga a credencial digitada e explica por quê (RNF10).
5. **Teste de conexão.** Opcional: uma chamada mínima a `{base_url}/models`, com
   o resultado em português e a causa acionável de uma falha (chave recusada,
   endpoint errado, limite de requisições, prazo esgotado).

Sair a qualquer momento — `Esc`, *Sair* ou *Voltar* até o início — não grava
nada: o rascunho volta ao que está em vigor. Uma gravação só acontece na última
etapa, depois de `LlmConfig::validate` aceitar a configuração inteira, então não
existe estado intermediário inválido no disco.

## Configuracao da IA na TUI

A tela `Configurar IA` agrupa os campos por proposito — *Quem responde*
(provedor, endereco, modelo e chave), *Seguranca e limites* (envio remoto, tempo
limite e tentativas), *Alternativa local* e *O que analisar* (pasta do projeto)
— e mostra somente os campos aplicaveis: provedores remotos exibem chave e
consentimento; o llama.cpp local os oculta. O rodape da tela explica o campo em
foco em linguagem simples, com um exemplo; campos vazios exibem o exemplo em
cinza e a linha `Se salvar:` resume o efeito do rascunho antes de gravar.

`Tab` percorre os campos e acoes, as setas andam na coluna (`↑`/`↓`) e trocam de
coluna (`←`/`→`), `Enter` abre o campo para digitar, troca o provedor ou aciona
a opcao em foco, `Espaco` alterna opcoes liga/desliga, `Esc` sai do campo em
edicao ou descarta o rascunho e `Ctrl+U` limpa o campo atual. Valores invalidos
mantem a tela aberta com uma mensagem que diz o que corrigir. Chaves ficam no
keyring do sistema e nunca sao gravadas no TOML. No Linux o keyring usa o
Secret Service (por exemplo, gnome-keyring ou KWallet), que precisa estar ativo
para salvar e ler chaves de provedores remotos. A evidencia visual do desenho
esta em `docs/evidence/tui-config-ia/`.

## Retentativas e limite de uso

`max_retries` é o número de tentativas **adicionais**. Nenhuma retentativa sai sem
esperar: um `Retry-After` do provedor tem precedência e, na ausência dele, o
SmartSec aplica backoff exponencial (500 ms, 1 s, 2 s, com jitter) porque reenviar
o mesmo payload no mesmo instante consome o orçamento de tokens por minuto que
acabou de estourar. Um `429` vira uma mensagem que diz o que fazer — aguardar o
período pedido, reduzir o payload ou usar o llama.cpp local — em vez de um `status
429` cru. Um `Retry-After` maior que o teto de espera não vira espera: a resposta
é imediata, para não passar do prazo da análise.

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

Para abrir a TUI direto nos resultados de um scan concluído, sem repetir a
varredura:

```bash
smartsec replay <SCAN_ID>
```

A tela reconstrói os achados e a linha do tempo das ações da IA a partir do log
estruturado. O RAG continua sob demanda e não altera o registro original.

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
llama.cpp local (`llama-server` na porta 8080) com o GGUF Llama 3.1 8B e o
checkout versionado em `~/nuclei-templates`. Os artefatos temporarios ficam no
caminho informado ao fim da execucao. A evidencia homologada desta mudanca esta em
[`docs/evidence/issue-53-tui-e2e.md`](evidence/issue-53-tui-e2e.md).

Para uma execucao real, a configuracao TOML pode definir `nuclei_templates_path` e
`nuclei_templates_commit`. O SmartSec rejeita o scan se o diretorio nao for um
checkout Git no commit esperado. A imagem usada e
`docker.io/projectdiscovery/nuclei@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb`.
