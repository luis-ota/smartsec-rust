# Estendendo as ferramentas do SmartSec

Este documento descreve o contrato de manifesto, os runners e parsers
registrados e o procedimento para adicionar uma ferramenta sem recompilar o
núcleo (RNF08).

## Visão geral

O núcleo do SmartSec não compara nomes de ferramentas com strings mágicas. Cada
ferramenta é descrita por um `ToolManifest` e registrada no `ToolRegistry`,
que resolve:

- o **runner**: como o manifesto vira um comando executado no Podman rootless;
- o **parser**: como a saída do runner vira achados estruturados.

O catálogo é montado com as ferramentas embutidas (Nmap, Nuclei, Nikto e ZAP) mais as
ferramentas declaradas na chave `[[tools]]` do arquivo de configuração TOML.
Ferramentas desabilitadas (`enabled = false`) são validadas, mas ficam fora do
catálogo exibido na CLI/TUI.

## Contrato do manifesto

Todos os campos são obrigatórios, exceto `enabled` (padrão `true`).

| Campo | Tipo | Descrição |
|---|---|---|
| `name` | string | Nome exibido e chave de seleção (`--tools`, TUI). Único no catálogo (comparação sem diferenciar maiúsculas). |
| `description` | string | Texto curto exibido na TUI. |
| `category` | string | Categoria livre (ex.: `RECON`, `DAST`). |
| `image` | string | Referência de imagem do container (`registry/nome:tag` ou `nome@sha256:<digest>`). Não pode conter espaços nem caracteres de controle e não pode começar com `-`, bloqueando injeção de opções do Podman como `--privileged` e `--volume`. |
| `version` | string | Versão da ferramenta, gravada no log estruturado (RNF09). |
| `runner` | string | Runner registrado que executa a ferramenta. |
| `parser` | string | Parser registrado que interpreta a saída. |
| `command_template` | lista de strings | Comando do container; nenhum item pode ser vazio, o primeiro item é o executável (não pode começar com `-`) e ao menos um argumento deve conter o marcador `{target}`. |
| `output_format` | string | Formato da saída, validado contra o parser: `xml` para `nmap-xml`, `jsonl` para `nuclei-jsonl`, `json` para `nikto-json` e `zap-json`, `text` para `generic-text`. |
| `enabled` | bool | Opcional. `false` mantém a ferramenta fora do catálogo. |

O alvo informado na CLI substitui exatamente o marcador `{target}`. Nenhum
shell é usado: cada item da lista vira um argumento literal do container.

## Runners registrados

| Runner | Comportamento |
|---|---|
| `nmap` | Execução real do Nmap com `-Pn -sT -sV -oX -`; comportamento e argumentos definidos pelo runner. |
| `nuclei` | Execução real do Nuclei com o plano validado pelo orquestrador e templates montados em somente leitura. |
| `generic` | Executa o `command_template` do manifesto no executor Podman rootless, sem privilégios e com rede `pasta`. |
| `zap` | Monta o plano de automação do ZAP em memória, monta-o em somente leitura e coleta o relatório gravado pelo container (ver a seção do ZAP). |

## Parsers registrados

| Parser | Comportamento |
|---|---|
| `nmap-xml` | Converte o XML do Nmap em achados rastreáveis. |
| `nuclei-jsonl` | Converte o JSONL do Nuclei em achados rastreáveis. |
| `nikto-json` | Converte o relatório JSON do Nikto em achados rastreáveis, preservando URL, método HTTP, referência e evidência. |
| `zap-json` | Converte o relatório `traditional-json` do ZAP em achados rastreáveis, preservando URL, método HTTP, referência, risco/confiança e evidência. |
| `generic-text` | Extrai achados informativos simples do texto, um por linha não vazia e não diagnóstica. |

## Ferramentas embutidas

| Ferramenta | Imagem e versão | Runner | Parser |
|---|---|---|---|
| Nmap | `docker.io/instrumentisto/nmap:7.95` (tag) | `nmap` | `nmap-xml` |
| Nuclei | `docker.io/projectdiscovery/nuclei@sha256:2a11…` (digest) | `nuclei` | `nuclei-jsonl` |
| Nikto | `docker.io/alpine/nikto:2.2.0@sha256:eb2fe882…` (digest), versão `2.1.6` | `generic` | `nikto-json` |
| ZAP | `ghcr.io/zaproxy/zaproxy:2.14.0@sha256:3280adc7…` (digest), versão `2.14.0` | `zap` | `zap-json` |

### Nikto

O Nikto é executado pelo runner `generic` a partir do `command_template`
embutido, com `output_format = "json"`. Dois detalhes do comportamento real do
scanner condicionam o comando e estão documentados com evidência em
`docs/evidence/issue-14-nikto.md`:

- o Nikto exige um arquivo de saída para `-Format json` e aborta com
  `+ ERROR: Output file format specified without a name` sem `-o`. A flag `-o -`
  faz o próprio scanner escrever no stdout, sem shell e sem arquivo, o que é
  compatível com o filesystem somente leitura do executor;
- `-ask no` é obrigatório. Sem ele o Nikto abre o prompt "submit this
  information to CIRT.net", cujo texto vaza para o stdout e corrompe o JSON.

O parser `nikto-json` preserva URL (reconstruída a partir do alvo e do caminho
relativo), método HTTP, referência (ID do Nikto e OSVDB) e evidência, sempre
passada por `utils::redaction`. O Nikto não emite campo de severidade: a
severidade vem da taxonomia de IDs do próprio scanner (faixas de `db_tests`,
`db_outdated`, `db_realms`, `db_server_msgs`, `db_httpoptions`, `db_embedded`) e
da presença de referência OSVDB.

Erros tratados como `failed` com mensagem acionável em pt-BR: JSON inválido,
stdout vazio, alvo sem servidor web (o Nikto termina com status 0 e reporta o
código interno `000029`) e exit status diferente de zero. Exit status e timeout
vêm do executor Podman e são preservados.

### ZAP

O ZAP é executado pelo runner `zap`, com `output_format = "json"`. Ele é o único
runner que **não** entrega a saída estruturada pelo stdout: o job `report` do
ZAP sempre acrescenta a extensão do template ao nome do arquivo e não existe
parâmetro de saída em stdout. Isso foi verificado executando o container contra
um alvo local; a evidência completa está em `docs/evidence/issue-28-zap.md`.

O runner `zap` portanto:

1. monta o plano de automação YAML **em memória**, com o alvo no contexto
   `default`, o job `spider`, `passiveScan-wait` e o job `report`;
2. grava o plano num diretório temporário do host e o monta em
   `/zap/automation` em **somente leitura**, como os templates do Nuclei;
3. monta um diretório de saída gravável em `/smartsec-out` e coleta o
   `zap-report.json` depois da execução e **antes** de remover o container.

O diretório de saída é criado pelo executor, vazio, com modo `0733`, no
`TMPDIR` do host, e é removido ao final. O modo `0733` é necessário porque, em
Podman rootless sem `keep-id`, o usuário do container é um *subuid* do host. O
volume é montado com `rw,noexec,nosuid,nodev` e é o **único** ponto de escrita
fora das tmpfs: o container continua `--read-only`, `--cap-drop all` e
`no-new-privileges`, sem shell, sem capacidade nova e sem nada executado no
host.

Duas particularidades da imagem condicionam o comando e só foram descobertas
executando:

- a imagem declara `ENTRYPOINT []` e `CMD ["bash"]`, então `podman create
  IMAGEM zap.sh …` executa `/zap/zap.sh` pelo `PATH`. O `zap.sh` da 2.14 não
  tem atalhos `-quickstart`/`-baseline`/`-full`;
- o `zap.sh` **ignora `JAVA_OPTS`**: ele calcula `-Xmx` a partir do
  `/proc/meminfo` do host e imprimiria `-Xmx3942m` numa máquina de 15 Gi. A
  única forma de limitar o heap é `-Xmx<N>m` como argumento único, e `-cmd` é
  obrigatório para o container encerrar.

Além disso, `HOME` precisa ser gravável: sem a tmpfs em `/home/zap`, o ZAP
aborta com `The home path is not writable: /home/zap/.ZAP/`.

O parser `zap-json` preserva URL, método HTTP, referência (`alertRef`,
`pluginid` e CWE), rótulo de risco e confiança e evidência mínima sanitizada.
A **severidade do ZAP é autoritativa** (TCC_SPEC §7) e vem do campo estruturado
`riskcode` do scanner (`0` informativa, `1` baixa, `2` média, `3` alta), sem
reinterpretar o texto do alerta. O template `traditional-json` não inclui
cabeçalhos nem corpos de requisição/resposta, e a sanitização remove query
strings e credenciais de qualquer campo que sobre.

Erros tratados como `failed` com mensagem acionável em pt-BR: JSON inválido,
stdout vazio, relatório sem site varrido, site sem alertas, artefato ausente,
exit status diferente de zero e timeout. Uma saída que não é relatório nunca é
lida como varredura limpa.

## Procedimento para registrar uma ferramenta por configuração

1. Escolha uma imagem de container que execute a ferramenta e fixe a versão.
2. Monte o comando completo (binário + argumentos) e use `{target}` no lugar
   do alvo. Use `runner = "generic"` e `parser = "generic-text"`.
3. Adicione o bloco `[[tools]]` ao arquivo TOML usado com `--config`.
4. Valide com uma execução controlada:

   ```bash
   smartsec tool ScannerWeb --target 169.254.1.2:3000 --config ./smartsec.toml
   ```

5. Confirme no log estruturado e no relatório que a ferramenta, a imagem e a
   versão aparecem corretamente e que os achados têm proveniência `real`.

Exemplo mínimo:

```toml
target_url = "http://169.254.1.2:3000"

[llm]
provider = "Ollama"

[[tools]]
name = "ScannerWeb"
description = "Scanner de servidores web"
category = "DAST"
image = "docker.io/exemplo/scanner-web:1.4.0"
version = "1.4.0"
runner = "generic"
parser = "generic-text"
command_template = ["scanner", "-u", "{target}"]
output_format = "text"
enabled = true
```

## Erros de configuração

A configuração é validada no carregamento e interrompe o fluxo com mensagem
acionável em pt-BR. Exemplos:

- ferramenta duplicada (mesmo nome de uma embutida ou de outra `[[tools]]`);
- campo obrigatório ausente: `a ferramenta 'ScannerWeb' não define o campo obrigatório 'version' em [[tools]]`;
- runner desconhecido: `a ferramenta 'ScannerWeb' usa o runner desconhecido 'foo'; runners registrados: nmap, nuclei, generic, zap`;
- parser desconhecido, com a lista de parsers registrados;
- `image` inválida: vazia, com espaços/caracteres de controle, iniciada por `-` ou fora do formato de referência;
- `command_template` com item vazio, primeiro item iniciado por `-` ou sem o marcador `{target}`;
- `output_format` incompatível com o parser escolhido;
- TOML malformado na seção `[[tools]]`.

## Adicionando um novo runner ou parser

Registrar uma ferramenta por configuração não exige recompilar, mas ela só pode
usar runners e parsers já registrados. Para criar um runner ou parser novo:

1. Implemente a execução no executor Podman rootless existente, sem comandos
   no host e sem mock no fluxo real.
2. Registre o identificador no `ToolRegistry` (`src/tools/registry.rs`) com o
   `RunnerKind`/`ParserKind` correspondente.
3. Ligue o parser ao pipeline em `Orchestrator::build_findings`.
4. Adicione testes cobrindo argumentos, falhas, timeout e parsing.
5. Atualize este documento, o `TCC_SPEC.md` e a matriz de rastreabilidade.

Limites de segurança: nenhuma ferramenta nova deve receber privilégios extras,
montar o socket do Podman, escrever fora do tmpfs ou ser executada fora do
container. Segredos nunca entram no manifesto nem no `command_template`.
