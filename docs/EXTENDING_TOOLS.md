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

O catálogo é montado com as ferramentas embutidas (Nmap, Nuclei, Nikto, SQLMap, TruffleHog
e ZAP) mais as
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
| `output_format` | string | Formato da saída, validado contra o parser: `xml` para `nmap-xml`, `jsonl` para `nuclei-jsonl` e `trufflehog-jsonl`, `json` para `nikto-json` e `zap-json`, `text` para `sqlmap-text` e `generic-text`. |
| `enabled` | bool | Opcional. `false` mantém a ferramenta fora do catálogo. |

O alvo informado na CLI substitui exatamente o marcador `{target}`. Nenhum
shell é usado: cada item da lista vira um argumento literal do container.

## Runners registrados

| Runner | Comportamento |
|---|---|
| `nmap` | Execução real do Nmap com `-Pn -sT -sV -oX -`; comportamento e argumentos definidos pelo runner. |
| `nuclei` | Execução real do Nuclei com o plano validado pelo orquestrador e templates montados em somente leitura. |
| `generic` | Executa o `command_template` do manifesto no executor Podman rootless, sem privilégios e com rede `pasta`. |
| `repository` | Alvo **é um repositório**, não um host. Canonicaliza o diretório e o monta em somente leitura; URI remota autorizada é repassada sem mount. Ver [Runner `repository`](#runner-repository). |
| `zap` | Monta o plano de automação do ZAP em memória, monta-o em somente leitura e coleta o relatório gravado pelo container (ver a seção do ZAP). |

## Parsers registrados

| Parser | Comportamento |
|---|---|
| `nmap-xml` | Converte o XML do Nmap em achados rastreáveis. |
| `nuclei-jsonl` | Converte o JSONL do Nuclei em achados rastreáveis. |
| `nikto-json` | Converte o relatório JSON do Nikto em achados rastreáveis, preservando URL, método HTTP, referência e evidência. |
| `sqlmap-text` | Converte o texto do SQLMap em achados rastreáveis, preservando parâmetro, método HTTP, tipo e título da injeção confirmada. |
| `trufflehog-jsonl` | Converte o JSONL do TruffleHog em achados rastreáveis, preservando detector, arquivo, linha e verificação, **sem o valor do segredo**. |
| `zap-json` | Converte o relatório `traditional-json` do ZAP em achados rastreáveis, preservando URL, método HTTP, referência, risco/confiança e evidência. |
| `generic-text` | Extrai achados informativos simples do texto, um por linha não vazia e não diagnóstica. |

## Ferramentas embutidas

| Ferramenta | Imagem e versão | Runner | Parser |
|---|---|---|---|
| Nmap | `docker.io/instrumentisto/nmap:7.95` (tag) | `nmap` | `nmap-xml` |
| Nuclei | `docker.io/projectdiscovery/nuclei@sha256:2a11…` (digest) | `nuclei` | `nuclei-jsonl` |
| Nikto | `docker.io/alpine/nikto:2.2.0@sha256:eb2fe882…` (digest), versão `2.1.6` | `generic` | `nikto-json` |
| SQLMap | `docker.io/parrotsec/sqlmap:7.3@sha256:31bb35cd…` (digest), versão `1.10.4` | `generic` | `sqlmap-text` |
| TruffleHog | `docker.io/trufflesecurity/trufflehog@sha256:52e67fef…` (digest), versão `3.97.9` | `repository` | `trufflehog-jsonl` |
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

### SQLMap

O SQLMap é executado pelo runner `generic` a partir do `command_template`
embutido, com `output_format = "text"`. O SQLMap não tem modo JSON, e três
comportamentos seus, medidos em container, condicionam o comando. Todos estão
documentados com evidência em `docs/evidence/issue-15-sqlmap.md`.

- `--batch` é obrigatório. Sem ele o SQLMap bloqueia em `_input()` esperando o
  prompt "Do you want to reduce the number of requests? [Y/n]" (medido: 45 s
  sem término contra 3 s com a flag). Quando o stdin não é um terminal o
  scanner adivinha o default, mas isso é acidental e não determinístico.
- `--answers=exploit=N,...` é o que impede o *takeover*. Em `--batch` o default
  de "do you want to exploit this SQL injection?" é `Y`, e o `Y` faz o scanner
  sair do escopo da varredura e enumerar banco, tabelas e colunas do alvo.
- `--technique=BEUT` limita a agressividade: o default `BEUSTQ` inclui `S`
  (stacked queries) e `Q` (inline queries), que executam statements
  adicionais no banco do alvo. `--level=2`, `--risk=2`, `--threads=1`,
  `--timeout=10`, `--retries=1` e `--time-sec=3` limitam carga e tempo
  (medido: 43–47 s sem limites contra 5–12 s com eles, dentro do timeout de
  15 min do executor).

O resultado útil vem do **stdout**, e não do arquivo `--output-dir`: verificado
que o arquivo `log` do SQLMap contém exatamente o mesmo bloco `Parameter:` /
`Type:` / `Title:` que o stdout. O tmpfs `/tmp` do container é destruído no fim
da execução, e o `PodmanExecutor` só captura stdout, então ler o arquivo exigiria
montar volume — que é justamente onde o `target.txt` do SQLMap gravaria a query
string crua do alvo. `--output-dir=/tmp` mantém o log e a sessão no tmpfs
efêmero; sem a flag o scanner tenta `$HOME/.local/share/sqlmap`, que é somente
leitura.

O parser `sqlmap-text` preserva parâmetro, método HTTP, `Type` e `Title`, que é
a taxonomia do próprio scanner sobre a injeção confirmada, e descarta o
`Payload:` — um fragmento com forma de query string, escrito incondicionalmente
pelo scanner e que a regra de sanitização do projeto proíbe em finding. A
severidade vem dessa mesma taxonomia de tipos (`error-based` e `UNION query`
em ALTA, `stacked queries` em CRÍTICA, o restante em MÉDIA).

Duas particularidades do formato condicionam a leitura e foram encontradas
executando: um `Parameter:` abre um **grupo de técnicas**, e cada `Type:` dentro
do grupo é um ponto de injeção distinto; e o SQLMap termina com status `0` em
**todos** os cenários, inclusive alvo inalcançável e URL inválida, com o `stderr`
vazio. Por isso o parser lê os diagnósticos do stdout.

Erros tratados como `failed` com mensagem acionável em pt-BR: alvo inalcançável,
URL inválida, bloco de injeção sem `Type:`, stdout vazio, saída não reconhecida
e exit status diferente de zero. Não encontrar parâmetros injetáveis é resultado
legítimo e vira varredura limpa, não erro — ainda que o SQLMap não distinga
"sem parâmetro" de "sem injeção". Exit status e timeout vêm do executor Podman e
são preservados.
### Runner `repository`

O runner `repository` existe porque o alvo de uma ferramenta de segredos **não é
um host de rede**: é um repositório, e o executor precisa montar um diretório do
host dentro do container. O runner `generic` não recebe mount algum, então não
atende a esse caso.

O runner decide entre duas formas, ambas com autorização explícita do usuário:

| Alvo | Resolução | Mount |
|---|---|---|
| Caminho absoluto de diretório | Canonicalizado e resolvido com o sandbox de `code_agent::workspace` | `ro` em `/alvo` |
| URI `https://`/`http://` de repositório autorizado | Repassada ao subcomando `git` do TruffleHog | nenhum |

O alvo entra no comando do scanner apenas como `file:///alvo` (local) ou como a
URI remota. **O caminho do host nunca aparece no comando**: ele viaja pelo
`--volume` do executor, que sempre acrescenta `:ro`.

A validação do caminho é deliberadamente estrita, e cada recusa tem motivo
mensurável:

- caminho relativo é recusado (`Workspace` exige raiz explícita);
- `..` é recusado explicitamente. Canonicalizar sozinho resolveria
  `/repo/../..` para `/tmp` e montaria um diretório que o usuário não pediu;
- diretório inexistente é recusado **antes** do container, porque o
  `trufflehog git` sobre um alvo que não é repositório git termina com exit 0 e
  stdout vazio;
- esquema remoto não suportado (`ssh://`, forma scp-like `git@host:org/repo`) é
  recusado, porque a validação de alvo da CLI já não os aceita e repassá-los
  produziria um alvo que não sai da validação.

A canonicalização reaproveita `code_agent::workspace`, que já recusa `..`,
caminho absoluto fora da raiz e symlink que escapa. Reescrever essa lógica
seria uma segunda implementação de uma garantia de segurança.

### TruffleHog

O TruffleHog entra no portfólio real com imagem fixada por digest e runner
`repository`. Sete detalhes do comportamento real do scanner condicionam o
comando e o parser, todos medidos em container e documentados em
`docs/evidence/issue-18-trufflehog.md`:

- **`--json` é obrigatório.** Sem ele o TruffleHog imprime o valor completo do
  segredo em texto legível no stdout (`Found unverified result … Raw result:
  -----BEGIN RSA PRIVATE KEY----- …`). Não é escolha de formato: é a condição
  para a integração existir.
- **`--json` não basta para mascarar.** O registro JSONL carrega o segredo em
  `Raw`, `RawV2`, `Redacted` e `SecretParts`. O parser é uma **allow-list**:
  esses campos não existem na estrutura desserializada, então não há como
  alcançarem um finding, um log ou a evidência versionada. A redaction de
  `utils::redaction` também os remove, porque o stdout do container é persistido
  no log estruturado **antes** de qualquer parser rodar.
- **`--no-update` é obrigatório.** Sem ele o auto-updater tenta gravar o binário
  novo sob o `--read-only` do executor, falha com `cannot move binary (exit
  status 1)` e aborta a varredura inteira com stdout vazio — o SmartSec
  reportaria "nenhum segredo encontrado" para uma varredura que não rodou.
- **`--fail-on-scan-errors` é obrigatório.** Sem ele, alvo inexistente termina
  com exit 0 e stdout vazio, e o erro fica só no stderr.
- **A verificação remota fica desligada.** Ela sai pela rede para o endpoint do
  provedor de cada detector **enviando o segredo detectado**, e degrada em
  silêncio quando a rede não responde: medido, 3,58 s e 3 tentativas a mais, com
  o achado rebaixado para `unverified` e nenhum erro reportado. A decisão está
  registrada para review.
- **Não há flag de limitação de profundidade.** `--max-depth=1` e `--max-depth=2`
  suprimem achados reais de forma reprodutível sobre um repositório de 2
  commits. O escopo é limitado pelo alvo explícito e pelo mount somente leitura.
- **O subcomando `git` abre a lista de argumentos.** Repetir `trufflehog` como
  primeiro item quebra a execução com `expected command but got "trufflehog"`.

O parser `trufflehog-jsonl` preserva detector, arquivo, linha, commit e
verificação, e reduz o prefixo de montagem (`/alvo/`) para que a evidência
mostre o caminho relativo ao repositório. O TruffleHog não emite severidade: ela
vem do estado de verificação publicado pelo scanner (`High` para confirmado,
`Medium` para detectado e não validado). Um `Verified: false` **não** significa
segredo inválido — com `--no-verification` é o resultado esperado para todo
achado, e o texto do relatório diz isso.

Saída vazia com exit status 0 é varredura limpa, não erro: nenhum segredo
encontrado não emite registro. O que separa alvo inválido de varredura limpa é o
`--fail-on-scan-errors`, que faz o container encerrar com status 1. Registro
JSONL malformado, saída diagnóstica (`[ERRO]`) e exit status diferente de zero
são tratados como `failed` com mensagem acionável em pt-BR.
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

### A tmpfs do host é verificada, não presumida

O `TMPDIR` é herdado do ambiente, então "o diretório temporário está em tmpfs"
não vale como construção do código: basta uma máquina — ou um runner de CI —
com `TMPDIR` apontando para um diretório comum em disco, e o mesmo código passa
a montar em bind mount um diretório persistente, gravando o relatório do scanner
fora da regra de isolamento do `TCC_SPEC.md`, sem nenhum sinal.

Por isso `WritableOutput::new` (e o diretório do plano de automação, que é a
configuração temporária da execução) **verificam** a condição antes de gravar:

- o tipo do filesystem vem de `/proc/self/mountinfo`, com o ponto de montagem
  **mais específico** que contém o caminho (`std::fs::metadata` não serve: devolve
  modo e dono, não o tipo do filesystem, e exigiria `libc`);
- o caminho é canonicalizado, então um `TMPDIR` que é symlink para disco é
  avaliado no destino real;
- só `tmpfs` é aceito. `overlay` **não** é aceito: é a camada copy-on-write do
  container e o dado gravado nela vive no diretório superior, em disco do host —
  aceitá-la seria aceitar escrita em disco com outro nome;
- sem `tmpfs`, sem tabela legível, ou sem conseguir identificar o ponto de
  montagem, a **execução falha** com mensagem acionável em pt-BR. Não existe
  caminho de degradação para escrita fora da regra.

A mensagem tem o formato do projeto (caminho, o que foi encontrado, o que era
esperado, o que fazer):

```
o diretório de escrita efêmera '/var/lib/smartsec-tmp' está no filesystem 'btrfs',
e a regra de isolamento do SmartSec exige 'tmpfs'; a execução foi interrompida
para não gravar a configuração temporária e o relatório do scanner fora da
tmpfs. Ajuste o ambiente: monte uma tmpfs (por exemplo
`sudo mount -t tmpfs -o size=512m tmpfs /var/tmp/smartsec`) e aponte a variável
TMPDIR para ela antes de rodar a varredura. Um 'overlay' não é aceito: a camada
copy-on-write do container grava em disco do host.
```

Uma ferramenta nova que grave no host não precisa reimplementar isso: passa por
`WritableOutput::new` e herda a verificação. O tipo de filesystem é injetável
(`tmpfs::FilesystemProbe`), o que permite testar o caminho negativo — diretório
em disco comum precisa falhar — sem depender da máquina de teste.

Limitações conhecidas, documentadas em `src/orchestrator/tmpfs.rs`: a tabela
lida é a do namespace de montagem do processo (o Podman rootless não cria um
namespace próprio para o processo do host, e o bind mount referencia o mesmo
inode do host); um symlink trocado entre a verificação e a criação ficaria fora
do alcance (TOCTOU que exige escrita concorrente no `TMPDIR`); e kernels sem
`/proc/self/mountinfo` legível fazem a execução falhar, em vez de assumir
`tmpfs`.

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
- campo obrigatório ausente: `a ferramenta 'ZAP' não define o campo obrigatório 'version' em [[tools]]`;
- runner desconhecido: `a ferramenta 'ZAP' usa o runner desconhecido 'foo'; runners registrados: nmap, nuclei, generic, repository`;
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

Uma ferramenta que precise ler um diretório do host deve usar o runner
`repository`, que monta o alvo em somente leitura. Nenhuma ferramenta pode
montar o alvo para escrita, receber o resultado da varredura por volume ou
escrever no repositório analisado: o executor acrescenta `:ro` a todo volume, e
a regra do `TCC_SPEC.md` §7 é explícita.
