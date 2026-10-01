# Evidência real — TruffleHog (issue #18)

Trabalho de campo anterior à implementação. Segue o método da issue #14
(Nikto): nada é codificado antes de ser executado de verdade no container com
as **exatas** flags do `PodmanExecutor` (`src/orchestrator/sandbox.rs`).

Repositório de teste sintético: `repo-teste/` (chave privada RSA gerada na hora,
`.env` e `creds.sh` com segredos obviamente falsos). Nenhum segredo real foi
usado em nenhum momento.

## Script de reprodução

`run-th.sh` reproduz literalmente o `podman create` do executor, trocando apenas
o `run --rm` (o executor faz `create` + `start --attach` + `rm`, o resultado é o
mesmo):

```sh
podman run --rm \
  --network pasta:--map-host-loopback=169.254.1.2 \
  --memory 512m --cpus 1 --pids-limit 256 \
  --cap-drop all --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m \
  --tmpfs /root/.config:rw,noexec,nosuid,nodev,size=16m \
  --volume $PWD/repo-teste:/alvo:ro \
  docker.io/trufflesecurity/trufflehog@sha256:52e67fef… <argumentos>
```

## Imagem e versão

| Item | Valor |
|---|---|
| Repositório | `docker.io/trufflesecurity/trufflehog` |
| Tag local | `latest` |
| Digest (manifest) | `sha256:52e67fef4d054ecff5c2ce4b4ae376626d1ef54aa0898b53cac19c25e92e14db` |
| `trufflehog --version` | `trufflehog 3.97.9` |
| Tamanho | 64,6 MB |

O digest é **multi-arch**: `podman run …trufflehog@sha256:52e67fef…` resolveu
localmente sem pull e reportou a mesma versão `3.97.9`, confirmando que a
referência por digest é a forma correta de fixar (RNF09).

## ACHADO 1 (crítico) — sem `--json` o segredo sai em claro no stdout

Este é o achado que determina o desenho da integração. Sem `--json`, o TruffleHog
imprime o **valor completo** do segredo como texto legível:

```console
$ ./run-th.sh --no-update --no-verification filesystem /alvo
Found unverified result 🐷🔑❓
Detector Type: PrivateKey
Decoder Type: PLAIN
Raw result: -----BEGIN RSA PRIVATE KEY-----
[MATERIAL DA CHAVE MASCARADO — 27 linhas de base64]
[… 24 linhas de material da chave …]
-----END RSA PRIVATE KEY-----
```

`--json` é, portanto, **obrigatório** e não uma escolha de formato. Mesmo no modo
JSON, os campos `Raw`, `RawV2` e `SecretParts` continuam carregando o segredo
completo (ver ACHADO 2) — o `--json` resolve a legibilidade, não a exposição.

## ACHADO 2 (crítico) — no modo JSON o segredo também está presente

Com `--json`, o stdout é **JSONL** (um objeto por linha, sem array), o que torna
a integração viável. Mas o objeto carrega o segredo em três lugares:

```json
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/alvo/id_rsa_teste","line":1}}},
 "SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem",
 "DetectorType":15,"DetectorName":"PrivateKey",
 "DetectorDescription":"Private keys are used for securely connecting…",
 "DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,
 "Raw":"-----BEGIN RSA PRIVATE KEY-----\nMIIE<MASCARADO>…\n-----END RSA PRIVATE KEY-----\n",
 "RawV2":"",
 "Redacted":"-----BEGIN RSA PRIVATE KEY-----\nMIIE<MASCARADO>",
 "ExtraData":{},"StructuredData":null,
 "SecretParts":{"token":"-----BEGIN RSA PRIVATE KEY-----\nMIIE<MASCARADO>…"}}
```

Consequência prática: **`Raw`, `RawV2` e `SecretParts` jamais podem entrar no
finding, no log estruturado, no relatório ou na evidência versionada.** O parser
tem de ser uma allow-list: só `DetectorName`, `Verified`, `SourceMetadata.Data`
(`Filesystem.file/line` ou `Git.file/line`) e a origem são lidos do objeto.

O campo `Redacted` do TruffleHog é insuficiente como fonte de evidência: trunca
no meio do segredo e não é estável entre versões.

## ACHADO 3 — `--no-update` é obrigatório, senão a execução inteira falha

A primeira execução do trabalho de campo **não produziu nenhuma saída**:

```console
$ ./run-th.sh --json --no-verification filesystem /alvo ; echo "EXIT=$?"
error: could not lock config file /root/.gitconfig: Read-only file system
… error occurred with trufflehog updater 🐷  {"error": "cannot move binary (exit status 1)"}
EXIT=1
```

O `--read-only` do executor torna `/root` imutável; o auto-updater do TruffleHog
tenta gravar o binário novo, falha e **aborta a varredura inteira** com exit 1
e stdout vazio. Com `--no-update` a mesma execução devolve exit 0 e o JSONL
correto. Sem essa flag, o SmartSec reportaria "nenhum segredo encontrado" para
uma varredura que na verdade nem rodou.

## ACHADO 4 — ruído `could not lock config file /root/.gitconfig` no stderr

A mesma trava do item anterior também emite, em **stderr**:

```
error: could not lock config file /root/.gitconfig: Read-only file system
```

É ruído benigno (a varredura segue e o resultado é idêntico), mas é confundido
com diagnóstico real. A correção é `HOME=/tmp`, que aponta para o tmpfs já
montado pelo executor:

```console
$ ./run-th-home.sh --no-update --json --no-verification filesystem /alvo
EXIT=0   # stderr sem nenhuma linha de lock
```

## ACHADO 5 — sem rede a verificação degrada em silêncio

A rede `pasta` é isolada para o host, mas o TruffleHog **tem** acesso de saída
(ele próprio clona repositórios remotos, ver ACHADO 7). O que muda é o resultado
da verificação. Comparando as mesmas execuções:

| Execução | `scan_duration` | `verification_caching` | stdout |
|---|---|---|---|
| com `--no-verification` | 10,2 ms | `Misses:0` | 1 achado, `Verified:false` |
| sem `--no-verification` | **3,58 s** | `Misses:3, VerificationTimeSpentMS:4339` | 1 achado, `Verified:false` |

Ou seja: **a verificação sai pela rede e, quando não consegue, rebaixa o achado
para `unverified` sem erro, sem aviso e sem código de saída diferente.** Não há
timeout nem falha visível — apenas 3,6 s gastos e um resultado menos
confiável. Isso é relevante para o relatório: um `Verified:false` não significa
"segredo inválido", pode significar "a rede não deixou verificar".

Como verificar exigiria enviar o segredo detectado ao endpoint do provedor de
cada detector, a integração **não habilita verificação por padrão**
(`--no-verification`). Está registrado como decisão pendente de review.

## ACHADO 6 — `--max-depth` é não monotônico e não serve para limitar a varredura

O requisito era limitar a varredura para não varrer a internet inteira. As flags
candidatas foram testadas no repositório de teste (1 e depois 2 commits):

| Comando | Achados |
|---|---|
| `git file:///alvo` (sem limite) | 1 |
| `git --max-depth=0 file:///alvo` | 1 |
| `git --max-depth=1 file:///alvo` | **0** |
| `git --max-depth=2 file:///alvo` | **0** |
| `git --max-depth=3 file:///alvo` | 1 |
| `git --max-depth=5 file:///alvo` | 1 |
| `git --since-commit=<primeiro commit> file:///alvo` | 0 |

`--max-depth=1` e `--max-depth=2` **suprimem o segredo real** mesmo estando
abaixo do número de commits. O resultado é reproduzível (3 execuções
consecutivas idênticas) e não é flutuação. `--since-commit` com o commit raiz
também apaga o achado.

**Decisão:** nenhuma flag de limitação de profundidade é usada. A contenção vem
de outro lugar, que é o que de fato restringe o escopo: (a) o alvo é sempre
explicitado pelo usuário e (b) para repositório local o alvo é montado
**somente leitura** em um ponto fixo do container, sem rede de saída livre para
varredura. Registrar `--max-depth` como armadilha conhecida evita que alguém o
"otimize" depois e passe a perder achados em silêncio.

## ACHADO 7 — subcomandos: qual serve para "repositório local ou remoto autorizado"

| Subcomando | Alvo | Comportamento real observado |
|---|---|---|
| `filesystem <dir>` | diretório local montado | funciona; 1 achado. **Não** é repositório git, não vê histórico |
| `git file://<dir>` | repositório git local montado | funciona; 1 achado, com `commit`, `email`, `repository`, `file`, `line` |
| `git <url>` | repositório remoto | funciona; **tem rede** na `pasta` |
| `git file://<dir não-git>` | diretório comum | **falha**: `fatal: '…' does not appear to be a git repository` (exit 0, stdout vazio) |
| `github --org=…` | GitHub | exige token de API; fora do escopo do TCC (credencial de terceiro) |

O subcomando `git` é o que atende ao critério de aceite: o mesmo argumento
aceita `file://` (repositório git local, montado `ro`) e uma URL remoto
autorizada. `filesystem` fica registrado como alternativa, mas perde o
histórico — e o histórico é justamente onde segredos Vazam.

Verificação empírica do caso remoto (URL do próprio projeto do TCC, repositório
público e já autorizado por ser o código do trabalho):

```console
$ ./run-th.sh --no-update --json --no-verification git https://github.com/luis-ota/smartsec-rust.git
{"level":"info-0",…,"msg":"scanning repo",…,"repo":"https://github.com/luis-ota/smartsec-rust.git"}
{"level":"info-0",…,"msg":"finished scanning","chunks":1855,"bytes":1339614,
 "verified_secrets":0,"unverified_secrets":5,"scan_duration":"5.978016111s"}
EXIT=0
```

## Comportamento de erro observado

| Cenário | exit | stdout | stderr |
|---|---|---|---|
| nenhum segredo encontrado | `0` | vazio | log `finished scanning` com `unverified_secrets:0` |
| alvo inexistente, **sem** `--fail-on-scan-errors` | `0` | vazio | `errors":["lstat /nao-existe: no such file or directory"]` |
| alvo inexistente, **com** `--fail-on-scan-errors` | `1` | vazio | `error running scan` + o mesmo `lstat` |
| segredo encontrado | `0` | 1 linha JSONL | log `finished scanning` |
| com `--fail` | `183` | JSONL | — |
| diretório não-git com `git file://` | `0` | vazio | `fatal: '…' does not appear to be a git repository` |
| sem `--no-update` | `1` | vazio | `error occurred with trufflehog updater` |

Três conclusões que viram contrato:

1. **Alvo inexistente sai com 0 sem `--fail-on-scan-errors`.** O SmartSec
   trataria "caminho errado" como "varredura limpa". A flag é obrigatória.
2. **`--fail` (exit 183) não pode ser usada**: transformaria "achou segredo" em
   "falha de execução", invertendo o sentido dos exit codes do SmartSec
   (`TCC_SPEC.md` §10).
3. **Diretório não-git com `git file://` sai com 0 e stdout vazio** — mesma
   armadilha do item 1. O SmartSec tem de dizer isso ao usuário, e o
   `--fail-on-scan-errors` sozinho não cobre esse caso, porque o erro fica só no
   stderr. O parser não pode assumir que "stdout vazio + exit 0" é "nada
   encontrado".

## Comando final validado

```sh
trufflehog --no-update --no-color --json --no-verification --fail-on-scan-errors \
           git file:///alvo
```

| Flag | Origem empírica |
|---|---|
| `--no-update` | ACHADO 3 — sem ela o executor aborta com exit 1 e stdout vazio sob `--read-only` |
| `--json` | ACHADO 1 — sem ela o segredo é impresso em claro no stdout |
| `--no-verification` | ACHADO 5 — verificação sai pela rede e degrada em silêncio; envia o segredo ao provedor |
| `--fail-on-scan-errors` | tabela de erro — sem ela alvo inexistente sai com 0 e parece limpo |
| `--no-color` | o executor não aloca TTY; sequências de cor no JSONL poluiriam a evidência |
| `git file://<mount>` | ACHADO 7 — único subcomando que atende repo local **e** remoto, e preserva histórico |

## Montagem somente leitura confirmada

O mount `ro` foi testado dentro do container, com a mesma flag `--read-only` do
executor:

```console
$ podman run --rm --read-only --tmpfs /tmp:rw,size=32m -v $PWD/repo-teste:/alvo:ro … \
    -c 'echo x > /alvo/.env'
sh: can't create /alvo/.env: Read-only file system
```

O repositório analisado não pode ser alterado pelo scanner, mesmo que o
TruffleHog tente.

## O que a integração encontrou executando o SmartSec de verdade

Os quatro pontos abaixo só apareceram quando o binário compilado rodou contra o
`fake_podman` com o JSONL real. Nenhum deles é visível lendo o código.

### 1. O segredo vazava no log estruturado

O `stdout` do container é persistido em `tools_executed[].stdout` do log
estruturado. Com o JSONL real, esse campo carregava o segredo de quatro formas:

```console
$ grep -o 'VALOR-DE-EXEMPLO[A-Z0-9-]*' smartsec/scans/*.json
smartsec/scans/scan_1790798211899117076.json:VALOR-DE-EXEMPLO-NAO-E-SEGREDO-0000000000
smartsec/scans/scan_1790798211899117076.json:VALOR-DE-EXEMPLO-NAO-E-SEGREDO-0000000000
```

As duas correções, ambas com teste:

- `utils::redaction` remove `Raw`, `RawV2`, `Redacted` e `SecretParts` de
  qualquer objeto que seja registro do TruffleHog (identificado pelos marcadores
  `DetectorName`/`SourceMetadata`). O filtro é específico da ferramenta: um
  campo `Raw` de outro scanner não é apagado, e há teste para isso.
- `sandbox::read_stream_live` passa a sanitizar cada linha antes de enviá-la ao
  sink. Sem isso o segredo aparecia **ao vivo na TUI e no headless**, porque o
  trace é empurrado para a interface enquanto o container ainda roda.

O parser já era seguro por allow-list (o `Raw` nem existe na estrutura
desserializada), mas a proteção do parser não bastava: o log estruturado
persistia o stdout **antes** de qualquer parser.

### 2. O ponto de montagem do container vazava para a evidência

O `file` do TruffleHog é o caminho **dentro** do container (`/alvo/config/app.env`),
porque o scanner só enxerga o repositório pelo mount. Copiado direto, o relatório
mostrava `/alvo/config/app.env`, um diretório que não existe para quem lê. O
parser reduz o prefixo de montagem e a evidência passa a trazer o caminho
relativo ao repositório.

### 3. Repetir `trufflehog` como primeiro argumento quebra a execução

O `command_template` do manifesto exige que o primeiro item seja o executável e
não comece com `-`. A tentativa natural, repetindo o nome do binário como o
Nikto faz, **não funciona**:

```console
$ ./run-th.sh trufflehog --no-update --json --no-verification git file:///alvo ; echo "EXIT=$?"
trufflehog: error: expected command but got "trufflehog", try --help
EXIT=1
```

O TruffleHog usa um parser de CLI que interpreta o primeiro token como
subcomando. A solução foi colocar o subcomando `git` na frente, que satisfaz o
manifesto e funciona — as flags globais são aceitas normalmente depois do
subcomando, com resultado idêntico ao validado.

### 4. Saída vazia é varredura limpa, e isso contraria a intuição

O parser foi escrito primeiro com a regra "stdout vazio é erro", por
paralelo com o Nikto. Os testes derrubaram a regra: com nenhum segredo
encontrado, o TruffleHog real sai com **exit 0 e stdout vazio**, e reportar
isso como erro transformaria um resultado legítimo em falha de execução. O que
distingue alvo inválido de varredura limpa é o `--fail-on-scan-errors`: alvo
inválido sai com status 1, e o executor prefixa a saída com `[ERRO]`. A
distinção é testada nos dois sentidos.

## Cobertura de teste

| Suíte | Testes | O que fixa |
|---|---:|---|
| `tools::trufflehog` | 6 | argv exato, digest fixado, ausência de metacaractere e de `:rw` |
| `tools::repository` | 9 | canonicalização, symlink, `..`, relativo, inexistente, arquivo, esquema remoto |
| `orchestrator::trufflehog_parser` | 17 | detector/arquivo/linha/verificação, vazamento, JSONL inválido, dedup |
| `utils::redaction` | 2 | remoção dos campos de valor e não-remoção de `Raw` alheio |
| `tests/trufflehog_integration` | 12 | fluxo ponta a ponta com `fake_podman`, mount `:ro`, segredo ausente de todo artefato |

O teste que fecha a issue é
`o_valor_do_segredo_emitido_pelo_scanner_nao_sobrevive_em_nenhum_artefato`: ele
faz o scanner emitir um JSONL **com o segredo plantado** e verifica log
estruturado, relatório, stdout, stderr e log de chamadas do Podman.
