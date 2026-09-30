# Evidência real — SQLMap (issue #15)

Escopo: validação do comportamento do SQLMap dentro do executor Podman rootless
antes de fixar o `command_template` embutido e o parser `sqlmap-text`. Nenhuma
flag deste documento foi escolhida por suposição: todas foram medidas em
container antes de entrar no código.

Alvo: servidores HTTP locais em `127.0.0.1`, publicados no container pela rede
`pasta` como `169.254.1.2`. Nenhum alvo externo foi escaneado.

| Alvo | O que é |
|---|---|
| `http://169.254.1.2:3000` | `python3 -m http.server` servindo um HTML estático: sem parâmetro e sem SQLi |
| `http://169.254.1.2:3100/item?id=1` | servidor HTTP local **deliberadamente vulnerável** (SQLite, concatenação de string em `?id=`) |
| `http://169.254.1.2:9999/item?id=1` | porta fechada: alvo inexistente |

Confirmação do alvo vulnerável, direto no host e sem container:

```
$ curl -s 'http://127.0.0.1:3100/item?id=1'
<html><body><p>alice</p></body></html>
$ curl -s "http://127.0.0.1:3100/item?id=1'"
<html><body><p>erro: unrecognized token: "'"</p></body></html>
$ curl -s 'http://127.0.0.1:3100/item?id=1 UNION SELECT nome FROM usuarios'
<html><body><p>alice; bob; carla</p></body></html>
```

## Imagem avaliada

| Imagem | Versão do SQLMap | Resultado |
|---|---|---|
| `docker.io/library/sqlmap` | — | acesso negado no registro; repositório inexistente |
| `docker.io/jaeles-project/sqlmap` | — | acesso negado no registro; repositório inexistente |
| `docker.io/insecureproject/sqlmap` | — | acesso negado no registro; repositório inexistente |
| `docker.io/googlesky/sqlmap:latest-alpine` | — | funciona fora do sandbox, mas falha no executor: `exit 2` em 1 s com `error: Failed to initialize cache at /root/.cache/uv`. O `ENTRYPOINT` é `uv run sqlmap-dev/sqlmap.py` e o `--read-only` bloqueia o cache do `uv`, para o qual o executor não monta tmpfs |
| `docker.io/secsi/sqlmap:1.10` | `1.10#stable` | funciona (achou a injeção em 7 s) e ocupa 59 MB, mas traz um SQLMap **anterior**, e pertence ao mesmo mantenedor cuja `secsi/nikto` já foi reprovada na issue #14 (`Required module not found: XML::Writer`) |
| `docker.io/parrotsec/sqlmap:7.3` | `1.10.4#stable` | **escolhida**: imagem oficial do Parrot Security Project, tag versionada, multi-arch, construída em 2026-08-17, `ENTRYPOINT ["sqlmap"]` limpo e SQLMap mais atual entre as candidatas |

Imagem fixada por digest:

```
docker.io/parrotsec/sqlmap:7.3@sha256:31bb35cd9fdc8c00d3673d26c48a59d2d8ea3c4955c252fb5dee2f96992b4596
```

Versão reportada pela própria imagem:

```
$ podman run --rm --network none --entrypoint sqlmap docker.io/parrotsec/sqlmap:7.3 --version
1.10.4#stable
```

No código da imagem, `VERSION = "1.10.4.0"` e `TYPE = "stable"`, o que
corresponde a `SQLMAP_VERSION = "1.10.4"`.

Custo de disco: 704 MB descomprimido contra 59 MB da `secsi`. Registrado como
ponto de revisão no PR.

## Descobertas que só apareceram executando

### 1. `--batch` é obrigatório: sem ele o SQLMap trava

Medido com TTY real (`pty.openpty()`), porque é esse o caso em que o prompt
interrompe de fato. Mesmo alvo, mesmo sandbox, mudando **apenas** `--batch`:

```
############ SEM --batch, com TTY ############
RESULTADO: TRAVADO por 45s (ainda rodando apos 45s)
--- ultimas linhas ---
[19:12:54] [INFO] testing 'Oracle AND time-based blind (query SLEEP)'
it is recommended to perform only basic UNION tests if there is not at least one
other (potential) technique found. Do you want to reduce the number of requests? [Y/n]

############ COM --batch, com TTY ############
RESULTADO: terminou em 3s exit=0
```

Causa, no fonte da imagem (`lib/core/common.py`, `readInput`):

```python
if retVal is None:
    if checkBatch and conf.get("batch") or any(conf.get(_) for _ in ("api", "nonInteractive")):
        dataToStdout("%s%s\n" % (message, options), forceOutput=not kb.wizardMode, bold=True)
        debugMsg = "used the default behavior, running in batch mode"
        retVal = default
    else:
        ...
        retVal = _input()          # bloqueia
```

Complemento observado, e que motivou a decisão: quando o stdin **não** é um TTY
(`/dev/null`, que é o que o `PodmanExecutor` faz com `Stdio::null()`, ou um
pipe) o `_input()` não bloqueia, e o scanner **adivinha o default
silenciosamente**. Isso é acidental, não determinístico. `--batch` é a garantia
de que nenhuma pergunta chega a ler entrada.

`--batch` não remove o texto do prompt do stdout, e o parser precisa ignorá-lo:

```
[1/1] URL:
GET http://169.254.1.2:3100/item?id=1
do you want to test this URL? [Y/n/q]
> Y
```

### 2. `--batch` sozinho responde `Y` e o SQLMap ataca o banco

Este é o achado de maior impacto. No bloco de resultado, com `--batch` e **sem**
`--answers`, o default do SQLMap para a pergunta final é `Y`:

```
sqlmap identified the following injection point(s) with a total of 51 HTTP(s) requests:
---
Parameter: id (GET)
    ...
---
do you want to exploit this SQL injection? [Y/n] Y          <-- default do batch
[19:14:48] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
```

O `Y` dispara *takeover*: o SQLMap passa a enumerar banco, tabelas e colunas.
Para uma ferramenta de varredura isso é agressividade desnecessária e fora do
escopo de "achar SQL injection". A correção é responder `N` explicitamente com
`--answers`, e ela é verificável:

```
---                                        (sem --answers)
do you want to exploit this SQL injection? [Y/n] Y

---                                        (com --answers=exploit=N,...)
do you want to exploit this SQL injection? [Y/n] N
```

### 3. Onde fica a saída útil: o stdout, e o arquivo é dispensável

O SQLMap grava log, sessão e CSV em arquivo. O `PodmanExecutor` só captura
stdout (`podman_output` em `src/orchestrator/pipeline.rs` usa `result.stdout`) e
o tmpfs `/tmp` é destruído no fim da execução. Medindo o que o scanner escreve,
com um volume extra **apenas para investigação**:

```
751    /sqlout/sq/169.254.1.2/log
8192   /sqlout/sq/169.254.1.2/session.sqlite
146    /sqlout/sq/169.254.1.2/target.txt
94     /sqlout/sq/results-09302026_0716pm.csv
```

O arquivo `log` contém **exatamente** o mesmo bloco que o stdout, e isso foi
verificado na mesma execução que o gerou (`grep -c "Parameter: id" stdout.txt` →
`1`). **O parsing do stdout é equivalente ao parsing do arquivo.**

O arquivo é ainda a opção *menos* segura:

- `target.txt` grava a linha de comando completa, com a query string crua do
  alvo (`http://169.254.1.2:3100/item?id=1`): é justamente o lugar onde a query
  string apareceria;
- `session.sqlite` é um cache binário de 8 KB;
- com `--read-only` e sem volume, `/tmp` é tmpfs efêmero: o arquivo não
  sobrevive ao fim do container, e o executor não monta volume para ele.

Limitação real, registrada: o SQLMap **não tem modo JSON**. O parser trabalha
sobre texto. Isso está no PR como decisão a revisar.

### 4. O formato do bloco: um `Parameter:` vale para vários `Type:`

Comportamento do stdout que não é óbvio pela leitura do código: o SQLMap escreve
o parâmetro **uma vez** e lista em seguida vários conjuntos `Type:`/`Title:`/
`Payload:`. Cada `Type:` é um ponto de injeção **distinto** que herda o
parâmetro corrente:

```
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1612=1612

    Type: time-based blind
    Title: SQLite > 2.0 AND time-based blind (heavy query)
    Payload: id=1 AND 4608=LIKE(CHAR(65,...),UPPER(HEX(RANDOMBLOB(300000000/2))))

    Type: UNION query
    Title: Generic UNION query (NULL) - 1 column
    Payload: id=1 UNION ALL SELECT CHAR(113,...)-- risT
```

Ler `Parameter:` como "abre um achado" perde dois dos três pontos e ainda
sobrescreve `Type` e `Title` do ponto anterior. Um segundo `Parameter:`, separado
por `---`, reinicia o grupo quando mais de um parâmetro é vulnerável.

### 5. O SQLMap termina com exit `0` em todos os cenários

Medido com os mesmos limites e o mesmo sandbox:

| Cenário | exit | Diagnóstico no stdout |
|---|---:|---|
| injeção confirmada | `0` | `sqlmap identified the following injection point(s) with a total of 49 HTTP(s) requests:` + bloco `Parameter:`/`Type:`/`Title:` |
| alvo sem SQLi | `0` | `[ERROR] all tested parameters do not appear to be injectable.` |
| alvo sem parâmetro | `0` | a mesma linha de "não injetável" |
| porta fechada | `0` | `[CRITICAL] unable to connect to the target URL ('Connection refused'). sqlmap is going to retry the request(s)` e depois `[ERROR] unable to connect to the target URL ('Connection refused'), skipping to the next target` |
| URL inválida (`ftp://`) | `0` | `[ERROR] invalid target URL, skipping to the next target` |
| `stderr` | — | **vazio em todos os cenários** |

O exit status não carrega informação de erro, e o `stderr` está sempre vazio: o
diagnóstico chega ao parser pelo stdout, com status `succeeded`. O parser
**precisa** ler os diagnósticos do stdout.

Dois detalhes que só apareceram executando:

- a mesma mensagem aparece como `[ERROR]` ou `[CRITICAL]` dependendo do modo
  (TTY ou pipe), na mesma versão. O parser casa pelo **texto**, nunca pelo
  prefixo de nível;
- "sem parâmetro" e "sem injeção" produzem a **mesma** linha `all tested
  parameters do not appear to be injectable`. O SQLMap não distingue os dois
  casos, e a varredura sem parâmetro é tratada como varredura limpa.

### 6. `/root/.local/share/sqlmap` é somente leitura

```
[19:16:37] [WARNING] unable to create history directory '/root/.local/share/sqlmap/history'
([Errno 30] Read-only file system: '/root/.local/share/sqlmap').
Using temporary directory '/tmp/sqlmaphistorygr_tis5s' instead
```

Ruído benigno, e `--output-dir=/tmp` evita o caminho altogether.

### 7. A mensagem de erro seria redigida inteira pela sanitização

Achado de interação entre o texto do SQLMap e `utils::redaction`. A linha
`[CRITICAL]` que precede o erro contém a frase
`sqlmap is going to retry the request(s)`, e `redaction.rs` trata a palavra
`request` como chave de corpo HTTP, o que substitui a linha inteira por
`[REDACTED]` — escondendo do operador o diagnóstico real.

Por isso o parser usa a **última** linha que casa com o marcador, remove os
sufixos conhecidos do SQLMap (`, skipping to the next target` e
`. sqlmap is going to retry the request(s)`) e só então sanitiza. Se ainda
assim a mensagem inteira for redigida, o erro mantém um texto genérico em
pt-BR dizendo que o diagnóstico foi omitido pela sanitização, para que a falha
nunca vire silêncio.

## Comando final validado

Executado com as flags exatas do `PodmanExecutor`: `--network
pasta:--map-host-loopback=169.254.1.2`, `--memory 512m`, `--cpus 1`,
`--pids-limit 256`, `--cap-drop all`, `--security-opt no-new-privileges`,
`--read-only`, tmpfs `/tmp` (128 MB) e `/root/.config` (16 MB).

```bash
podman run --rm -i \
  --network "pasta:--map-host-loopback=169.254.1.2" \
  --memory 512m --cpus 1 --pids-limit 256 \
  --cap-drop all --security-opt no-new-privileges --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m \
  --tmpfs /root/.config:rw,noexec,nosuid,nodev,size=16m \
  docker.io/parrotsec/sqlmap:7.3@sha256:31bb35cd9fdc8c00d3673d26c48a59d2d8ea3c4955c252fb5dee2f96992b4596 \
  sqlmap --batch --answers 'exploit=N,keep testing=N,reduce the number of requests=Y,proceed=C' \
    --disable-coloring --flush-session \
    --technique=BEUT --level=2 --risk=2 --threads=1 \
    --timeout=10 --retries=1 --time-sec=3 \
    --output-dir=/tmp \
    -u 'http://169.254.1.2:3100/item?id=1' \
  < /dev/null
```

A imagem declara `ENTRYPOINT ["sqlmap"]`, e o executor monta
`podman create … IMAGEM <argumentos>`. Repetir `sqlmap` como primeiro item
deixa o comando explícito, como já ocorre com Nmap, Nuclei e Nikto; no container
`sqlmap --version` e `--version` produzem a mesma saída.

### Efeito dos limites de agressividade (medido)

| Configuração | Requisições HTTP | Duração | Técnicas executadas |
|---|---:|---:|---|
| sem limites (default `BEUSTQ`, level 1, risk 1, `--timeout=30 --retries=3`) | 51 | 43–47 s | inclui `stacked queries` e `inline queries` |
| com os limites adotados | 49 | **5–12 s** | apenas boolean-based, time-based e UNION |

Além do tempo, os limites mudam **o que é executado**. Sem `--technique=BEUT` o
log mostra `SQLite > 2.0 stacked queries (heavy query - comment)` e `SQLite > 2.0
stacked queries (heavy query)`, que executam statements adicionais no banco do
alvo. Com a flag, essas linhas não aparecem.

O custo do `--timeout=10` está no mesmo run sem limites:
`[CRITICAL] connection timed out to the target URL. sqlmap is going to retry the
request(s)`, com 30 s gastos num único request, porque o default é
`--timeout=30 --retries=3`.

### Tempo real e cabimento no timeout do executor

O `PodmanExecutor` usa `Duration::from_secs(15 * 60)`. Medido: **5 a 12 s** por
alvo com os limites adotados, e **43 a 47 s** sem eles. Cabe com folga.

O SQLMap **não tem** limite global de execução: não existe `--run-timer` em
`-hh`. O teto é o timeout do executor, que já emite `[ERRO] O container ...
excedeu o tempo limite de 15 minutos.`, mata o container e devolve status
`TimedOut` ao pipeline.

## Execução real do produto completo

Depois de integrado, o binário do SmartSec executou o SQLMap de verdade, no
container, contra os alvos locais, pelo mesmo executor de qualquer outra
ferramenta.

Alvo com injeção:

```console
$ smartsec tool SQLMap --target 'http://169.254.1.2:3100/item?id=1' --output relatorio.md
  [ 1/ 1] SQLMap
  OK (2026-09-30T20:39:36Z, 4154 bytes de saída)
  Total de achados: 3
  CRÍTICAS: 0   ALTAS: 1   MÉDIAS: 2   BAIXAS: 0   INFORMATIVAS: 0
  OK Relatório exportado: relatorio.md
  OK Análise concluída.
# exit 0
```

Log estruturado da mesma execução (RNF09):

```
ferramenta  : SQLMap
versão      : 1.10.4
imagem      : docker.io/parrotsec/sqlmap:7.3@sha256:31bb35cd9fdc8c00d3673d26c48a59d2d8ea3c4955c252fb5dee2f96992b4596
status      : succeeded | duracao_ms: 6438
 - Medium | sqlmap parâmetro: id | método: GET | tipo: boolean-based blind | técnica: AND boolean-based blind - WHERE or HAVING clause | url: http://169.254.1.2:3100/item
 - Medium | sqlmap parâmetro: id | método: GET | tipo: time-based blind | técnica: SQLite > 2.0 AND time-based blind (heavy query) | url: http://169.254.1.2:3100/item
 - High   | sqlmap parâmetro: id | método: GET | tipo: UNION query | técnica: Generic UNION query (NULL) - 1 column | url: http://169.254.1.2:3100/item
```

Verificação de sanitização na mesma execução:

```console
$ grep -c "RANDOMBLOB\|?id=\|Payload" relatorio.md
0
```

Alvo sem SQLi — varredura limpa, `exit 0`, 0 achados:

```console
$ smartsec tool SQLMap --target 'http://169.254.1.2:3000/index.html?id=1' --output limpo.md
  OK (2026-09-30T20:39:58Z, 5868 bytes de saída)
  Total de achados: 0
# exit 0
```

Alvo inalcançável — erro de execução, `exit 2`, mensagem acionável em pt-BR:

```console
$ smartsec tool SQLMap --target 'http://169.254.1.2:9999/item?id=1' --output falha.md
  FALHA Varredura concluída com erros: o SQLMap não conseguiu executar a varredura: unable to connect to the target URL ('Connection refused')
# exit 2
```

## Comportamentos de erro tratados

| Cenário | Tratamento no SmartSec |
|---|---|
| alvo inalcançável (`Connection refused`) | `failed` com `o SQLMap não conseguiu executar a varredura: unable to connect to the target URL ('Connection refused')` |
| URL inválida | `failed` com `o SQLMap não conseguiu executar a varredura: invalid target URL` |
| nenhum parâmetro injetável | **não** é erro: varredura limpa, 0 achados, status `succeeded` |
| bloco de injeção sem `Type:` | achado descartado e erro registrado em pt-BR |
| stdout vazio, só `[ERRO]` do executor ou texto não reconhecido | `failed`; nunca "varredura limpa" |
| exit status diferente de zero | `failed` pelo `podman_output`, que preserva o status do container |
| timeout de 15 min | `failed` com a mensagem do executor; container morto e removido |

## Evidência preservada por achado

```
sqlmap parâmetro: id | método: GET | tipo: boolean-based blind |
técnica: AND boolean-based blind - WHERE or HAVING clause |
url: http://127.0.0.1:3100/item
```

O `Payload:` é **descartado de propósito**. Ele é escrito incondicionalmente em
`lib/controller/controller.py:165` (`data += "    Payload: %s\n" % ...`) e
nenhuma flag o suprime; é um fragmento com forma de query string, e
`redaction.rs` não o remove, porque `sanitize_text` só age em URLs e em linhas
com chave sensível. A regra do projeto proíbe query string em finding, então o
parser descarta o campo. `Parameter`, `Type` e `Title` — a taxonomia do próprio
scanner — descrevem a injeção sem o payload.

Observação para revisão: como o `Payload:` é incondicional, ele permanece no
`stdout` sanitizado que o log estruturado preserva por RNF09. Ele **não** está
em finding, evidência, descrição, recomendação nem relatório, e a query string
real do alvo é removida pela sanitização em todos esses artefatos. Tratar o
`stdout` bruto do scanner como dado sensível exigiria mexer em
`utils::redaction.rs`, que é contrato compartilhado por todas as ferramentas e
não pertence a esta issue.
