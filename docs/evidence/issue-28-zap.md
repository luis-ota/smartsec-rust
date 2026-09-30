# Evidência da integração do OWASP ZAP — issue #28

Este documento registra a execução real do OWASP ZAP dentro do executor Podman
rootless do SmartSec, contra um alvo local controlado, e as conclusões que
sustentam a implementação. Todos os comandos abaixo foram executados na máquina
de validação (Arch Linux, Podman rootless, 15 Gi de RAM).

## 1. Alvo e ambiente

O alvo é um servidor HTTP estático publicado **apenas no loopback do host**:

```
$ mkdir -p /tmp/smartsec-www
$ printf '<html><body><h1>Alvo</h1></body></html>\n' > /tmp/smartsec-www/index.html
$ setsid --fork python3 -m http.server 3000 --bind 127.0.0.1 --directory /tmp/smartsec-www
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000
200
```

Nenhum serviço foi exposto na rede local. De dentro do container, o alvo é
alcançado por `http://169.254.1.2:3000`, thanks à rede `pasta` do executor com
`--map-host-loopback=169.254.1.2`.

## 2. Imagem avaliada e digest

| Item | Valor |
|---|---|
| Imagem | `ghcr.io/zaproxy/zaproxy:2.14.0` |
| Digest usado no manifesto | `sha256:3280adc730131f1f4460ab226b0f85e3e9ab3301ef5a7030f745ac4dd6b6ff87` |
| Versão (`@version` do relatório) | `2.14.0` |
| Tamanho | 2.05 GB |

A imagem foi baixada durante esta issue e o digest **não** foi copiado de
fonte secundária: ele é o que o próprio Podman reporta após o `pull`.

```
$ podman inspect --format '{{index .RepoDigests 0}}' ghcr.io/zaproxy/zaproxy:2.14.0
ghcr.io/zaproxy/zaproxy@sha256:3280adc730131f1f4460ab226b0f85e3e9ab3301ef5a7030f745ac4dd6b6ff87
```

## 3. O bloqueio real: o relatório do ZAP é sempre um arquivo

O job `report` do ZAP **sempre** concatena um nome de arquivo e acrescenta a
extensão do template. Não existe parâmetro de saída em stdout: o conjunto de
parâmetros é fechado (`template`, `theme`, `reportDir`, `reportFile`,
`reportTitle`, `reportDescription`, `displayReport`) e o ZAP rejeita o resto.

Os templates válidos, extraídos do erro do próprio ZAP:

```
Job report invalid template: inexistente, valid templates: [high-level-report,
modern, risk-confidence-html, sarif-json, traditional-html, traditional-html-plus,
traditional-json, traditional-json-plus, traditional-md, traditional-pdf,
traditional-xml, traditional-xml-plus]
```

Quatro combinações foram testadas no container real, buscando um destino que
resultasse em escrita no stdout. **Nenhuma funciona**, e a razão é a mesma em
todas: o ZAP acrescenta a extensão `.json` ao nome, produzindo um caminho que
não pode ser criado.

| # | `reportDir` | `reportFile` | Resultado real |
|---|---|---|---|
| 1 | `/dev` | `stdout` | `Job report failed to generate report: /dev/stdout.json` |
| 2 | — | `/dev/stdout` | mesmo erro, caminho normalizado |
| 3 | `/tmp` | `/dev/stdout` | mesmo erro |
| 4 | `/proc/self/fd` | `1` | mesmo erro |

Montar um tmpfs não resolve: o ZAP tentaria criar `/dev/stdout.json`. A API do
ZAP é inalcançável porque o executor remove o container logo após
`podman start --attach`. O `-autorun` aceita arquivo ou URL, mas não lê
`stdin`.

## 4. `podman cp` foi testado de verdade — e não resolve

Teste com o container criado com exatamente as flags do executor (`--read-only`,
tmpfs, `--cap-drop all`, `--security-opt no-new-privileges`, rede `pasta`),
scan concluído e container encerrado:

```
$ podman cp <id>:/tmp/zap-report.json ./zap-report.json
Error: "/tmp/zap-report.json" could not be found on container <id>: no such file or directory
exit=125

$ podman cp <id>:/home/zap/.ZAP/config.xml ./tmpfs-copia.json
Error: "/home/zap/.ZAP/config.xml" could not be found on container <id>: no such file or directory
exit=125
```

**Descoberta decisiva:** quando o container encerra, o tmpfs é desmontado e o
conteúdo desaparece. `podman cp` só enxerga o que está declarado em `Mounts`, e
os tmpfs não estão lá. Nenhum método de extração salva um relatório gravado em
tmpfs depois da saída do container.

O mesmo teste com o relatório em um **bind mount** do host funciona:

```
$ podman cp <id>:/smartsec-out/zap-report.json ./copia.json
exit=0
```

Ou seja, `podman cp` só funciona quando o artefato já está num volume de bind —
situação em que o host **já tem o arquivo em mãos** e o `podman cp` é uma
operação redundante e uma superfície de falha adicional.

## 5. Solução implementada

O executor ganhou a capacidade de coletar um artefato gravado pelo container
antes de removê-lo (`PodmanExecutor::execute_with_artifact`). A implementação:

1. cria um diretório **vazio** no `TMPDIR` do host, com modo `0733`;
2. monta **apenas esse diretório** no container, em `/smartsec-out`, com
   `rw,noexec,nosuid,nodev`;
3. lê o arquivo depois da execução e **antes** de remover o container;
4. remove o diretório ao final, inclusive nos caminhos de erro.

Por que `0733`: em Podman rootless sem `keep-id`, o usuário do container é um
*subuid* do host. Um diretório do host em `0755` pertence ao *root do container*
(uid 0) e o processo do scanner não consegue gravar nele — comportamento
verificado:

```
$ touch /smartsec-out/teste.txt
touch: cannot touch '/smartsec-out/teste.txt': Permission denied
# com o diretório em 0733:
TOUCH-733-OK
```

### Por que isso não enfraquece o sandbox

- O container continua **sem shell**: cada item do comando continua sendo um
  argumento literal do Podman.
- O container continua **`--read-only`**, `--cap-drop all` e
  `no-new-privileges`, sem nenhuma capacidade ou volume novo.
- O único ponto de escrita fora das tmpfs é um diretório **criado pelo próprio
  SmartSec, vazio, efêmero e inacessível a outros processos** (o pai é o
  `TMPDIR` do processo, e dentro do container ele só é alcançável pelo mount).
- O volume é montado com `noexec,nosuid,nodev`, então o scanner não ganha
  executável, setuid nem dispositivo novo.
- Nada é executado no host além do binário do Podman, e nenhum comando de shell
  é montado.
- O diretório é removido ao final, verificado por teste de integração.

O que muda em relação ao desenho inicial desta issue é apenas o **mecanismo**:
a intenção (coletar um artefato do container antes de removê-lo) é mantida, mas
por bind mount em vez de `podman cp`, porque o `podman cp` foi demonstradamente
inviável com tmpfs e redundante com bind mount.

### A tmpfs do `TMPDIR` é verificada, não presumida

O bind mount acima só é aceito pela regra de isolamento do `TCC_SPEC.md`
*porque* o diretório de saída está em `tmpfs`. Essa condição não é garantida
pelo código: o `TMPDIR` é herdado do ambiente, e nesta máquina ele é `tmpfs` por
acaso da configuração (`TMPDIR=/tmp`, `/tmp` é tmpfs). Numa máquina — ou num
runner de CI — em que `TMPDIR` aponte para um diretório comum em disco, o mesmo
código montaria um diretório persistente e gravaria o relatório do scanner fora
da regra, **sem nenhum sinal**.

Por isso `WritableOutput::new` verifica a condição antes de criar o diretório.
O tipo do filesystem é resolvido em `/proc/self/mountinfo` (o ponto de montagem
mais específico que contém o caminho, sobre o caminho canonicalizado), e sem
`tmpfs` a execução falha com mensagem acionável. O mesmo vale para o diretório
do plano de automação, que é a configuração temporária da execução.

Verificado com o binário real, nos dois sentidos:

**`TMPDIR` em disco comum — a execução é recusada, sem degradar:**

```
$ df -T $TMPDIR
/dev/mapper/root  btrfs  247943168 219649720 25435928  90%  /home

$ smartsec-rust tool ZAP --target http://127.0.0.1:3000
FALHA (o diretório de escrita efêmera
'/home/luis/dev/bobera/tcc/.tmpfs-prova/smartsec-zap-plano-2139822-1790805148066234664'
está no filesystem 'btrfs', e a regra de isolamento do SmartSec exige 'tmpfs'; a
execução foi interrompida para não gravar a configuração temporária e o
relatório do scanner fora da tmpfs. Ajuste o ambiente: monte uma tmpfs (por
exemplo `sudo mount -t tmpfs -o size=512m tmpfs /var/tmp/smartsec`) e aponte a
variável TMPDIR para ela antes de rodar a varredura. Um 'overlay' não é aceito:
a camada copy-on-write do container grava em disco do host.)
```

Nenhum container é criado, nenhum `--volume` é montado, e a varredura é
registrada como `failed` — nunca como varredura limpa.

**`TMPDIR` em tmpfs — a execução segue e o diretório some ao final:**

```
$ df -T $TMPDIR
tmpfs  tmpfs  8073404  848 8072556  1%  /dev/shm

$ smartsec-rust tool ZAP --target http://127.0.0.1:3000
  │ $ podman create ... --volume /dev/shm/sb-tmpfs/smartsec-zap-plano-...:/zap/automation:ro \
  │   --volume /dev/shm/sb-tmpfs/smartsec-saida-2142783-1:/smartsec-out:rw,noexec,nosuid,nodev ...
  OK (2026-09-30T21:52:58Z, 0 bytes de saída)

$ ls -A /dev/shm/sb-tmpfs
(nada: o diretório de saída e o do plano foram removidos)
```

### Decisão sobre `overlay`

`overlay` **não** é aceito. Ele é a camada copy-on-write de um container, e o
dado gravado nela reside no diretório superior (`upperdir`), normalmente em
disco do host: aceitá-lo equivaleria a aceitar escrita em disco com outro
nome, que é exatamente o que a regra do TCC proíbe. Em container de CI o `/tmp`
costuma ser uma `tmpfs` própria; quando não é, a execução falha e a mensagem diz
como corrigir o ambiente — falha barulhenta é o comportamento desejado, e
melhor que a violação silenciosa que a verificação existe para impedir.

Os testes cobrem os dois sentidos sem depender da máquina: o tipo de filesystem
é injetável (`tmpfs::FilesystemProbe`), então o caminho negativo usa um diretório
base descartável e afirma que a recusa acontece **antes** de qualquer criação, e
que a mensagem nomeia o filesystem encontrado, o `tmpfs` exigido e a correção.
Há ainda um teste sobre a máquina real que exige coerência entre a tabela de
montagens do processo e o resultado da verificação, em vez de assumir tmpfs.

As limitações conhecidas — namespace de montagem do processo, janela TOCTOU de
symlink e kernels sem `/proc/self/mountinfo` legível — estão documentadas em
`src/orchestrator/tmpfs.rs`, e a regra correspondente em `TCC_SPEC.md` §7.

## 6. Configuração final validada

```
podman create --name zap \
  --network pasta:--map-host-loopback=169.254.1.2 \
  --memory 1536m --cpus 1 --pids-limit 256 \
  --cap-drop all --security-opt no-new-privileges --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m \
  --tmpfs /root/.config:rw,noexec,nosuid,nodev,size=16m \
  --tmpfs /home/zap:rw,noexec,nosuid,nodev,size=512m \
  --volume <plano>:/zap/automation:ro \
  --volume <saida>:/smartsec-out:rw,noexec,nosuid,nodev \
  ghcr.io/zaproxy/zaproxy:2.14.0@sha256:3280adc7... \
  zap.sh -Xmx1024m -cmd -autorun /zap/automation/scan.yaml \
  -config spider.scope=http://169.254.1.2:3000
```

Plano de automação montado em memória pelo SmartSec e montado em somente leitura:

```yaml
env:
  contexts:
    - name: default
      urls:
        - 'http://169.254.1.2:3000'
      includePaths:
        - .*
      excludePaths: []
  vars: {}
jobs:
  - type: spider
    parameters:
      context: default
      user: ""
  - type: passiveScan-wait
    parameters: {}
  - type: report
    parameters:
      template: traditional-json
      reportDir: /smartsec-out
      reportFile: zap-report
```

### Saída real

```
Found Java version 11.0.22
Available memory: 15768 MB
Using JVM args: -Xmx1024m
Job spider requesting URL http://169.254.1.2:3000
Job spider found 3 URLs
Job passiveScan-wait finished, time taken: 00:00:02
Job report generated report /smartsec-out/zap-report.json
Automation plan succeeded!
exit=0 oom=false
```

## 7. Cada flag, e por que ela existe

Todas as flags abaixo foram decididas **executando** o container, não lendo
documentação.

- **`-Xmx1024m`** — o `zap.sh` da 2.14 **ignora `JAVA_OPTS`**. Ele calcula o
  heap a partir do `/proc/meminfo`, que dentro do container continua reportando
  a memória do host, e imprimiria `Using JVM args: -Xmx3942m` numa máquina de
  15 Gi, o que estoura o limite de cgroup. `-Xmx` passado como argumento é a
  única forma de limitar o heap — e tem de ser um argumento único, senão o
  `zap.sh` não reconhece.
- **`-cmd`** — sem `-cmd` o ZAP abre a proxy e **não encerra**; o executor
  ficaria preso até o timeout de 15 minutos.
- **`-autorun /zap/automation/scan.yaml`** — o plano vem do bind mount somente
  leitura. O `-autorun` aceita arquivo ou URL, nunca `stdin`.
- **`-config spider.scope=<alvo>`** — a única via do ZAP para receber o alvo de
  fora do plano, necessária porque o executor exige que o `command_template` do
  manifesto carregue `{target}`. O alvo autoritativo da varredura é o contexto
  `default` do plano; a execução com e sem essa chave produziu o mesmo
  resultado.
- **`--tmpfs /home/zap`** — obrigatória. Sem ela, com o `--read-only` do
  executor, o ZAP aborta antes do primeiro job:
  `The home path is not writable: /home/zap/.ZAP/`, status 1.
- **`--memory 1536m`** — o padrão do executor (`512m`) passa em alvos estáticos
  triviais, mas DAST real precisa de folga. `1536m` foi validado sem OOM.
- **`--volume <saida>:/smartsec-out:rw,noexec,nosuid,nodev`** — seção 5.

### Achados que só aparecem executando

- **A imagem não tem `ENTRYPOINT`** (`ENTRYPOINT=[]`, `CMD=["bash"]`).
  `podman create IMAGEM zap.sh -Xmx1024m …` executa `/zap/zap.sh` pelo `PATH`
  (shebang `#!/usr/bin/env bash`) e funciona. O `zap.sh` da 2.14 **não** tem
  atalhos `-quickstart`/`-baseline`/`-full`: ele só reconhece `-Xmx*` e
  `--jvmdebug*` e repassa o resto ao `java -jar zap-2.14.0.jar`.
- **`passiveScan-wait` não aceita `maxTime`** e o job `delay` não aceita
  `delay`: ambos respondem `Unrecognised parameter for job <job> : <param>`.
  O plano usa `passiveScan-wait` sem parâmetros.
- **`outputSummary` não serve** para coletar o relatório: ele valida o plano
  **antes** de executar e exige acesso de escrita no diretório pai de
  `summaryFile`, e quando aceita **não grava arquivo** se não houver alertas.
  Com tmpfs ele falha com `parent directory of summaryFile does not exist`; com
  bind mount em `0755` do host, falha com `no write access to parent directory
  of summaryFile`. Por isso o fluxo usa o job `report`.

## 8. Formato do relatório e a origem da severidade

Raiz: `@programName`, `@version`, `@generated`, `site[]`.
`site`: `@name`, `@host`, `@port`, `@ssl`, `alerts[]`.
`alert`: `pluginid`, `alertRef`, `alert`, `name`, `riskcode`, `confidence`,
`riskdesc`, `count`, `cweid`, `solution`, `reference`, `desc`,
`instances[{uri, method, param, attack, evidence, otherinfo}]`.

**A severidade do ZAP é autoritativa** (TCC_SPEC §7) e vem de `riskcode`, o campo
estruturado do próprio scanner: `0` informativa, `1` baixa, `2` média, `3` alta.
O ZAP não tem nível "Crítico", então o risco alto é o teto. `riskdesc` traz
risco e confiança rotulados pelo scanner (`Medium (High)`) e é preservado como
rótulo, sem ser reinterpretado. Um `riskcode` ausente ou fora da faixa cai em
`Info`: uma saída inesperada nunca produz severidade maior que a do scanner.

**O template `traditional-json` não contém cabeçalhos nem corpos de
requisição/resposta**, verificado por busca no arquivo real gerado:
`requestHeader`, `responseHeader`, `requestBody`, `responseBody` e `httpHeader`
estão ausentes (os templates `*-plus` é que os incluem). Nenhum corpo HTTP
chega ao achado, à evidência, ao log ou ao relatório.

### Alertas reais obtidos contra o alvo local

Quatro alertas, três URLs varridas:

| `alertRef` | Alerta | `riskcode` | `riskdesc` | Severidade SmartSec |
|---|---|---|---|---|
| 10038-1 | Content Security Policy (CSP) Header Not Set | 2 | Medium (High) | MÉDIA |
| 10020-1 | Missing Anti-clickjacking Header | 2 | Medium (Medium) | MÉDIA |
| 10036 | Server Leaks Version Information via "Server" Header | 1 | Low (High) | BAIXA |
| 10021 | X-Content-Type-Options Header Missing | 1 | Low (Medium) | BAIXA |

O alerta 10036 preservou a evidência devolvida pelo alvo
(`SimpleHTTP/0.6 Python/3.14.7`), e o 10020 o parâmetro observado
(`x-frame-options`).

O relatório real gerado está preservado em
`tests/fixtures/zap/relatorio.json`, sem alteração em relação à saída do
container.

## 9. Limpeza

Todos os containers de teste foram removidos com `podman rm -f` ao final de cada
experimento; nenhum container e nenhum processo ficaram órfãos. O servidor
`http.server` do alvo local permanece em execução apenas para a duração da
investigação.
