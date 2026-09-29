# Evidência real — Nikto (issue #14)

Escopo: validação do comportamento do Nikto dentro do executor Podman rootless
antes de fixar o `command_template` embutido e o parser `nikto`.

Alvo: servidor HTTP local em `127.0.0.1:3000`, publicado no container pela rede
`pasta` como `169.254.1.2:3000`. Nenhum alvo externo foi escaneado.

## Imagem avaliada

| Imagem | Versão do Nikto | Resultado |
|---|---|---|
| `docker.io/sullo/nikto:2.5.0` | — | acesso negado no registro; tag inexistente |
| `docker.io/securecodebox/nikto@sha256:6f09…` | 2.1.6 | imagem embrulha o Nikto em uma app Sinatra; não serve como runner de CLI |
| `docker.io/hackllc/nikto:2.6.1` | 2.6.1 | aceita `-o -`, porém grava em arquivo real (`/dev/stdout.json`) e falha com `--read-only` |
| `docker.io/secsi/nikto:latest` | — | falha na inicialização: `Required module not found: XML::Writer` |
| `docker.io/raesene/nikto:latest` | 2.5.0 | funciona, mas o JSON é um array de hosts e o alvo é resolvido sem `pasta` de forma estável |
| `docker.io/alpine/nikto:2.2.0` | 2.1.6 | **escolhida**: JSON único em stdout, sem arquivo, compatível com `--read-only` |

Imagem fixada por digest:

```
docker.io/alpine/nikto:2.2.0@sha256:eb2fe88217ec32695f3843f67c7a7f1628b484b653e99015aac69c586eb2a88b
```

## Descoberta que definiu o `command_template`

O modo JSON do Nikto **exige arquivo de saída** por padrão: `report_head` aborta
com `+ ERROR: Output file format specified without a name` quando `-Format` é
informado sem `-o`. A resolução sem shell é a flag `-o -`, que faz o Nikto
escrever o relatório no stdout em vez de criar um arquivo:

```perl
# nikto_core.plugin — a saída de texto normal é suprimida quando o arquivo é "-"
return if defined $CLI{'file'} && $CLI{'file'} eq "-";
```

Nenhum `cat`, `tee` ou shell é necessário: o próprio Nikto resolve.

Um segundo problema apareceu na execução real. A imagem declara
`ENTRYPOINT ["nikto.pl"]`, e o executor do SmartSec monta
`podman create … IMAGEM <argumentos>`. Repetir `nikto.pl` como primeiro
argumento é inofensivo (o Nikto ignora o token), mas incluí-lo no
`command_template` deixa o comando explícito e legível, como já ocorre com
Nmap e Nuclei. Os dois formatos foram comparados no container e produzem JSON
idêntico.

## Comando final validado

Executado exatamente com as flags do `PodmanExecutor` (`--read-only`,
`--cap-drop all`, `--security-opt no-new-privileges`, `--memory 512m`,
`--cpus 1`, `--pids-limit 256`, tmpfs restritos, rede `pasta`):

```bash
podman run --rm -i \
  --network "pasta:--map-host-loopback=169.254.1.2" \
  --memory 512m --cpus 1 --pids-limit 256 \
  --cap-drop all --security-opt no-new-privileges --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m \
  --tmpfs /root/.config:rw,noexec,nosuid,nodev,size=16m \
  docker.io/alpine/nikto:2.2.0@sha256:eb2fe88217ec32695f3843f67c7a7f1628b484b653e99015aac69c586eb2a88b \
  nikto.pl -h http://169.254.1.2:3000 -nointeractive -ask no -maxtime 10m -Format json -o - \
  < /dev/null
```

`-ask no` é obrigatório. Sem ele o Nikto 2.1.6 abre o prompt interativo
"Would you like to submit this information … to CIRT.net (y/n)?" e esse texto
**vaza para o stdout**, quebrando o JSON:

```
{"host":"169.254.1.2",…,"vulnerabilities":[…]}

      *********************************************************************
      Portions of the server's headers (Python/3.14.7) are not in
      the Nikto 2.1.6 database … Would you like
      to submit this information (*no server specific data*) to CIRT.net
      for a Nikto update (or you may email to sullo@cirt.net) (y/n)?
```

## Resultado (exit status 0, stdout 908 bytes, stderr vazio)

Trecho sanitizado, sem segredos e sem corpos HTTP:

```json
{
  "host": "169.254.1.2",
  "ip": "169.254.1.2",
  "port": "3000",
  "banner": "SimpleHTTP/0.6 Python/3.14.7",
  "vulnerabilities": [
    { "id": "999957", "OSVDB": "0", "method": "GET",  "url": "/",                "msg": "The anti-clickjacking X-Frame-Options header is not present." },
    { "id": "999102", "OSVDB": "0", "method": "GET",  "url": "/",                "msg": "The X-XSS-Protection header is not defined. …" },
    { "id": "999103", "OSVDB": "0", "method": "GET",  "url": "/",                "msg": "The X-Content-Type-Options header is not set. …" },
    { "id": "600720", "OSVDB": "0", "method": "HEAD", "url": "/",                "msg": "SimpleHTTP/0.6 appears to be outdated (current is at least 1.2)" },
    { "id": "007252", "OSVDB": "0", "method": "GET",  "url": "/#wp-config.php#",  "msg": "#wp-config.php# file found. This file contains the credentials." }
  ]
}
```

Campos que o parser precisa preservar: `id` (referência Nikto), `OSVDB`
(referência OSVDB), `method` (método HTTP), `url` (caminho) e `msg` (evidência).
`banner` descreve o servidor e também entra na evidência.

## Comportamentos de erro observados

| Cenário | Comportamento real |
|---|---|
| alvo com porta fechada | exit `0`, JSON válido com um item `id: "000029"`, `msg: "No web server found …"` |
| saída não-JSON (Nikto 2.6.1 gravando arquivo sob `--read-only`) | stderr `+ ERROR: Unable to open '-.json' for write: Read-only file system` |
| container inexistente / imagem ausente | o executor do SmartSec já traduz em mensagem acionável em pt-BR |

O alvo com porta fechada **não** é erro de execução: o Nikto termina com
sucesso e reporta que nada foi encontrado. O parser precisa tratar esse item
como diagnóstico e não como vulnerabilidade.
