# Evidência — Correlação, deduplicação e enriquecimento CVE/NVD (issue #19)

Escopo: implementação de REQ11 (integrar CVE/NVD para validar e enriquecer
achados) e da parte de deduplicação de REQ12.

Alvo: servidor HTTP local em `127.0.0.1:3000`, publicado no container pela rede
`pasta` como `169.254.1.2:3000`. **Nenhum alvo externo foi escaneado.** A única
conversa com a internet é a consulta à API pública da NVD, que é o objeto da
issue.

Data da execução: 30/09/2026. Ambiente: Podman rootless, Linux.

---

## 1. Regra de correlação adotada

**Dois achados são o mesmo problema quando, no mesmo alvo, compartilham uma
identidade estruturada emitida pelo próprio scanner.** Nunca por semelhança de
texto.

| Chave | Origem da identidade | Exemplo |
|---|---|---|
| `cve:<id>@<endpoint>\|alvo=<alvo>` | Referência CVE citada por qualquer scanner | `cve:CVE-2021-44228@http://alvo/app\|alvo=http://alvo` |
| `osvdb:<id>@<endpoint>\|alvo=<alvo>` | Referência OSVDB do Nikto | `osvdb:4321@http://alvo/` |
| `nuclei:<template>\|<matcher>@<endpoint>\|alvo=<alvo>` | Template e matcher do Nuclei | `nuclei:cve-2021-44228\|jndi-injection@http://alvo/app` |
| `nikto:<referência>@<url>\|alvo=<alvo>` | ID de teste do Nikto no endpoint | `nikto:nikto:999957@http://alvo/` |
| `nmap:<porta>/<serviço>/<produto>\|alvo=<alvo>` | Porta, serviço e banner do Nmap | `nmap:3000/http/nginx` |

Duas decisões de projeto que merecem registro:

1. **O endpoint faz parte da chave de referência cruzada.** Na primeira versão a
   chave era só `cve:<id>`, e dois templates do mesmo CVE em páginas diferentes
   eram fundidos em um único achado — o ponto de exposição em `/login` se
   perdia. O endpoint foi incluído justamente para que a correlação atravesse
   ferramentas (ZAP e Nuclei reportam `endpoint`) sem apagar o local da
   exposição. Regressão coberta por
   `achados_parecidos_mas_em_endpoints_distintos_nao_sao_mesclados`.

2. **Evidência sem identidade estrutural nunca é mesclada.** A saída do parser
   `generic-text` carrega só a linha textual do scanner. Sem `template`,
   `endpoint`, `nikto referência` ou `porta`, ela não produz chave e permanece
   sempre isolada. É a garantia formal de que a deduplicação é conservadora.

A implementação usa union-find por chaves: dois achados de ferramentas
diferentes se encontram por uma referência CVE compartilhada sem que as
ferramentas se conheçam entre si.

### Regra de severidade do grupo

**A severidade do grupo é a mais alta entre as origens.**

Justificativa: a severidade estruturada de cada scanner é autoritativa
(TCC_SPEC.md §7). O agrupamento apenas agrega observações, **não reclassifica**
nenhuma delas. Tomar o máximo é a única regra que não pode **rebaixar** uma
classificação autoritativa — rebaixar esconderia um achado crítico apenas
porque outro scanner omitiu a mesma anomalia com rótulo menor.

Quando as origens divergem, nada é sobrescrito:

- cada origem fica em `origins` com `tool`, `severity`, `evidence` e
  `detected_at` próprios;
- `severity_conflict` registra a divergência em pt-BR;
- o relatório e a TUI listam todas as origens do grupo.

Divergência entre o scanner e a NVD segue a mesma regra: as duas classificações
ficam visíveis e a severidade do scanner permanece autoritativa
(`annotate_nvd_divergence`).

---

## 2. Evidência empírica da API da NVD

### 2.1 Endpoint e formato

Chamada real, sanitizada (a resposta tem 87 139 bytes; abaixo só o que o
SmartSec usa):

```bash
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"
```

```json
{
  "resultsPerPage": 1,
  "startIndex": 0,
  "totalResults": 1,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2026-09-30T19:12:49.812",
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2021-44228",
        "published": "2021-12-10T10:15:09.143",
        "metrics": {
          "cvssMetricV31": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "baseScore": 10.0,
                "baseSeverity": "CRITICAL"
              },
              "exploitabilityScore": 3.9,
              "impactScore": 6.0
            }
          ]
        },
        "references": [
          { "url": "https://logging.apache.org/log4j/2.x/security.html", "source": "security@apache.org", "tags": ["Vendor Advisory"] },
          { "url": "https://packetstormsecurity.com/files/165225/…", "source": "security@apache.org", "tags": ["Third Party Advisory", "VDB Entry"] }
        ]
      }
    }
  ]
}
```

Decisões extraídas disso:

- a métrica preferencial é `type: "Primary"` com `source: "nvd@nist.gov"`, na
  ordem CVSS **4.0 → 3.1 → 3.0 → 2.0**;
- a referência escolhida prioriza as etiquetas `Vendor Advisory`, `Patch` e
  `Release Notes`, nessa ordem; sem nenhuma, usa a primeira devolvida;
- o documento precisa ser um **objeto** com `vulnerabilities`. Um array ou um
  texto no lugar do objeto indica proxy, portal cativo ou página de erro — e sem
  essa checagem um `[]` seria lido como "CVE inexistente", mascarando a
  indisponibilidade como resultado limpo.

### 2.2 Limite de taxa — medido nesta máquina

A documentação da NVD publica **5 requisições a cada 30 segundos sem chave de
API** e **50 a cada 30 segundos com chave**. O limite sem chave foi reproduzido
em rajada:

```
$ for i in $(seq 1 12); do
    curl -s -o /dev/null -w "$i:%{http_code} " \
      "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-0000$i"
  done

1:200 2:200 3:200 4:200 5:200 6:429 7:429 8:200 9:200 10:200 11:429 12:429
```

O `429` vem do Cloudflare, com corpo `error code: 1015` e
`Retry-After: 0`:

```
retry-after: 0
error code: 1015
```

`Retry-After: 0` é inútil como espera, então o cliente aplica o backoff próprio
(5 s, dobrando a cada tentativa, com no máximo duas tentativas) em vez de
confiar no cabeçalho.

Implementação:

| Situação | Intervalo mínimo entre requisições |
|---|---|
| sem chave (`SMARTSEC_NVD_API_KEY` ausente) | 6 s (5 req / 30 s) |
| com chave | 0,6 s (50 req / 30 s) |

As consultas são **sequenciais** e aguardam o intervalo antes de cada requisição
que não seja a primeira. Um CVE citado por vários achados vira **uma** consulta.

A chave é lida da variável de ambiente `SMARTSEC_NVD_API_KEY` e **nunca** é
gravada em arquivo, log, relatório ou tela. A descrição do limite publicada no
relatório diz apenas se há chave, nunca o valor
(`a_descricao_do_limite_de_taxa_nao_vaza_a_chave_de_api` → `rate_limit_pt_br`).

### 2.3 Cache em disco

- Caminho: `<config_dir>/smartsec/nvd-cache/{CVE}.json`, junto dos logs de scan.
- **TTL: 7 dias**, documentado no relatório e no código (`CACHE_TTL_DAYS`).
- O `queried_at` **original** viaja com a entrada, inclusive quando a resposta
  vem do cache: dado de terceiro envelhece e o relatório precisa dizer quando
  foi obtido.

Conteúdo real gravado por uma execução real:

```json
{
  "cve_id": "CVE-2021-44228",
  "cvss_base_score": 10.0,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "cvss_severity": "Critical",
  "cvss_version": "3.1",
  "reference": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/M5CSVUNV4HWZZXGOKNSK6L7RPM7BOKIB/",
  "queried_at": "2026-09-30T21:41:38Z"
}
```

---

## 3. Execução real — enriquecimento com a NVD no ar

Alvo local com um template do Nuclei que reporta `template-id: cve-2021-44228`:

```
$ smartsec-rust scan --config scan.toml --target http://169.254.1.2:3000

  │ correlação: 11 achados consolidados a partir de 11 origens de scanner
  │ NVD: 1 enriquecidos, 0 do cache, 0 sem registro em 1 consultados.
  Total de achados: 11
  CRÍTICAS: 1   ALTAS: 0   MÉDIAS: 0   BAIXAS: 0   INFORMATIVAS: 10
  OK Relatório exportado: smartsec-report.md
  OK Log estruturado: …/smartsec/scans/scan_1790804537457274972.json
```

Achado enriquecido, exatamente como persistido no log estruturado:

```json
{
  "title": "Possível vulnerabilidade detectada — cve-2021-44228",
  "severity": "Critical",
  "enrichment": {
    "cve_id": "CVE-2021-44228",
    "cvss_base_score": 10.0,
    "cvss_severity": "Critical",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cvss_version": "3.1",
    "from_cache": false,
    "queried_at": "2026-09-30T21:41:38Z",
    "reference": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/M5CSVUNV4HWZZXGOKNSK6L7RPM7BOKIB/"
  },
  "severity_conflict": null,
  "origins": [ { "tool": "Nuclei", "severity": "Critical", "evidence": "template: cve-2021-44228 | matcher: jndi-injection | …", "detected_at": "…" } ]
}
```

### Cache respeitado na segunda execução

Mesma varredura, logo em seguida, com o cache já aquecido:

```
  │ correlação: 11 achados consolidados a partir de 11 origens de scanner
  │ NVD: 0 enriquecidos, 1 do cache, 0 sem registro em 1 consultados.
```

Nenhuma requisição à NVD. O relatório marca `(cache local)` no contexto e o
log marca `"cached": 1`.

---

## 4. Comportamento degradado — NVD indisponível

A indisponibilidade foi reproduzida de verdade, apontando o tráfego HTTPS para
um proxy inexistente (`127.0.0.1:9`), com o cache removido:

```
$ HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 \
  smartsec-rust scan --config scan.toml --target http://169.254.1.2:3000

  │ correlação: 11 achados consolidados a partir de 11 origens de scanner
  │ NVD: 0 enriquecidos, 0 do cache, 0 sem registro em 1 consultados.
    Enriquecimento NVD indisponível: não foi possível consultar a NVD
    (CVE-2021-44228): não foi possível estabelecer conexão com o serviço
    — o relatório base foi gerado normalmente.
  Total de achados: 11
  CRÍTICAS: 1   ALTAS: 0   MÉDIAS: 0   BAIXAS: 0   INFORMATIVAS: 10
  OK Relatório exportado: smartsec-report.md
  OK Log estruturado: …/smartsec/scans/scan_1790805850249330875.json
  OK Análise concluída.
```

Os **11 achados** e a severidade **CRÍTICA** saíram idênticos. O relatório base
foi gravado e o log estruturado também. A causa ficou visível:

```json
{
  "correlation": { "input_count": 11, "output_count": 11, "merged_groups": 0, "conflicts": 0 },
  "nvd": {
    "consulted": 1,
    "enriched": 0,
    "cached": 0,
    "not_found": 0,
    "unavailable_reasons": [
      "não foi possível consultar a NVD (CVE-2021-44228): não foi possível estabelecer conexão com o serviço"
    ]
  }
}
```

No relatório:

```
## Correlação e enriquecimento CVE/NVD

- correlação: 11 achados consolidados a partir de 11 origens de scanner
- NVD: 0 enriquecidos, … Enriquecimento NVD indisponível: … — o relatório base foi gerado normalmente.
- Cache local da NVD: `…/smartsec/nvd-cache` com validade de 7 dias.
- Limite de taxa respeitado: 5 requisições a cada 30 s (intervalo mínimo de 6000 ms, sem chave de API).
- **Nota:** a indisponibilidade da NVD não altera a severidade de nenhum achado e não impede a emissão deste relatório.
```

### Caminhos que degradam

Todos verificados por teste; **nenhum** usa `unwrap`, `expect` ou `panic`:

| Caminho | Resultado |
|---|---|
| cliente não inicializável | `Unavailable("o cliente da NVD não pôde ser inicializado…")` |
| DNS / conexão recusada | `Unavailable("não foi possível estabelecer conexão com o serviço")` |
| timeout (10 s por requisição) | `Unavailable("tempo limite de espera excedido")` |
| HTTP 429 | `Unavailable("… por limite de taxa; aguarde alguns segundos")` + 1 retry com backoff |
| HTTP 5xx | `Unavailable("a NVD respondeu com erro de servidor (…)")` + 1 retry com backoff |
| HTTP 404 / 4xx | `Unavailable("a NVD respondeu com status 404 para …")`, sem retry |
| JSON malformado | `Unavailable("a NVD devolveu resposta malformada…")` |
| envelope não-objeto (`[]`, texto, `null`) | `Unavailable("… não é o envelope esperado…")` |
| CVE sem registro na base | `NotFound` — é resultado, não falha |
| identificador vazio | `Unavailable("identificador CVE vazio")` |

A indisponibilidade da NVD **não** vira `run_error` nem altera o exit code: é um
aviso, exibido em destaque na TUI (`enrichment_warning`), impresso no headless e
registrado no relatório e no log.

---

## 5. Achado que só apareceu em execução real

**O TTL do cache estava errado.** A primeira versão passava
`REQUEST_TIMEOUT * 4` (40 s) para `read_cache`. Na prática isso anulava o
cache: a segunda execução voltava à NVD, estourando o limite público de taxa sem
nenhuma necessidade — visível nas duas execuções reais acima, ambas marcando
`0 do cache`.

Nenhum teste unitário pegou isso, porque os testes semeavam o cache com um TTL
injetado. Corrigido para o TTL documentado (`cache_ttl()`, 7 dias) e fixado pela
regressão `o_ttl_do_cache_e_o_documentado_e_nao_o_tempo_de_requisicao`, que
compara os dois valores e prova que um cache de uma hora é válido no TTL real e
seria descartado no TTL de requisição.

Os outros dois defeitos só apareceram porque os testes de falso duplicado foram
escritos para o caso difícil:

1. A chave `cve:<id>` sem endpoint fundia templates do mesmo CVE em páginas
   diferentes.
2. `extract_cve_ids` aceitava `CVE-2021-442` (sem os quatro dígitos de
   sequência), o que gerava uma chave de correlação errada.

---

## 6. Segurança da evidência

Verificado por contagem no relatório e em todos os logs de scan da execução:

```bash
$ grep -ciE "curl |request:|response:|Authorization|token=|?apiKey" \
    smartsec-report.md .config/smartsec/scans/*.json
smartsec-report.md:0
.config/smartsec/scans/scan_1790803902967204044.json:0
… (todos os 9 logs: 0)
```

Nenhum corpo HTTP, comando curl, credencial ou query string. O erro do
`reqwest` é traduzido por **categoria** (`is_timeout`, `is_connect`,
`is_decode`, `is_request`) em vez de `to_string()`, porque a mensagem original
inclui a URL com a query string. A query string é montada por
`RequestBuilder::query` e a chave viaja apenas no cabeçalho `apiKey`.

`Vulnerability::sanitized()` também sanitiza `origins` e `enrichment`, e não
só os campos originais — uma origem vinda de um log antigo é re-sanitizada antes
de entrar no relatório.

---

## 7. Verificações

```text
$ cargo fmt --check
(sem saída)

$ cargo clippy --all-targets -j 1 -- -D warnings
(sem saída)

$ cargo test -j 1
test result: ok. 262 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok.  69 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok.   3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok.   6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok.  12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

**352 testes, todos verdes.**

Os três casos exigidos pelos critérios de aceite têm teste dedicado em
`tests/correlation_nvd.rs`:

| Caso | Teste |
|---|---|
| correlação real | `achados_correlacionados_preservam_todas_as_evidencias_e_origens` |
| conflito de severidade | `conflito_entre_scanners_preserva_as_duas_severidades` |
| falso duplicado | `falsos_duplicados_permanecem_separados` |

O terceiro é o mais denso: cobre mesmo template em endpoints diferentes,
mesmo endpoint com testes do Nikto diferentes, e evidência sem identidade
estrutural que nunca pode ser fundida.