# Exemplo de CI — SmartSec headless

Este diretório contém um workflow de exemplo para usar o SmartSec no CI de
**outro repositório**, com IA real, Podman rootless e artefatos auditáveis.
Ele não substitui o CI do próprio projeto (`.github/workflows/ci.yml`).

## Arquivo

- [`github-actions-smartsec.yml`](github-actions-smartsec.yml) — workflow do
  GitHub Actions, disparado manualmente (`workflow_dispatch`). O `schedule`
  semanal está comentado para evitar custo e varreduras não autorizadas.

Copie o arquivo para `.github/workflows/smartsec.yml` no repositório da
aplicação e ajuste:

| Item | O que revisar |
|---|---|
| `SMARTSEC_REF` | Tag ou SHA do SmartSec. Não use branch móvel em produção. |
| `SMARTSEC_PASTA_COMMIT` | Commit do `pasta` que aceita `--map-host-loopback`. |
| `SMARTSEC_NUCLEI_COMMIT` | Commit dos templates; o binário recusa outro. |
| `OPENAI_API_KEY` | Secret do repositório. Sem ele, o provedor remoto falha. |
| `target` | URL/IP **autorizado**. O workflow não verifica autorização por você. |
| `tools` | Lista de ferramentas. `TruffleHog` exige um caminho de repositório como `target`, não uma URL. |
| `project` | Diretório do código que o agente pode ler para localizar correções. |
| `fail_on_critical` | `true` bloqueia o job em achado crítico (exit 1). |

## O que o workflow faz

1. Compila/instala o SmartSec a partir de uma ref fixa.
2. Compila o `pasta` homologado (o do runner pode não aceitar
   `--map-host-loopback`).
3. Confirma Podman rootless e monta uma tmpfs de trabalho.
4. Baixa os templates do Nuclei no commit esperado.
5. Executa `smartsec scan` headless contra o alvo, com `SMARTSEC_API_KEY`
   apenas como override de sessão (não grava a chave).
6. Publica como artefato:
   - `artifacts/smartsec-report.md`
   - `artifacts/smartsec-report.pdf`
   - `artifacts/scan.log`
   - `artifacts/scan_*.json` (auditoria estruturada)
7. Aplica o contrato de exit codes:
   - `0` — scan concluído sem achado crítico;
   - `1` — scan concluído com achado crítico (falha só se
     `fail_on_critical=true`);
   - `2` — erro de configuração/execução (sempre falha);
   - qualquer outro — falha inesperada.

## Exit codes e gate de merge

O exit code do SmartSec é resultado de negócio, não defeito do pipeline. Por
isso o passo do scan usa `continue-on-error` e o veredito fica explícito em um
passo separado. Para bloquear merge em achado crítico, mantenha
`fail_on_critical=true`; para apenas publicar evidências, use `false`.

## Limitações conhecidas

- O runner precisa de **Podman rootless**; Docker privilegiado não é
  equivalente e o SmartSec recusa executar sem rootless.
- O `pasta` do sistema pode não suportar `--map-host-loopback`; o workflow
  compila o commit homologado.
- O executor exige tmpfs para diretórios temporários; o workflow monta
  `/var/tmp/smartsec` e exporta `TMPDIR`.
- O Nuclei exige um checkout Git no commit fixado. Atualizar o commit no
  binário e no workflow juntos.
- A IA remota consome tokens. O orçamento do agente de código é limitado
  (120 chamadas e 180 s por fase), mas a análise de logs ainda tem custo.
- O relatório é Markdown/PDF; o SmartSec não gera SARIF. Não anexe um SARIF
  inventado; publique os artefatos reais.
- Segredos nunca devem ir para o TOML, para o relatório ou para o artefato.
  Use `SMARTSEC_API_KEY`/secret e confira o `scan.log` antes de compartilhar.

## Teste local do mesmo caminho

O script [`../../scripts/e2e_headless.sh`](../../scripts/e2e_headless.sh)
executa o mesmo fluxo localmente e valida os artefatos:

```bash
SMARTSEC_TARGET='http://169.254.1.2:3000' \
SMARTSEC_TOOLS='Nmap,Nuclei,Nikto,SQLMap,ZAP' \
SMARTSEC_PROJECT=/caminho/do/projeto \
./scripts/e2e_headless.sh
```

Ele exige alvo autorizado, Podman rootless, `pasta` com
`--map-host-loopback`, templates do Nuclei e a chave no `auth.json` ou em
`SMARTSEC_API_KEY`.
