# Issue #76 — Análise da codebase com IA

Evidencia reproduzivel da fase que localiza a origem dos achados no codigo do
projeto analisado e explica a correcao no proprio codigo.

Objetivo: mostrar, com saida real, que o headless recebe `--project`, produz
`arquivo:linha` verificavel, grava a localizacao no relatorio e no log
estruturado, e nao modifica o projeto analisado.

Nenhuma chave de API e nenhum modelo hospedado sao usados. O provedor de IA e o
script local definido dentro de `scripts/evidence_issue_76_code_agent.sh`, que o
aplicativo desconhece e que existe apenas para tornar esta evidencia
reproduzivel. O alvo e um servidor local autorizado em `127.0.0.1`, alcancavel
pelo runner pelo IP da rede rootless `pasta` (`169.254.1.2`).

## Como reproduzir

```bash
cargo build
scripts/evidence_issue_76_code_agent.sh /tmp/ev76
```

Implica em `cargo`, `python3`, `curl`, `jq` e `rg`, e na imagem do Nmap ja
presente no Podman local.

Ambiente desta execucao: Linux, Podman 6.1.1 rootless, imagem
`docker.io/instrumentisto/nmap:7.95`, alvo local `http://169.254.1.2:38198`,
projeto alvo `/tmp/ev76/projeto` (copia de `tests/fixtures/codebase`).

## 1. A flag `--project` e reconhecida e o diretorio entra na saida

O cabecalho da execucao mostra o alvo; a fase do agente de codigo e a etapa
`[3/4]`, depois dos scanners e da analise de logs:

```text
[3/4] Localização no código (projeto: /tmp/ev76/projeto)
  │ [INFORMATIVA] Porta 38198 — BaseHTTPServer 0.6 exposto
    código: src/app.py:4
    correção: Valide o usuario antes de prosseguir
    correção: Adicione teste de regressao
  │ 1 de 1 achados com origem localizada no código
```

O criterio de aceite pede `arquivo:linha`; a saida traz `código: src/app.py:4`,
com os passos de correcao do modelo abaixo.

## 2. A linha existe de verdade no projeto analisado

`/tmp/ev76/projeto/src/app.py`, linha 4:

```python
def login(user):
    """Autentica um usuário fictício da fixture."""
    if not user:
        raise ValueError("login exige usuário")
    return user
```

A linha 4 e `raise ValueError("login exige usuário")` — exatamente o que o
relatorio mostra no bloco de trecho. A linha nao foi inventada: ela so entra no
resultado se o agente a leu pelo sandbox durante o laço.

## 3. A localizacao chega ao relatorio

Secao `## Localização no código` do `relatorio.md`:

```text
## Localização no código

- Achados com origem localizada: 1 de 1

### [INFORMATIVA] Porta 38198 — BaseHTTPServer 0.6 exposto

**Arquivo:** `src/app.py` · **Linha:** 4

```
raise ValueError("login exige usuário")
```

**Correção sugerida:**

- Valide o usuario antes de prosseguir
- Adicione teste de regressao
```

O cabecalho do relatorio declara qual arvore foi analisada:

```text
**Projeto analisado:** /tmp/ev76/projeto
```

E a **severidade nao muda**: o scanner classificou como INFORMATIVA e a secao de
codigo repete `INFORMATIVA`. O agente aponta onde corrigir e nunca reclassifica
(TCC_SPEC, secao 7).

## 4. O log estruturado registra o rastro da fase

Campos novos em `~/.config/smartsec/scans/scan_*.json`:

```json
{
  "code_project_dir": "/tmp/ev76/projeto",
  "code_located_count": 1,
  "code_tool_calls_count": 1,
  "code_unavailable_reason": null,
  "tool_calls": [
    {
      "tool": "read_file",
      "outcome": "ok",
      "arguments": "{\"path\":\"src/app.py\"}"
    }
  ]
}
```

E a localizacao gravada no proprio achado:

```json
[
  {
    "titulo": "Porta 38198 — BaseHTTPServer 0.6 exposto",
    "arquivo": "src/app.py",
    "linha": 4,
    "correcao": [
      "Valide o usuario antes de prosseguir",
      "Adicione teste de regressao"
    ]
  }
]
```

O `code_project_dir` e gravado mesmo quando **zero** achados sao localizados: e
ele que distingue "a fase rodou e nao achou origem" de "a fase nunca rodou".

## 5. O projeto analisado nao foi modificado

Lista de arquivos do projeto ao final da execucao:

```text
./build/ignored.py
./dist/ignored.py
./node_modules/ignored.js
./README.md
./src/app.py
./src/binary.bin
./src/config.py
./src/nested/deep.py
./target/ignored.rs
```

Idêntica à fixture de origem. Nenhum arquivo criado, nenhum alterado.

## 6. O provedor de IA sem tool calling degrada sem inventar

Nesta execucao o provedor respondeu aos dois turnos. O caminho oposto — provedor
que **nao** implementa tool calling — é coberto por teste automatizado, porque
depende de um trait e não de uma execução real:

```text
code_agent::agent::tests::a_provider_without_tool_calling_never_invents_a_location ... ok
```

O resultado nesse caso é `localização não determinada` com o motivo "o provedor
configurado não implementa tool calling", e nenhuma chamada de ferramenta.

## 7. Consentimento remoto (RNF10)

Um provedor remoto sem consentimento bloqueia a fase **antes** do primeiro turno:

```text
code_agent::agent::tests::remote_consent_blocks_the_phase_before_any_turn ... ok
pipeline::tests::a_remote_provider_without_consent_blocks_the_code_phase ... ok
```

Nenhum turno é aberto — nem um turno sem ferramentas — porque qualquer ida ao
provedor já seria envio do código do alvo.

## 8. `run_command` recusado sem opt-in

`run_command` nasce desabilitado porque o pipeline nunca concede allowlist:

```text
code_agent::tools::tests::run_command_is_denied_without_allowlist ... ok
code_agent::tools::tests::run_command_denies_program_outside_allowlist ... ok
code_agent::tools::tests::run_command_timeout_interrupts_the_process ... ok
```

## Mapa criterio de aceite -> verificacao

| Criterio | Onde esta demonstrado |
|---|---|
| Headless `scan --project` localiza `arquivo:linha`, grava no log e no relatorio | Secoes 1, 3 e 4 desta evidencia; `tests/code_agent_integration.rs` |
| TUI exibe localizacao e correcao por achado | `screens::results::tests::the_detail_shows_the_location_and_the_remediation_at_80x24` |
| Agente usa so as ferramentas registradas e nunca sai do diretorio | `workspace.rs` (symlink e `..`), `a_location_outside_the_workspace_is_never_accepted`, `observe_search_hits` |
| `run_command` exige opt-in e allowlist, recusa acionavel | Secao 8 |
| Provedor sem tool calling cai no fallback sem inventar | Secao 6 |
| Segredos mascarados; consentimento remoto respeitado | Secao 7; `secrets_never_reach_the_provider_or_the_analysis`, `the_code_agent_audit_trail_is_sanitized_before_persistence` |
| Testes com provedor fake e fixtures; limites, recusas e timeouts | `ScriptedProvider` em `agent.rs`; `tests/fixtures/codebase/` |
| Fluxo, limites e riscos documentados | `docs/AGENTE_DE_CODIGO.md`, secao 7 do `TCC_SPEC.md` |
| Nunca escreve no projeto analisado | Secao 5; `the_phase_never_writes_in_the_analyzed_project` |