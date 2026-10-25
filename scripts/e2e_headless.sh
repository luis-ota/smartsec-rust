#!/usr/bin/env bash
# Executa um scan headless real do SmartSec e valida os artefatos.
#
# Uso:
#   SMARTSEC_TARGET='http://169.254.1.2:3000' \
#   SMARTSEC_TOOLS='Nmap,Nuclei,Nikto,SQLMap,ZAP' \
#   SMARTSEC_PROJECT=/caminho/do/projeto \
#   ./scripts/e2e_headless.sh
#
# Variáveis:
#   SMARTSEC_BIN        binário (padrão: target/release/smartsec)
#   SMARTSEC_TARGET     alvo autorizado (padrão: http://169.254.1.2:3000)
#   SMARTSEC_TOOLS      ferramentas separadas por vírgula
#   SMARTSEC_PROJECT    projeto para o agente de código
#   SMARTSEC_OUT        diretório dos artefatos
#   SMARTSEC_LLM        provedor (padrão: openai)
#   SMARTSEC_MODEL      modelo (padrão: gpt-4o-mini)
#   SMARTSEC_FAIL_ON_CRITICAL  se "true", exit 1 quando houver crítico
#
# O script NÃO inicia alvo, Podman, pasta ou templates: ele valida o binário e
# o ambiente existentes. O objetivo é ser reproduzível na máquina de gravação.

set -euo pipefail

readonly RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly BIN="${SMARTSEC_BIN:-$RAIZ/target/release/smartsec}"
readonly ALVO="${SMARTSEC_TARGET:-http://169.254.1.2:3000}"
readonly FERRAMENTAS="${SMARTSEC_TOOLS:-Nmap,Nuclei,Nikto,SQLMap,ZAP}"
readonly PROJETO="${SMARTSEC_PROJECT:-$RAIZ}"
readonly PROVEDOR="${SMARTSEC_LLM:-openai}"
readonly MODELO="${SMARTSEC_MODEL:-gpt-4o-mini}"
readonly FALHAR_CRITICO="${SMARTSEC_FAIL_ON_CRITICAL:-false}"
readonly SAIDA="${SMARTSEC_OUT:-$RAIZ/e2e-artifacts/headless-$(date +%Y%m%d-%H%M%S)}"

falhar() {
    printf 'FALHA: %s\n' "$*" >&2
    printf 'Artefatos preservados em: %s\n' "$SAIDA" >&2
    exit 1
}

for cmd in bash jq rg find; do
    command -v "$cmd" >/dev/null || falhar "dependência ausente: $cmd"
done
[ -x "$BIN" ] || falhar "binário não executável: $BIN (rode cargo build --release)"

mkdir -p "$SAIDA"

printf 'SmartSec: %s\n' "$("$BIN" --version)"
printf 'Alvo:     %s\n' "$ALVO"
printf 'Ferramentas: %s\n' "$FERRAMENTAS"
printf 'Projeto:  %s\n' "$PROJETO"
printf 'Saída:    %s\n\n' "$SAIDA"

inicio="$(date +%s)"
set +e
"$BIN" scan \
    --target "$ALVO" \
    --tools "$FERRAMENTAS" \
    --project "$PROJETO" \
    --llm "$PROVEDOR" \
    --model "$MODELO" \
    --output-dir "$SAIDA" \
    2>&1 | tee "$SAIDA/scan.log"
codigo="${PIPESTATUS[0]}"
set -e
printf '%s\n' "$codigo" > "$SAIDA/exit-code.txt"

[ -s "$SAIDA/smartsec-report.md" ] || falhar "relatório Markdown ausente/vazio"
[ -s "$SAIDA/smartsec-report.pdf" ] || falhar "relatório PDF ausente/vazio"

# O ID é impresso no fim do log; usá-lo evita pegar um scan antigo.
scan_id="$(grep -oE 'scan_[0-9]+' "$SAIDA/scan.log" | tail -1 || true)"
[ -n "$scan_id" ] || falhar "não foi possível identificar o scan_id no log"
auditoria="$HOME/.config/smartsec/scans/${scan_id}.json"
[ -s "$auditoria" ] || falhar "auditoria não encontrada: $auditoria"
cp -p "$auditoria" "$SAIDA/"

# Contrato mínimo da auditoria e do relatório.
jq -e '
  (.tools_executed | type == "array" and length > 0)
  and (.findings | type == "array")
  and (.runtime.phase == "completed")
  and (.agent_analysis | type == "string" and length > 0)
' "$auditoria" >/dev/null || falhar "auditoria não contém tools/findings/runtime/agent_analysis válidos"

# Nenhum segredo óbvio nos artefatos publicáveis.
if rg -i -n \
    'authorization:[[:space:]]|bearer[[:space:]]|set-cookie:|api[_-]?key[[:space:]]*[:=][[:space:]]*[^" ]|secret[[:space:]]*[:=][[:space:]]*[^" ]' \
    "$SAIDA/smartsec-report.md" "$auditoria" >/dev/null; then
    falhar "padrão de credencial encontrado no relatório/auditoria"
fi

# Containers residuais do SmartSec.
residuais="$(podman ps -a --format '{{.Names}}' 2>/dev/null | grep '^smartsec-' || true)"
[ -z "$residuais" ] || falhar "containers SmartSec residuais: $residuais"

total="$(jq '.findings | length' "$auditoria")"
criticos="$(jq '[.findings[] | select(.severity == "CRÍTICA" or .severity == "CRITICA" or .severity == "CRITICAL")] | length' "$auditoria")"
localizados="$(jq '.code_located_count // 0' "$auditoria")"
chamadas="$(jq '.code_tool_calls_count // 0' "$auditoria")"
duracao="$(( $(date +%s) - inicio ))s"

printf '\nResumo:\n'
printf '  scan_id:       %s\n' "$scan_id"
printf '  exit code:     %s\n' "$codigo"
printf '  duração:       %s\n' "$duracao"
printf '  achados:       %s (críticos: %s)\n' "$total" "$criticos"
printf '  localizados:   %s\n' "$localizados"
printf '  chamadas IA:   %s\n' "$chamadas"
printf '  relatório:     %s\n' "$SAIDA/smartsec-report.md"
printf '  PDF:           %s\n' "$SAIDA/smartsec-report.pdf"
printf '  auditoria:     %s\n' "$SAIDA/${scan_id}.json"

case "$codigo" in
    0) ;;
    1)
        if [ "$FALHAR_CRITICO" = "true" ]; then
            falhar "achado crítico encontrado (exit 1) e SMARTSEC_FAIL_ON_CRITICAL=true"
        fi
        printf 'Aviso: achado crítico encontrado; artefatos preservados.\n' >&2
        ;;
    *) falhar "SmartSec retornou exit code $codigo (erro de configuração/execução)" ;;
esac

printf 'OK: scan headless e artefatos validados.\n'
