#!/usr/bin/env bash
# Gera a evidencia reproduzivel da issue #23: o mesmo servico de analise da IA
# no modo headless, no caminho de sucesso e no caminho de timeout com fallback.
#
# Nao usa chave de API nem modelo hospedado. O provedor e o script local
# `evidence_fake_openai_server.py`, que o aplicativo desconhece: ele existe
# apenas para tornar a evidencia reproduzivel.
#
# Uso: scripts/evidence_issue_23_ia.sh [diretorio-de-saida]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$(mktemp -d "${TMPDIR:-/tmp}/smartsec-evidence-23.XXXXXX")}"
OK_PORT="${SMARTSEC_EVIDENCE_PORT:-38198}"
HANG_PORT="${SMARTSEC_EVIDENCE_HANG_PORT:-38199}"
ALT_PORT="${SMARTSEC_EVIDENCE_ALT_PORT:-38200}"
TARGET_PORT="${SMARTSEC_EVIDENCE_TARGET_PORT:-38197}"
ROOTLESS_NET="169.254.1.2"
WORK="$OUT/work"
BIN="$REPO_ROOT/target/debug/smartsec-rust"
FAKE="$REPO_ROOT/scripts/evidence_fake_openai_server.py"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

fail() { printf 'FALHA: %s\nEvidências parciais em: %s\n' "$1" "$OUT" >&2; exit 1; }

for command in cargo python3 curl jq rg; do
  command -v "$command" >/dev/null || fail "dependência ausente: $command"
done

wait_port() {
  for _ in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then exec 3>&- 2>/dev/null; return 0; fi
    sleep 0.25
  done
  return 1
}

# Alvo autorizado local, servido apenas em 127.0.0.1. O runner o alcança pelo
# IP da rede rootless `pasta` (169.254.1.2), como no fluxo real.
mkdir -p "$WORK/alvo" "$OUT/config"
printf '<!doctype html><html lang="pt-BR"><title>Alvo autorizado</title><body>SmartSec evidencia 23</body></html>\n' \
  >"$WORK/alvo/index.html"
python3 -m http.server "$TARGET_PORT" --bind 127.0.0.1 --directory "$WORK/alvo" \
  >"$WORK/alvo.log" 2>&1 &
PIDS+=("$!")
wait_port "$TARGET_PORT" || fail "o alvo local não iniciou na porta $TARGET_PORT"
TARGET="http://$ROOTLESS_NET:$TARGET_PORT"

cargo build --manifest-path "$REPO_ROOT/Cargo.toml" --quiet
[[ -x "$BIN" ]] || fail "binário não encontrado: $BIN"

run_headless() {
  local config="$1" nome="$2"
  ( cd "$WORK" && env XDG_CONFIG_HOME="$OUT/config" HOME="$WORK" \
      "$BIN" scan --target "$TARGET" --config "$config" \
      --output-dir "$WORK/relatorio-$nome" >"$WORK/headless-$nome.txt" 2>&1
    echo $? >"$WORK/headless-$nome.exit" ) || true
}

# --- Caminho 1: o provedor configurado responde dentro do contrato -----------
GUIDANCE="Revise a exposicao do servico e valide o TLS. Aplique hardening."
python3 "$FAKE" "$OK_PORT" "$GUIDANCE" --dump-prompt "$WORK/prompt-recebido.txt" \
  >"$WORK/provedor-sucesso.log" 2>&1 &
PIDS+=("$!")
wait_port "$OK_PORT" || fail "o provedor fake não iniciou na porta $OK_PORT"

cat >"$WORK/sucesso.toml" <<EOF
target_url = "$TARGET"
active_tools = ["nmap"]
execution_type = "Auto"

[llm]
provider = "Custom"
base_url = "http://127.0.0.1:$OK_PORT/v1"
model = "gpt-4o"
api_key = "evidence-local"
remote_consent = true
timeout_secs = 5
max_retries = 0
EOF

run_headless "$WORK/sucesso.toml" sucesso

# --- Caminho 2: o provedor configurado trava; a alternativa local responde ---
# Primário em --hang (aceita e não responde) e alternativa local na ALT_PORT.
python3 "$FAKE" "$HANG_PORT" --hang >"$WORK/provedor-timeout.log" 2>&1 &
PIDS+=("$!")
wait_port "$HANG_PORT" || fail "o provedor em --hang não iniciou na porta $HANG_PORT"

python3 "$FAKE" "$ALT_PORT" "$GUIDANCE" >"$WORK/provedor-alternativa.log" 2>&1 &
PIDS+=("$!")
wait_port "$ALT_PORT" || fail "a alternativa local não iniciou na porta $ALT_PORT"

cat >"$WORK/timeout.toml" <<EOF
target_url = "$TARGET"
active_tools = ["nmap"]
execution_type = "Auto"

[llm]
provider = "Custom"
base_url = "http://127.0.0.1:$HANG_PORT/v1"
model = "gpt-4o"
api_key = "evidence-local"
remote_consent = true
timeout_secs = 3
max_retries = 0
fallback_enabled = true
fallback_base_url = "http://127.0.0.1:$ALT_PORT/v1"
fallback_model = "llama3.1:8b"
EOF

run_headless "$WORK/timeout.toml" timeout

# --- Verificações sobre os artefatos ---------------------------------------
mapfile -t AUDITS < <(find "$OUT/config/smartsec/scans" -maxdepth 1 -name '*.json' 2>/dev/null | sort)
[[ "${#AUDITS[@]}" -ge 1 ]] || fail "nenhum log estruturado foi gravado"

printf 'Evidência bruta em: %s\n' "$OUT"
for audit in "${AUDITS[@]}"; do
  printf -- '--- %s\n' "$(basename "$audit")"
  jq -c '{llm_provider, llm_model, llm_provider_effective, llm_fallback_used, llm_failure_reason, llm_analyzed_at, llm_neutralized_snippets}' "$audit"
done
