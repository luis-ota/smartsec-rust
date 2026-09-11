#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
E2E_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/smartsec-tui-e2e.XXXXXX")"
CONFIG_ROOT="$E2E_ROOT/config"
TARGET_ROOT="$E2E_ROOT/alvo"
EVIDENCE_ROOT="$E2E_ROOT/evidencias"
SESSION="smartsec-e2e-$$"
PORT="${SMARTSEC_E2E_PORT:-38153}"
TARGET="http://169.254.1.2:$PORT"
TUI_STDERR="$EVIDENCE_ROOT/tui.stderr"
SERVER_LOG="$EVIDENCE_ROOT/alvo.log"
SERVER_PID=""

cleanup() {
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

fail() {
  printf 'FALHA: %s\n' "$1" >&2
  printf 'Evidências preservadas em: %s\n' "$EVIDENCE_ROOT" >&2
  exit 1
}

for command in cargo curl jq podman python3 rg tmux; do
  command -v "$command" >/dev/null || fail "dependência ausente: $command"
done

[[ "$(podman info --format '{{.Host.Security.Rootless}}')" == "true" ]] \
  || fail "o Podman precisa estar em modo rootless"
[[ -d "$HOME/nuclei-templates/.git" ]] \
  || fail "templates do Nuclei ausentes em $HOME/nuclei-templates"

mkdir -p "$CONFIG_ROOT" "$TARGET_ROOT" "$EVIDENCE_ROOT"
printf '<!doctype html><html lang="pt-BR"><title>Alvo autorizado</title><body>SmartSec E2E</body></html>\n' \
  >"$TARGET_ROOT/index.html"

if [[ -n "${SMARTSEC_BIN:-}" ]]; then
  BIN="$SMARTSEC_BIN"
else
  cargo build --manifest-path "$REPO_ROOT/Cargo.toml" --quiet
  BIN="$REPO_ROOT/target/debug/smartsec-rust"
fi
[[ -x "$BIN" ]] || fail "binário não executável: $BIN"

python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$TARGET_ROOT" \
  >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 20); do
  if curl --fail --silent --max-time 1 "http://127.0.0.1:$PORT" >/dev/null; then
    break
  fi
  sleep 0.25
done
curl --fail --silent --max-time 1 "http://127.0.0.1:$PORT" >/dev/null \
  || fail "o alvo local não iniciou na porta $PORT"

mapfile -t CONTAINERS_BEFORE < <(podman ps -a --format '{{.Names}}' | rg '^smartsec-' | sort || true)

tmux new-session -d -s "$SESSION" -x 80 -y 24 -c "$E2E_ROOT" \
  "env XDG_CONFIG_HOME='$CONFIG_ROOT' '$BIN' 2>'$TUI_STDERR'"
sleep 1

# Alvo, modo automático e abertura da configuração.
tmux send-keys -t "$SESSION" -l "$TARGET"
tmux send-keys -t "$SESSION" Tab Enter Tab Tab Enter
sleep 1
tmux capture-pane -p -t "$SESSION" >"$EVIDENCE_ROOT/configuracoes-80x24.txt"
rg -q 'Configurações de IA' "$EVIDENCE_ROOT/configuracoes-80x24.txt" \
  || fail "a tela de configurações não abriu"
rg -q 'Conexão principal' "$EVIDENCE_ROOT/configuracoes-80x24.txt" \
  || fail "a organização contextual da configuração não foi renderizada"

# Seis campos locais visíveis levam do provedor ao botão Salvar.
tmux send-keys -t "$SESSION" Tab Tab Tab Tab Tab Tab Enter
sleep 1
tmux capture-pane -p -t "$SESSION" >"$EVIDENCE_ROOT/inicio-apos-salvar.txt"
rg -q 'Nova análise' "$EVIDENCE_ROOT/inicio-apos-salvar.txt" \
  || fail "a configuração válida não foi salva"

# O foco retorna a Configurar IA; Tab seleciona Iniciar.
tmux send-keys -t "$SESSION" Tab Enter

RESULTS_READY=false
for _ in $(seq 1 240); do
  sleep 1
  if ! tmux has-session -t "$SESSION" 2>/dev/null; then
    fail "a TUI encerrou antes de apresentar os resultados"
  fi
  tmux capture-pane -p -t "$SESSION" >"$EVIDENCE_ROOT/estado-atual.txt" \
    || fail "não foi possível capturar o estado atual da TUI"
  if rg -q '^ SmartSec  / Resultados  05/05' "$EVIDENCE_ROOT/estado-atual.txt"; then
    RESULTS_READY=true
    break
  fi
done
[[ "$RESULTS_READY" == "true" ]] || fail "a TUI não concluiu em 240 segundos"
cp "$EVIDENCE_ROOT/estado-atual.txt" "$EVIDENCE_ROOT/resultados-80x24.txt"

# Resultados -> Nova análise -> Exportar.
tmux send-keys -t "$SESSION" Tab Tab Enter
for _ in $(seq 1 20); do
  [[ -f "$E2E_ROOT/smartsec-report.md" ]] && break
  sleep 0.25
done
[[ -s "$E2E_ROOT/smartsec-report.md" ]] || fail "o relatório Markdown não foi exportado"

mapfile -t AUDITS < <(find "$CONFIG_ROOT/smartsec/scans" -maxdepth 1 -type f -name '*.json' -print)
[[ "${#AUDITS[@]}" -eq 1 ]] || fail "era esperado exatamente um log de auditoria"
AUDIT="${AUDITS[0]}"

jq -e '
  ([.tools_executed[] | select(.tool_name == "Nmap" or .tool_name == "Nuclei")] | length) == 2
  and ([.tools_executed[] | select(.tool_name == "Nmap" or .tool_name == "Nuclei") | .status] | all(. == "succeeded"))
  and ([.findings[] | select(.source != "Real")] | length) == 0
  and ([.findings[] | select(.tool == "Nuclei")] | length) > 0
  and ([.findings[] | select(.tool == "Nuclei") | .evidence]
    | all(test("^template: .+ \\| matcher: .+ \\| endpoint: .+ \\| host: .+ \\| url: .+ \\| tags: ")))
  and (.agent_analysis | startswith("Análise concluída:"))
  and (.agent_analysis | test("critical|high severity|medium severity|low severity"; "i") | not)
' "$AUDIT" >/dev/null || fail "status, ferramentas ou proveniência inválidos na auditoria"

if rg -i -q '"(request|response|curl-command)"|authorization:|bearer[[:space:]]|api[_-]?key|set-cookie:|[?&](token|secret|password)=' \
  "$AUDIT" "$E2E_ROOT/smartsec-report.md"; then
  fail "payload HTTP ou credencial apareceu em artefato persistido"
fi

sleep 1
mapfile -t CONTAINERS_AFTER < <(podman ps -a --format '{{.Names}}' | rg '^smartsec-' | sort || true)
[[ "${CONTAINERS_BEFORE[*]}" == "${CONTAINERS_AFTER[*]}" ]] \
  || fail "a execução deixou contêiner SmartSec residual"

tmux send-keys -t "$SESSION" Escape Escape

printf 'OK: E2E real da TUI concluído em terminal 80x24.\n'
printf 'Alvo autorizado: %s (servido apenas em 127.0.0.1:%s).\n' "$TARGET" "$PORT"
printf 'Ferramentas: Nmap=%s, Nuclei=%s.\n' \
  "$(jq -r '.tools_executed[] | select(.tool_name == "Nmap") | .status' "$AUDIT")" \
  "$(jq -r '.tools_executed[] | select(.tool_name == "Nuclei") | .status' "$AUDIT")"
printf 'Achados reais: %s.\n' "$(jq '[.findings[] | select(.source == "Real")] | length' "$AUDIT")"
printf 'Auditoria: %s\n' "$AUDIT"
printf 'Relatório: %s\n' "$E2E_ROOT/smartsec-report.md"
printf 'Capturas: %s\n' "$EVIDENCE_ROOT"
