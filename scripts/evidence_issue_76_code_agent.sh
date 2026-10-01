#!/usr/bin/env bash
# Evidencia reproduzivel da issue #76 (agente de codigo).
#
# Sobe um alvo autorizado em 127.0.0.1, aponta o runner para o IP da rede
# rootless `pasta` (169.254.1.2) e executa o binario em modo headless sobre um
# projeto de fixture. Ao final imprime o que cada criterio de aceite produz.
#
# Nenhuma chave de API e nenhum modelo hospedado sao usados. O provedor de IA e
# o script local scripts/evidence_fake_openai_server.py, que o aplicativo
# desconhece e que existe apenas para tornar esta evidencia reproduzivel.
#
# Implica em: cargo, python3, curl, jq e rg, e nas imagens do Nmap ja presentes
# no Podman local.

set -euo pipefail

OUT="${1:-/tmp/ev76}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURE="$ROOT/tests/fixtures/codebase"
PROJECT="$OUT/projeto"
FAKE="$OUT/fake_openai.py"

rm -rf "$OUT"
mkdir -p "$PROJECT/src" "$OUT/saida"

# Projeto alvo: copia da fixture de codebase, para que a analicao de codigo
# tenha uma arvore real e nao a propria arvore do SmartSec.
cp -r "$FIXTURE/." "$PROJECT/"

# Alvo local autorizado, servido por um servidor estatico do proprio Python.
PORT=38198
cat > "$OUT/alvo.py" <<'PY'
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><title>alvo autorizado</title></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
socketserver.TCPServer(("127.0.0.1", int(__import__("os").environ["PORT"])), H).serve_forever()
PY
PORT=$PORT python3 "$OUT/alvo.py" &
ALVO_PID=$!

# Provedor de IA local, que responde a um turno de tool calling: pede a leitura
# de um arquivo do projeto e depois responde com a localizacao em JSON.
cat > "$FAKE" <<'PY'
import json, os, re, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

STATE = {"asked": False}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        msgs = body.get("messages", [])
        already = any(m.get("role") == "tool" for m in msgs)
        if not already:
            msg = {"role": "assistant", "content": "",
                   "tool_calls": [{"id": "c1", "type": "function", "function": {
                       "name": "read_file",
                       "arguments": json.dumps({"path": "src/app.py"})}}]}
        else:
            msg = {"role": "assistant", "content": json.dumps({
                "localizacao": {"arquivo": "src/app.py", "linha": 4},
                "passos": ["Valide o usuario antes de prosseguir",
                           "Adicione teste de regressao"]})}
        payload = json.dumps({"choices": [{"message": msg}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

HTTPServer(("127.0.0.1", int(os.environ["PORT"])), H).serve_forever()
PY

echo "==> compilando"
cd "$ROOT"
cargo build -j 1

echo "==> iniciando alvo autorizado em 127.0.0.1:$PORT"
sleep 1

LLM_PORT=38199
PORT=$LLM_PORT python3 "$FAKE" &
FAKE_PID=$!
sleep 1

# O provedor e `custom` apontado para o script local. A base_url vai no TOML
# porque a flag --llm reescreve a base para o padrao do provedor.
cat > "$OUT/smartsec.toml" <<TOML
target_url = "http://169.254.1.2:$PORT"
active_tools = ["Nmap"]
project_dir = "$PROJECT"
output_dir = "$OUT/saida"
output_file = "relatorio.md"

[llm]
provider = "custom"
base_url = "http://127.0.0.1:$LLM_PORT/v1"
model = "modelo-de-evidencia"
TOML

echo "==> executando headless com --project $PROJECT"
set +e
"$ROOT/target/debug/smartsec-rust" scan \
    --config "$OUT/smartsec.toml" \
    --target "http://169.254.1.2:$PORT" \
    --tools Nmap \
    --project "$PROJECT" \
    2>&1 | tee "$OUT/saida/stdout.txt"
STATUS=${PIPESTATUS[0]}
set -e

kill "$ALVO_PID" "$FAKE_PID" 2>/dev/null || true

echo
echo "==> exit code: $STATUS"
echo
echo "==> secao do relatorio:"
sed -n '/## Localização no código/,/^## Proveniência/p' "$OUT/saida/relatorio.md"

LOG="$(ls -t "$HOME"/.config/smartsec/scans/*.json 2>/dev/null | head -1 || true)"
if [ -n "$LOG" ]; then
  echo
  echo "==> campos da fase no log estruturado ($LOG):"
  jq '{code_project_dir, code_located_count, code_tool_calls_count,
       code_unavailable_reason,
       tool_calls: [.code_tool_calls[] | {tool, outcome, arguments}]}' "$LOG"
  echo
  echo "==> localizacao gravada no achado:"
  jq '[.findings[] | {titulo: .title, arquivo: .code_location.file,
       linha: .code_location.line, correcao: .code_remediation}]' "$LOG"
fi

echo
echo "==> projeto analisado nao foi modificado:"
( cd "$PROJECT" && find . -type f | sort )