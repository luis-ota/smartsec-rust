#!/usr/bin/env python3
"""Servidor OpenAI-compatible local, usado APENAS para gerar evidencia da issue #23.

Este script nao faz parte do aplicativo: o SmartSec nao conhece esta porta nem
este conteudo. Ele existe para que a evidencia de `docs/evidence/issue-23-ia-tui-headless.md`
possa ser reproduzida em qualquer maquina, sem depender de um modelo real.

Uso:  python3 scripts/evidence_fake_openai_server.py <porta> <conteudo>
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    content = "Revise a exposicao do servico e valide novamente."

    def do_POST(self):  # noqa: N802 (nome exigido pela biblioteca)
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        body = json.dumps(
            {
                "choices": [
                    {"message": {"role": "assistant", "content": self.content}}
                ]
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8098
    if len(sys.argv) > 2:
        Handler.content = sys.argv[2]
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
