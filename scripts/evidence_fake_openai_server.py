#!/usr/bin/env python3
"""Provedor OpenAI-compatible local, usado APENAS para gerar evidencia da issue #23.

Este script NAO faz parte do aplicativo: o SmartSec nao conhece esta porta nem
este conteudo, e o fluxo real nunca o invoca. Ele existe para que a evidencia de
`docs/evidence/issue-23-ia-unificada.md` seja reproduzivel em qualquer maquina,
sem depender de uma chave de API real nem de um modelo hospedado.

Dois modos, usados pela evidencia para cobrir os dois caminhos da issue:

  sucesso  python3 scripts/evidence_fake_openai_server.py <porta> "<conteudo>"
  timeout  python3 scripts/evidence_fake_openai_server.py <porta> --hang

Em `--hang` o servidor aceita a conexao e nunca responde, reproduzindo a queda
do provedor principal sem depender de rede. O tempo limite vem da configuracao
do provedor, e a alternativa local e o unico caminho de queda disponivel.

O conteudo devolvido e conferido contra o contrato de saida do SmartSec: uma
resposta em ingles, ou que cite severidade, e descartada pelo agente. Para
demonstrar o caminho de sucesso, use uma orientacao em portugues.
"""

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_CONTENT = "Revise a exposicao do servico e valide novamente."


class Handler(BaseHTTPRequestHandler):
    content = DEFAULT_CONTENT
    hang = False
    # Prompt recebido, para a evidencia mostrar o que foi de fato enviado ao
    # modelo, incluindo o bloco de dados nao confiaveis.
    last_prompt_path = None

    def do_POST(self):  # noqa: N802 (nome exigido pela biblioteca)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if self.last_prompt_path:
            try:
                payload = json.loads(raw.decode("utf-8"))
                prompt = payload.get("messages", [{}])[0].get("content", "")
                with open(self.last_prompt_path, "w", encoding="utf-8") as handle:
                    handle.write(prompt)
            except (ValueError, IndexError, KeyError, OSError):
                pass

        if self.hang:
            # Aceita a conexao e segura a resposta indefinidamente, sem fechar o
            # socket: e o que faz o provedor principal estourar o tempo limite e
            # acionar a alternativa local. O `sleep` em loop mantem a conexao viva
            # sem bloquear o laco de requisicoes.
            time.sleep(3600)

        body = json.dumps(
            {"choices": [{"message": {"role": "assistant", "content": self.content}}]}
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", nargs="?", type=int, default=8098)
    parser.add_argument("content", nargs="?", default=DEFAULT_CONTENT)
    parser.add_argument(
        "--hang",
        action="store_true",
        help="aceita a conexao e nunca responde (caminho de timeout)",
    )
    parser.add_argument(
        "--dump-prompt",
        metavar="ARQUIVO",
        help="grava o prompt recebido, para a evidencia de prompt injection",
    )
    args = parser.parse_args()

    Handler.content = args.content
    Handler.hang = args.hang
    Handler.last_prompt_path = args.dump_prompt

    # `ThreadingHTTPServer` permite que uma conexao presa em `--hang` nao impeca
    # o servidor de atender as demais; o `SingleThreaded` travaria o processo
    # inteiro no primeiro request sem resposta.
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    mode = "timeout (sem resposta)" if args.hang else "sucesso"
    print(
        f"provedor fake ouvindo em http://127.0.0.1:{args.port}/v1 · modo: {mode}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
