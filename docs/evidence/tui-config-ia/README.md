# Evidencia visual — tela "Configurar IA"

PNGs gerados a partir do buffer real da TUI (`ratatui::TestBackend`), nao de
captura de terminal: cada quadro foi renderizado em `80x24` ou `100x20` e o
conteudo de cada celula (`symbol`, `fg`, `bg`, `bold`) foi gravado em JSON e
convertido em PNG com Pillow e a fonte JetBrains Mono.

Receita usada (teste temporario `#[ignore]`, removido antes do commit conforme a
tarefa):

```sh
SMARTSEC_TUI_DUMPS=/tmp/dumps cargo test --bin smartsec -- --ignored dump_config_ia
python3 dump_to_png.py /tmp/dumps /tmp/dumps-png
```

Estados capturados:

| Arquivo | Estado |
| --- | --- |
| `01-80x24-padrao-provedor-depois.png` | instalacao nova: "Personalizado" sem endereco (IA desligada) |
| `02-80x24-remoto-endereco-depois.png` | provedor remoto completo, foco num campo de texto |
| `03-80x24-campo-em-edicao-depois.png` | campo de texto aberto para edicao, com cursor |
| `04-80x24-erro-validacao-depois.png` | tempo limite invalido: erro acionavel + resumo marcado |
| `05-80x24-alternativa-ligada-depois.png` | alternativa local ligada, campos condicionais visiveis |
| `06-100x20-alternativa-ligada-depois.png` | o mesmo estado em 100x20, com as duas colunas roladas |
| `07-80x12-compacto-depois.png` | terminal pequeno: formulario compacto com rolagem |
| `08-80x24-alteracao-pendente-depois.png` | rascunho alterado, marca de pendencia e contagem |
| `09-80x24-llamacpp-local-depois.png` | llama.cpp local: "nada sai da maquina" |
| `10-80x24-sem-chave-depois.png` | chave ausente: erro de credencial com proximo passo |
| `11-80x24-ajuda-depois.png` | overlay de ajuda no contexto da tela |
| `02-80x24-remoto-antes.png` | mesma tela no commit base `8328eaa` (antes) |
| `02-80x24-remoto-antes-depois.png` | par antes/depois lado a lado |
