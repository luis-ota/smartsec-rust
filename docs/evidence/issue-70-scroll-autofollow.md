# Evidencia da correcao de scroll e auto-follow do log — issue #70

Data da validacao: 24/09/2026.

Branch: `fix/issue-70-scroll-auto-follow`, derivada da `main` no commit `8adb770`.

## Causa observada

- `AppState::process_run_events` chamava `follow_latest_log` em todo ciclo e
  reposicionava `log_scroll` no final, desfazendo o scroll manual.
- O limite de scroll usava a quantidade de entradas de `exec_logs`, mas o
  `Paragraph` aplica quebra visual (`Wrap { trim: false }`); linhas longas
  ocupavam varias linhas de tela sem aumentar o limite.

## Correcao

- Novo estado `log_follow` (auto-follow) e `log_total_lines` (linhas visuais).
- `AppState::log_max_scroll` calcula o limite pelo total de linhas visuais,
  com piso na quantidade de entradas antes do primeiro render.
- `render_logs` mede as linhas visuais com `Paragraph::line_count` do proprio
  ratatui (mesma quebra usada na renderizacao) e so reposiciona o scroll
  quando o auto-follow esta ativo.
- `scroll` (teclas e roda do mouse) pausa o auto-follow ao subir no historico
  e o retoma ao voltar ao final.
- Ao descartar entradas antigas (limite de 5000 linhas), o offset manual e
  ajustado para a tela nao pular.

Observacao: `Paragraph::line_count` e exposto pela feature
`unstable-rendered-line-info` do ratatui 0.29. E a mesma dependencia ja
existente, sem crate novo e sem exigir toolchain nightly; foi escolhida por
medir exatamente a quebra usada na renderizacao.

## Testes automatizados

```text
$ cargo test --quiet -- log_scroll_pauses_follow mouse_wheel_over_the_log \
    new_log_lines_respect wrapped_log_lines_expand
running 4 tests
....
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 119 filtered out
```

Cobertura:

- `log_scroll_pauses_follow_and_resumes_at_the_bottom`: teclas pausam e
  retomam o auto-follow.
- `mouse_wheel_over_the_log_scrolls_and_pauses_follow`: roda do mouse sobre o
  log tem o mesmo contrato.
- `new_log_lines_respect_manual_scroll_and_resume_following`: novas mensagens
  nao puxam a tela depois de subir; ao religar o follow, a tela volta ao fim.
- `wrapped_log_lines_expand_the_scroll_limit`: linhas longas geram limite de
  scroll visual; topo e fim ficam alcancaveis em 80x24.

Suite completa da branch:

```text
running 123 tests ... test result: ok. 123 passed
running 12 tests  ... test result: ok. 12 passed
```

`cargo fmt --check` e `cargo clippy --all-targets -- -D warnings` sem avisos.

## Roteiro manual reproduzivel (80x24)

```bash
tmux new -s smartsec70 -x 80 -y 24 'cargo run'
```

1. Informe um alvo local autorizado e inicie no modo assistido com Nmap e
   Nuclei.
2. Durante a execucao, pressione `↑` varias vezes: a tela permanece no trecho
   escolhido mesmo com novas linhas chegando.
3. Use a roda do mouse sobre o `Log de saida`: o mesmo comportamento.
4. Pressione `↓` ate o final: o auto-follow volta a acompanhar as novas
   mensagens.
5. Confirme que linhas longas (tracos do Podman e JSONL do Nuclei) podem ser
   percorridas integralmente.
