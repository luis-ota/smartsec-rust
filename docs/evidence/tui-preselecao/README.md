# Evidência visual — pré-seleção de ferramentas pelo perfil do projeto

Data da validação: 15/10/2026.
Branch: `feat/preselecao-ferramentas`, derivada da `main` no commit `8328eaa`.

A tela de Ferramentas passou a pré-selecionar o catálogo a partir de um perfil
barato do projeto analisado (`src/project_profile.rs`): linguagens por extensão,
indícios de aplicação web, de banco SQL e de banco NoSQL, além da presença de
`.git`. Cada linha da lista mostra, de forma discreta, o motivo curto da
recomendação — inclusive quando a ferramenta foi desmarcada.

- `preselecao-nosql.png`: projeto Node com `mongoose` e `redis` no
  `package.json`. O SQLMap aparece desmarcado com o motivo "nenhum indício de
  banco SQL (projeto parece NoSQL)"; Nikto, ZAP e TruffleHog também explicam
  por que ficaram fora (sem aplicação web, sem repositório git).
- `preselecao-web.png`: projeto Flask com template HTML. Nikto e ZAP ficam
  marcados ("indício de aplicação web no projeto") e o SQLMap, sem indícios de
  banco, é mantido por precaução ("sem indícios de banco; mantida por
  precaução").

Os dois PNGs foram gerados a partir de um `TestBackend` 80x24 da TUI real, com
os mesmos fixtures de diretório temporário usados pelos testes — nenhuma rede,
keyring ou configuração pessoal é tocada.

## Como reproduzir

Na geração, um teste ignorado `dump_preselection_screens_for_evidence` gravou o
JSON de células de cada tela com a receita padrão das evidências de TUI deste
repositório (`SMARTSEC_TUI_DUMPS=<dir>` + `dump_to_png.py`); o dump foi removido
antes do commit, como manda a receita. A reprodução permanente é pelos testes de
`tui::screens::tools`, que verificam o mesmo conteúdo em 80x24:

```text
$ cargo test -j 1 --bin smartsec -- project_profile tui::screens::tools
```

## Testes automatizados que cobrem os motivos

- `the_nosql_project_explains_the_deselected_tools_at_80x24`
- `a_web_project_keeps_nikto_and_zap_with_reason_at_80x24`
- `explicit_active_tools_disable_the_recommendation_on_screen`
- `a_manual_toggle_survives_the_next_frame`
- `src/project_profile.rs`: fixtures de Python com `sqlite3`, Node com
  `mongoose`/`redis`, projeto sem web, projeto com e sem `.git`, diretório
  inacessível, dependências em diretórios ignorados e o teto de 400 arquivos.
