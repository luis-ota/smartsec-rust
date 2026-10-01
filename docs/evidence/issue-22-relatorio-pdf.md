# Evidencia da issue #22 — Relatorios Markdown e PDF

Branch: `feat/issue-22-relatorios-pdf`
Requisito: REQ18 (exportar relatorios Markdown e PDF), com efeito em REQ16 e REQ17.

## 1. O que foi entregue

| Entrega | Onde |
|---|---|
| PDF real, com fonte Unicode embutida, quebra de pagina, titulos e tabela de severidades | `src/report/pdf.rs` |
| Escape de conteudo dinamico vindo dos scanners | `src/report/generator.rs` |
| Resolucao de caminho compartilhada entre TUI e headless | `src/report/path.rs` |
| Secoes de analise da IA e de execucoes com falha | `src/report/generator.rs` |
| Fonte Noto Sans (SIL OFL 1.1) e sua licenca | `assets/fonts/` |
| Goldens de Markdown e de texto do PDF | `tests/fixtures/report/`, `src/report/golden.rs` |
| Testes de CLI: caminho pedido, falha de escrita, exit code | `tests/report_cli.rs` |

## 2. Dependencia nova: `printpdf`

| Item | Valor |
|---|---|
| Crate | `printpdf` 0.12.8 |
| Licenca | MIT |
| Publicada em | 2026-09-05, ativa |
| MSRV | 1.88 (a toolchain do projeto e 1.98) |
| Declaracao | `printpdf = { version = "0.12", default-features = false }` |

### O que entra

Sem `default-features`, a arvore de `printpdf` e composta por `allsorts-azul`,
`base64`, `flate2`, `getrandom`, `lopdf`, `serde`, `serde_derive`,
`serde_json`, `smallvec`, `time`, `wasm-bindgen`, `wasm-bindgen-futures` e
`weezl`. Todos sao Rust puro. `serde`, `serde_json` e `flate2` ja estavam no
`Cargo.lock` por causa do `reqwest` e do `quick-xml`.

### O que fica de fora, e por que

A feature `default` do `printpdf` 0.12.8 e exatamente `["html"]`, e `html`
liga `text_layout_hyphenation`, `xmlparser`, `rust-fontconfig`,
`azul-layout/xml` e `azul-layout/pdf`. `text_layout` por sua vez liga
`azul-css`, `azul-core` e `azul-layout`.

- **`rust-fontconfig`** e o binding que descobre fontes lendo a configuracao de
  fontconfig da maquina. Isso tornaria o relatorio dependente do ambiente:
  duas maquinas com fontes diferentes produziriam relatorios diferentes, e uma
  maquina sem configuracao de fonte teria o relatorio em branco. O SmartSec nao
  precisa disso: a fonte vai embutida em `assets/fonts/`.
- **`azul-layout`/`azul-css`/`xmlparser`** sao o motor de layout HTML/CSS. O
  relatorio nao usa HTML: o PDF e montado com a API de ops, posicionando cada
  linha. Puxar um motor de layout inteiro para nao usar layout nenhum seria
  custo de build e de superficie de ataque sem contrapartida.

### Impacto no `Cargo.lock`

- **+52 pacotes, -0, 0 mudancas de versao.** Nenhum pacote ja existente foi
  alterado de versao, entao nao ha risco de regressao por resolucao.
- As 52 entradas sao `printpdf`, `lopdf` (parser/serializador PDF), e a arvore
  de `allsorts-azul` (parser de fonte TrueType) com `brotli-decompressor`,
  `nom`, `rangemap`, `pathfinder_geometry`, `pathfinder_simd` e companhia.
- `ecb`, `aes`, `cbc` e `md-5` chegam por `lopdf` (suporte a PDF cifrado na
  leitura). `image` ja existia no lock por causa do `arboard`, nao do
  `printpdf`.
- Confirmado por `grep` no lock: nao entram `rust-fontconfig`, `azul-layout`,
  `azul-css`, `azul-core` nem `xmlparser`.

## 3. Fonte: Noto Sans

| Item | Valor |
|---|---|
| Arquivo | `assets/fonts/NotoSans-Regular.ttf`, 555 KB, versao estatica *hinted* |
| Licenca | SIL Open Font License 1.1, em `assets/fonts/LICENSE` |
| Origem | `notofonts/noto-fonts`, `hinted/ttf/NotoSans/` |
| SHA-256 | `b85c38ecea8a7cfb39c24e395a4007474fa5a4fc864f6ee33309eb4948d232d5` |
| `upem` | 1000 |
| Glifos | 2840 codepontos |

**Por que uma fonte embutida.** O relatorio e em portugues brasileiro. As 14
fontes padrao do PDF (Helvetica, Times, Courier...) sao declaradas como
`WinAnsiEncoding` e nao tem `cmap` Unicode: um acento viraria `?` ou um glifo
trocado. O teste `o_pdf_preserva_os_acentos_do_portugues` cobre exatamente
isso, e `embedded_font_covers_the_portuguese_alphabet` verifica glifo a glifo
que a fonte tem o pt-BR completo (`á à â ã é ê í ó ô õ ú ü ç` e maiusculas).

**Por que Noto Sans e nao DejaVu.** A cobertura latina e equivalente, mas a
Noto Sans e menor e tem um desenho mais neutro para relatorio. A versao
*hinted* estatica foi escolhida em vez da variavel porque o subconjunto de
fonte TrueType e definido sobre uma face concreta.

**O arquivo esta versionado.** `include_bytes!` falha a compilacao se a fonte
nao estiver no checkout, e `.gitignore` so ignora `/target`. Um checkout limpo
da branch compila e produz o mesmo relatorio.

## 4. Limitationo medida: o PDF nao reduz a fonte a um subconjunto

Isto contraria a expectativa inicial e precisa ficar registrado.

O `printpdf` 0.12.8 **so** monta o subconjunto de fonte na configuracao
`text_layout`. Sem ela, `src/font.rs` define:

```rust
#[cfg(not(feature = "text_layout"))]
pub fn subset_font(font: &ParsedFont, _glyph_ids: &BTreeMap<u16, String>) -> Result<SubsetFont, String> {
    Ok(SubsetFont {
        // Without text_layout, just return the original font bytes without subsetting
        bytes: font.original_bytes.clone(),
        glyph_mapping: BTreeMap::new(),
    })
}
```

Argumento com os glifos usados e descartado. Como `text_layout` e
justamente a feature que traria `azul-layout` e `rust-fontconfig`, e a escolha
foi manter as features desligadas, **cada PDF embute a Noto Sans
completa**. Medido no cenario de teste (relatorio de duas paginas, tres
achados): o Markdown tem 2.114 bytes e o PDF tem **292.110 bytes**, dos quais
quase todos sao a fonte comprimida.

Consequencias, com honestidade:

- O **texto esta correto**: acentos, severidades, secoes e paginacao.
- O **custo e so de tamanho**: ~290 KB por relatorio. Para um artefato de
  auditoria versionado no repositorio e aceitavel.
- `PdfSaveOptions::subset_fonts` continua sendo `true` e o pedido fica no
  codigo: se uma versao futura do `printpdf` passar a subdefinir a fonte sem
  `text_layout`, o comportamento improves sozinho.
- O teste `a_fonte_entrada_no_pdf_e_a_noto_sans_com_cmap_unicode` trava o
  comportamento **medido** (o tamanho do PDF nao cresce com o texto) e falha
  de proposito se isso mudar, para a mudanca aparecer como revisao e nao como
  um bytes-menos silencioso.

### Opcao nao escolhida

Ligar `text_layout` entregaria subconjunto de verdade, ao custo de `azul-layout`
(um motor de layout CSS completo) e de `rust-fontconfig` (leitura da
configuracao de fontes do host) no binario distribuido. A troca foi
**distribuicao portavel** contra **~290 KB por relatorio**. A decisao esta
aberta para revisao; ver a secao 8.

> Correcao factual: a justificativa original da issue descrevia
> `rust-fontconfig` como "binding de fontconfig do sistema". O crate
> `rust-fontconfig` 5.0.0 e Rust puro e **nao tem nenhuma dependencia**
> (verificado na API do crates.io). Ele le a configuracao de fontes do host em
> tempo de execucao, o que continua sendo uma dependencia de ambiente, mas nao
> uma ligacao com biblioteca C do sistema. A conclusao (manter as features
> desligadas) nao muda; o motivo described estava parcialmente errado.

## 5. Como o PDF foi testado

Um PDF nao e deterministico byte a byte: identificadores de objeto e o
timestamp de criacao mudam a cada execucao. O proprio teste
`pdf_gerado_tem_magic_bytes_e_nao_pode_ser_comparado_byte_a_byte` verifica
isso, e afirma que duas execucoes do mesmo relatorio produzem bytes
diferentes com **o mesmo texto**.

O que o golden compara:

1. **Markdown** — `tests/fixtures/report/completo.md`, byte a byte.
   `compile_report` e deterministico, entao qualquer mudanca de formato e uma
   mudanca de contrato e aparece no diff.
2. **PDF** — `tests/fixtures/report/completo.pdf.txt`, que e o **texto extraido
   do PDF realmente gravado**. O teste relê os bytes com
   `printpdf::PdfDocument::parse` e extrai o texto com `extract_text`, que
   reconstroi as strings a partir do `ToUnicode` CMap. Nao ha `pdftotext` nem
   `mutool`: nenhuma dependencia de sistema.

### Limitacao declarada deste teste

A extracao valida o **conteudo visivel**, nao a geometria. Ela reconstroi o
texto e a ordem das linhas, mas nao verifica:

- a posicao exata de cada glifo na pagina;
- a largura das colunas da tabela, o zebrado e os filetes;
- a quebra de linha dentro de um paragrafo.

O layout e verificado por outra via, tambem automatizada:
`long_unbreakable_text_is_split_instead_of_overflowing` e
`accented_text_wraps_without_losing_characters` medem a largura real de cada
linha contra a largura util da coluna, e
`o_pdf_quebra_pagina_quando_o_relatorio_nao_cabe_em_uma` verifica que um
relatorio longo vira varias paginas **sem perder texto** (confere o primeiro e
o ultimo achado apos a extracao).

A verificacao visual foi feita a mao, com `pdftoppm` (Poppler) e
`pdftotext -layout`, que **nao** fazem parte da suite:

```bash
pdftoppm -png -r 110 saida.pdf pagina   # inspecao visual das paginas
pdftotext -layout saida.pdf -           # conferencia da tabela e dos acentos
```

Ambos confirmaram acentos, tabela de severidades em duas colunas, marcacao
escapada exibida como texto literal (`<div>`, `*X-Powered-By*`, `` `Server` ``) e
ausencia de query string.

## 6. Bugs reais corrigidos nesta issue

| Bug | Onde | Efeito |
|---|---|---|
| A TUI ignorava `output_file`/`output_dir` e escrevia em `smartsec-report.md` fixo | `src/tui/event.rs:696` | O criterio "TUI e headless gravam no caminho solicitado" nao era atendido |
| `export_to_markdown` nao criava o diretorio de saida | `src/report/generator.rs` | Falha pouco clara quando `--output-dir` apontava para um caminho novo |
| `export_to_pdf` era um stub que retornava "nao implementada" | `src/report/generator.rs` | REQ18 nao existia |
| A analise da IA nao entrava no relatorio | `compile_report` | O resultado do LLM se perdia |
| Execucoes com erro nao entravam no relatorio | `compile_report` | Uma varredura incompleta parecia limpa |
| Conteudo dinamico concatenado cru | `compile_report` | Um titulo com `##` ou link podia forjar uma secao |

## 7. Matriz de rastreabilidade

| Requisito | Implementacao | Teste |
|---|---|---|
| REQ16 — traducao para linguagem compreensivel | Campo `didactic` entra como `**Em linguagem simples:**` em `src/report/generator.rs` | `tests/fixtures/report/completo.md` (linha 51) |
| REQ17 — relatorio com severidade, evidencia e recomendacao | Secoes Resumo, Pontos Criticos, Todas as Vulnerabilidades, Proveniencia, Analise da IA, Execucoes com falha | `markdown_bate_com_o_golden_byte_a_byte`, `o_pdf_nao_diverge_do_markdown_nas_secoes` |
| REQ18 — exportacao Markdown e PDF | `ReportGenerator::export_to_markdown` / `export_to_pdf`, `report::path` | `texto_do_pdf_bate_com_o_golden`, `headless_grava_markdown_e_pdf_no_caminho_pedido` |

## 8. Criterios de aceite

| Criterio | Status | Como foi verificado |
|---|---|---|
| TUI e headless gravam no caminho solicitado | Atendido | `headless_grava_markdown_e_pdf_no_caminho_pedido`, `sem_configuracao_o_relatorio_vai_para_o_caminho_padum`, `falha_de_escrita_retorna_erro_visivel_e_exit_2` |
| Erro de escrita retorna falha visivel | Atendido | `falha_de_escrita_retorna_erro_visivel_e_exit_2` (exit 2, caminho e causa na mensagem), `o_log_estruturado_sobrevive_a_falha_de_gravacao_do_relatorio` |
| Findings Info e execucoes com erro aparecem | Atendido | `findings_informativos_continuam_sendo_contados_e_listados`, `report_lists_failed_executions_with_tool_status_and_duration` |
| Conteudo dinamico escapado e segredos mascarados | Atendido | `escape_covers_markdown_syntax_without_touching_legitimate_text`, `escape_neutralizes_markdown_injection_in_a_title`, `injected_block_structure_stays_inside_the_description`, `o_golden_nao_contem_segredo_nem_query_string` |
| Testes comparam Markdown e PDF esperados | Atendido, com a limitacao da secao 5 | `markdown_bate_com_o_golden_byte_a_byte`, `texto_do_pdf_bate_com_o_golden` |

## 9. Decisoes que pedem revisao

1. **Fonte completa no PDF (~292 KB).** Consequencia direta de manter
   `default-features = false`. A alternativa e ligar `text_layout` e trazer
   `azul-layout` + `rust-fontconfig` para o binario distribuido. Decisao do
   orquestrador mantida; o custo esta medido e documentado acima.
2. **Negrito sintetizado.** O PDF embute uma fonte so (Regular) e o peso negrito
   e um traço de 0,32 pt sobre o glifo. Embutir a Noto Sans Bold custaria mais
   ~560 KB por PDF. O efeito visual e equivalente nestas tamnhas.
3. **Analise como paragrafo escapado.** A IA pode gerar texto que, escapado,
   vira `\#` ou `\-` no Markdown. Nao ha tentativa de interpretar a resposta
   da IA como Markdown: ela e texto do modelo, nao um template.
4. **A entrada da analise da IA passa por `sanitize_text`.** `compile_report`
   escapa a analise, mas nao a re-redige: se o LLM ecoar um segredo detectado,
   ele entraria no relatorio. O pipeline ja proibe enviar logs a provedores
   remotos sem consentimento, e o `last_log` nao contem corpos HTTP. Vale uma
   issue propria para aplicar `sanitize_text` tambem a analise da IA.
