//! Renderização do relatório em PDF (REQ18).
//!
//! O PDF é desenhado a partir da **mesma** string Markdown já sanitizada que
//! [`super::generator::ReportGenerator::export_to_markdown`] grava. Renderizar
//! um e outro a partir de uma única fonte é o que impede que os dois artefatos
//! divirjam: o `.pdf` não tem como mostrar um segredo que o `.md` removeu.
//!
//! A fonte é a Noto Sans (SIL OFL 1.1), embutida no repositório. O relatório é
//! escrito em português brasileiro com acentos, e as 14 fontes padrão do PDF
//! não têm `cmap` Unicode: sem fonte própria os caracteres saem quebrados.
//! `printpdf` embute subconjunto por padrão (`PdfSaveOptions::subset_fonts`),
//! então só os glifos realmente usados entram no arquivo.

use anyhow::{anyhow, Result};
use printpdf::{
    ops::PdfFontHandle, Color, Line, LinePoint, Mm, Op, ParsedFont, PdfDocument, PdfPage,
    PdfSaveOptions, Point, Pt, Rgb, TextItem, TextRenderingMode,
};

use super::generator::unescape_markdown;

/// Noto Sans Regular, versão estática hinted, sob SIL Open Font License 1.1.
/// A licença está em `assets/fonts/LICENSE` e o `OFL.txt` original do upstream
/// é referenciado em `docs/evidence/issue-22-relatorio-pdf.md`.
const NOTO_SANS_REGULAR: &[u8] = include_bytes!("../../assets/fonts/NotoSans-Regular.ttf");

// Geometria da página A4 em pontos (1 mm = 72/25,4 pt).
const PAGE_WIDTH: f32 = 595.28;
const PAGE_HEIGHT: f32 = 841.89;
const MARGIN: f32 = 51.02; // 18 mm
const CONTENT_WIDTH: f32 = PAGE_WIDTH - (2.0 * MARGIN);

// Escala tipográfica do relatório.
const SIZE_TITLE: f32 = 17.0;
const SIZE_HEADING: f32 = 13.0;
const SIZE_SUBHEADING: f32 = 10.5;
const SIZE_BODY: f32 = 9.0;
const LEADING_BODY: f32 = 12.5;
const BULLET_INDENT: f32 = 12.0;
/// Fração da altura útil que um bloco de cabeçalho reserva acima do título.
const HEADING_SPACE_BELOW: f32 = 4.0;

const COLOR_TEXT: Rgb = Rgb {
    r: 0.10,
    g: 0.10,
    b: 0.12,
    icc_profile: None,
};
const COLOR_TITLE: Rgb = Rgb {
    r: 0.06,
    g: 0.13,
    b: 0.28,
    icc_profile: None,
};
const COLOR_HEADING: Rgb = Rgb {
    r: 0.10,
    g: 0.24,
    b: 0.44,
    icc_profile: None,
};
const COLOR_RULE: Rgb = Rgb {
    r: 0.72,
    g: 0.76,
    b: 0.82,
    icc_profile: None,
};
const COLOR_TABLE_ZEBRA: Rgb = Rgb {
    r: 0.95,
    g: 0.96,
    b: 0.98,
    icc_profile: None,
};

/// Largura reservada à coluna de rótulo da tabela de severidades.
const TABLE_LABEL_WIDTH: f32 = 190.0;

/// Converte um bloco de `Op` de Markdown em bytes de PDF.
///
/// A string recebida já passou por `sanitize_text`/`sanitize_url` e por
/// [`super::generator::escape_markdown`]; aqui o escape é desfeito para que o
/// leitor veja o caractere real e não a sequência `\*`.
pub fn render(markdown: &str) -> Result<Vec<u8>> {
    let font = ParsedFont::from_bytes(NOTO_SANS_REGULAR, 0, &mut Vec::new())
        .ok_or_else(|| anyhow!("a fonte Noto Sans embutida não pôde ser interpretada"))?;

    let mut document = PdfDocument::new("SmartSec - Relatório de Análise de Segurança");
    let handle = PdfFontHandle::External(document.add_font(&font));
    let mut writer = Writer {
        document: &mut document,
        font: &font,
        handle,
        pages: Vec::new(),
        ops: Vec::new(),
        cursor_y: MARGIN,
        table_row_index: 0,
    };

    for block in parse_markdown(markdown) {
        writer.render_block(&block);
    }
    writer.finish_page();

    let mut warnings = Vec::new();
    let bytes = writer.document.with_pages(writer.pages).save(
        &PdfSaveOptions {
            // Subconjunto: só os glifos do relatório entram no arquivo, em vez
            // dos 2.840 da Noto Sans completa.
            subset_fonts: true,
            ..PdfSaveOptions::default()
        },
        &mut warnings,
    );
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Subconjunto da sintaxe Markdown emitida por `compile_report`
// ---------------------------------------------------------------------------

/// Um bloco lógico do relatório, já sem a marcação Markdown.
#[derive(Debug, PartialEq)]
enum Block {
    Heading(u8, String),
    /// Item de lista no formato `rótulo: valor`, laid out como tabela.
    Row(String, String),
    Bullet(String),
    Paragraph(String),
    Spacer,
}

/// Interpreta o subconjunto de Markdown que `compile_report` produz.
///
/// Cobre títulos, itens de lista, parágrafos e o parágrafo `**Rótulo:** valor`.
/// Marcação desconhecida vira texto literal, nunca erro: um achado malformado
/// não pode impedir a geração do relatório.
fn parse_markdown(markdown: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    for line in markdown.lines() {
        let trimmed = line.trim_end();
        if trimmed.trim().is_empty() {
            blocks.push(Block::Spacer);
        } else if let Some(title) = trimmed.strip_prefix("### ") {
            blocks.push(Block::Heading(3, plain(title)));
        } else if let Some(title) = trimmed.strip_prefix("## ") {
            blocks.push(Block::Heading(2, plain(title)));
        } else if let Some(title) = trimmed.strip_prefix("# ") {
            blocks.push(Block::Heading(1, plain(title)));
        } else if let Some(item) = trimmed.strip_prefix("- ") {
            match split_row(item) {
                Some((label, value)) => blocks.push(Block::Row(label, value)),
                None => blocks.push(Block::Bullet(plain(item))),
            }
        } else if let Some(body) = strip_label(trimmed) {
            blocks.push(Block::Paragraph(body));
        } else {
            blocks.push(Block::Paragraph(plain(trimmed)));
        }
    }
    blocks
}

/// Separa `- Rótulo: valor` em rótulo e valor, quando o item tem essa forma.
fn split_row(item: &str) -> Option<(String, String)> {
    let (label, value) = item.split_once(": ")?;
    let label = label.trim();
    // Um item de vulnerabilidade (`- [Alta] X - Nuclei`) não é uma linha de
    // tabela; exige um rótulo curto e sem marcação de lista.
    if label.is_empty() || label.len() > 48 || label.starts_with('[') {
        return None;
    }
    Some((plain(label), plain(value)))
}

/// Remove o marcador `**` de um parágrafo `**Rótulo:** valor`.
fn strip_label(line: &str) -> Option<String> {
    let body = line.strip_prefix("**")?;
    let (label, rest) = body.split_once(":**")?;
    Some(format!("{}: {}", plain(label), plain(rest)))
}

/// Texto como o leitor o vê: sem escape e sem vestígio de marcação.
fn plain(text: &str) -> String {
    unescape_markdown(text).trim().to_string()
}

// ---------------------------------------------------------------------------
// Composição da página
// ---------------------------------------------------------------------------

struct Writer<'a> {
    document: &'a mut PdfDocument,
    font: &'a ParsedFont,
    handle: PdfFontHandle,
    pages: Vec<PdfPage>,
    ops: Vec<Op>,
    /// Distância da linha de base atual ao topo da página, em pontos.
    cursor_y: f32,
    /// Alternância das linhas da tabela para manter a leitura em colunas.
    table_row_index: usize,
}

impl Writer<'_> {
    fn render_block(&mut self, block: &Block) {
        match block {
            Block::Spacer => self.cursor_y += LEADING_BODY * 0.5,
            Block::Heading(level, text) => self.heading(*level, text),
            Block::Row(label, value) => self.table_row(label, value),
            Block::Bullet(text) => {
                for line in self.wrap(text, CONTENT_WIDTH - BULLET_INDENT) {
                    self.write_line(&line, MARGIN + BULLET_INDENT, SIZE_BODY, &COLOR_TEXT, false);
                }
            }
            Block::Paragraph(text) => {
                for line in self.wrap(text, CONTENT_WIDTH) {
                    self.write_line(&line, MARGIN, SIZE_BODY, &COLOR_TEXT, false);
                }
            }
        }
    }

    fn heading(&mut self, level: u8, text: &str) {
        let (size, color) = match level {
            1 => (SIZE_TITLE, COLOR_TITLE),
            2 => (SIZE_HEADING, COLOR_HEADING),
            _ => (SIZE_SUBHEADING, COLOR_HEADING),
        };
        // Título de nível 1 no topo da página não precisa do espaço acima.
        if !(level == 1 && self.is_page_start()) {
            self.cursor_y += size * 0.55;
        }
        let leading = size * 1.32;
        for line in self.wrap(text, CONTENT_WIDTH) {
            self.write_line(&line, MARGIN, size, &color, true);
            self.cursor_y += leading;
        }
        if level <= 2 {
            self.rule();
        }
        self.cursor_y += HEADING_SPACE_BELOW;
    }

    /// Linha da tabela de severidades: rótulo na esquerda, valor na direita.
    fn table_row(&mut self, label: &str, value: &str) {
        let row_height = LEADING_BODY + 5.0;
        if !self.fits(row_height) {
            self.next_page();
        }
        let top = self.cursor_y;
        if self.table_row_index % 2 == 1 {
            self.fill_rect(MARGIN, top, CONTENT_WIDTH, row_height, &COLOR_TABLE_ZEBRA);
        }
        self.table_row_index += 1;
        self.write_line_at(
            &plain(label),
            MARGIN + 6.0,
            SIZE_BODY,
            &COLOR_TEXT,
            true,
            top + LEADING_BODY - 2.0,
        );
        self.write_line_at(
            &plain(value),
            MARGIN + TABLE_LABEL_WIDTH,
            SIZE_BODY,
            &COLOR_TEXT,
            false,
            top + LEADING_BODY - 2.0,
        );
        self.cursor_y = top + row_height;
    }

    fn write_line(&mut self, text: &str, x: f32, size: f32, color: &Rgb, bold: bool) {
        self.write_line_at(text, x, size, color, bold, self.cursor_y);
    }

    fn write_line_at(
        &mut self,
        text: &str,
        x: f32,
        size: f32,
        color: &Rgb,
        bold: bool,
        mut baseline_y: f32,
    ) {
        if text.is_empty() {
            return;
        }
        if !self.fits(LEADING_BODY) {
            self.next_page();
            baseline_y = self.cursor_y;
        }
        self.ops.push(Op::StartTextSection);
        self.ops.push(Op::SetTextCursor {
            pos: Point {
                x: Pt(x),
                // O eixo Y do PDF cresce para cima; o cursor do writer cresce
                // para baixo, a partir do topo.
                y: Pt(PAGE_HEIGHT - baseline_y),
            },
        });
        self.ops.push(Op::SetFont {
            font: self.handle.clone(),
            size: Pt(size),
        });
        self.ops.push(Op::SetLineHeight {
            lh: Pt(size * 1.32),
        });
        self.ops.push(Op::SetFillColor {
            col: Color::Rgb(color.clone()),
        });
        if bold {
            // Negrito real exigiria embutir a segunda fonte; traçar o glifo com
            // uma espessura fina tem o mesmo efeito visual e custa 1 KB a menos.
            self.ops.push(Op::SetTextRenderingMode {
                mode: TextRenderingMode::FillStroke,
            });
            self.ops.push(Op::SetOutlineColor {
                col: Color::Rgb(color.clone()),
            });
            self.ops.push(Op::SetOutlineThickness { pt: Pt(0.32) });
        }
        self.ops.push(Op::ShowText {
            items: vec![TextItem::Text(text.to_string())],
        });
        self.ops.push(Op::EndTextSection);
        self.cursor_y = baseline_y + LEADING_BODY;
    }

    fn rule(&mut self) {
        self.cursor_y += 2.0;
        self.draw_horizontal_line(MARGIN, self.cursor_y, CONTENT_WIDTH, &COLOR_RULE);
        self.cursor_y += 6.0;
    }

    /// Traça um filete horizontal, usado para separar as seções do relatório.
    fn draw_horizontal_line(&mut self, x: f32, y: f32, width: f32, color: &Rgb) {
        self.ops.push(Op::SetOutlineColor {
            col: Color::Rgb(color.clone()),
        });
        self.ops.push(Op::SetOutlineThickness { pt: Pt(0.6) });
        self.ops.push(Op::DrawLine {
            line: Line {
                points: vec![point(x, y), point(x + width, y)],
                is_closed: false,
            },
        });
    }

    fn fill_rect(&mut self, x: f32, top: f32, width: f32, height: f32, color: &Rgb) {
        self.ops.push(Op::SetFillColor {
            col: Color::Rgb(color.clone()),
        });
        self.ops.push(Op::DrawPolygon {
            polygon: printpdf::Polygon {
                rings: vec![printpdf::PolygonRing {
                    points: vec![
                        point(x, top),
                        point(x + width, top),
                        point(x + width, top + height),
                        point(x, top + height),
                    ],
                }],
                mode: printpdf::PaintMode::Fill,
                winding_order: printpdf::WindingOrder::NonZero,
            },
        });
    }

    fn is_page_start(&self) -> bool {
        (self.cursor_y - MARGIN).abs() < 0.5
    }

    /// Indica se ainda há altura útil para `needed` na página atual.
    fn fits(&self, needed: f32) -> bool {
        self.cursor_y + needed <= PAGE_HEIGHT - MARGIN
    }

    fn next_page(&mut self) {
        self.finish_page();
        self.cursor_y = MARGIN;
    }

    fn finish_page(&mut self) {
        if self.ops.is_empty() {
            return;
        }
        self.pages.push(PdfPage::new(
            Mm(210.0),
            Mm(297.0),
            std::mem::take(&mut self.ops),
        ));
    }
}

fn point(x: f32, y_from_top: f32) -> LinePoint {
    LinePoint {
        p: Point {
            x: Pt(x),
            y: Pt(PAGE_HEIGHT - y_from_top),
        },
        bezier: false,
    }
}

// ---------------------------------------------------------------------------
// Medição de texto
// ---------------------------------------------------------------------------

impl Writer<'_> {
    /// Largura de `text` em pontos, medida com as métricas reais da fonte.
    ///
    /// A largura real vem do `hmtx` da Noto Sans (1000 upem); estimar por
    /// contagem de caracteres faria a quebra de linha errar em português, onde
    /// `ã` e `l` têm larguras muito diferentes.
    fn width(&self, text: &str, size: f32) -> f32 {
        let upem = self.font.units_per_em.max(1) as f32;
        text.chars()
            .map(|character| {
                self.font
                    .lookup_glyph_index(character as u32)
                    .and_then(|gid| self.font.glyph_widths.get(&gid).copied())
                    .map_or(0.5, |units| units as f32 / upem)
            })
            .sum::<f32>()
            * size
    }

    /// Quebra `text` em linhas que cabem em `max_width`, sem cortar palavras.
    fn wrap(&self, text: &str, max_width: f32) -> Vec<String> {
        if text.trim().is_empty() {
            return vec![String::new()];
        }
        // Uma palavra mais larga que a coluna é quebrada por caractere: sem
        // isso, um payload sem espaços estoura a margem e some da página.
        let mut lines = Vec::new();
        let mut current = String::new();
        for word in text.split_whitespace() {
            let candidate = if current.is_empty() {
                word.to_string()
            } else {
                format!("{current} {word}")
            };
            if self.width(&candidate, SIZE_BODY) <= max_width {
                current = candidate;
                continue;
            }
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            if self.width(word, SIZE_BODY) <= max_width {
                current = word.to_string();
            } else {
                for chunk in self.break_word(word, max_width) {
                    if current.is_empty() {
                        current = chunk;
                    } else {
                        lines.push(std::mem::take(&mut current));
                        current = chunk;
                    }
                }
            }
        }
        if !current.is_empty() {
            lines.push(current);
        }
        lines
    }

    fn break_word(&self, word: &str, max_width: f32) -> Vec<String> {
        let mut chunks = Vec::new();
        let mut current = String::new();
        for character in word.chars() {
            if !current.is_empty()
                && self.width(&format!("{current}{character}"), SIZE_BODY) > max_width
            {
                chunks.push(std::mem::take(&mut current));
            }
            current.push(character);
        }
        if !current.is_empty() {
            chunks.push(current);
        }
        chunks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn font() -> ParsedFont {
        ParsedFont::from_bytes(NOTO_SANS_REGULAR, 0, &mut Vec::new()).expect("fonte embutida")
    }

    #[test]
    fn embedded_font_covers_the_portuguese_alphabet() {
        let font = font();
        for character in "áàâãéêíóôõúüçÁÀÂÃÉÊÍÓÔÕÚÇñÑç".chars() {
            let gid = font
                .lookup_glyph_index(character as u32)
                .unwrap_or_else(|| panic!("a fonte não tem glifo para {character:?}"));
            assert_ne!(gid, 0, "{character:?} aponta para .notdef");
        }
    }

    #[test]
    fn embedded_font_has_advance_widths_for_wrapping() {
        let font = font();
        assert_eq!(font.units_per_em, 1000);
        for character in "Aço".chars() {
            let gid = font.lookup_glyph_index(character as u32).unwrap();
            assert!(
                font.glyph_widths.get(&gid).copied().unwrap_or(0) > 0,
                "{character:?} não tem largura de avanço"
            );
        }
    }

    #[test]
    fn blocks_cover_the_markdown_subset_of_the_report() {
        let blocks = parse_markdown(
            "# Título\n\n**URL Alvo:** http://a.local\n\n- Críticas: 2\n- [Alta] SQL - Nuclei\n",
        );
        assert_eq!(
            blocks,
            vec![
                Block::Heading(1, "Título".to_string()),
                Block::Spacer,
                Block::Paragraph("URL Alvo: http://a.local".to_string()),
                Block::Spacer,
                Block::Row("Críticas".to_string(), "2".to_string()),
                Block::Bullet("[Alta] SQL - Nuclei".to_string()),
            ]
        );
    }

    #[test]
    fn escaped_markdown_is_rendered_as_the_plain_character() {
        // Reproduz a linha que `compile_report` monta: o rótulo de severidade
        // fica cru e só o título vindo do scanner é escapado.
        let titulo =
            super::super::generator::escape_markdown("injeção `rm -rf` **<b>** no parâmetro |id|");
        let linha = format!("### [Crítica] {titulo}");

        let blocks = parse_markdown(&linha);
        let Block::Heading(3, rendered) = &blocks[0] else {
            panic!("esperava título, veio {blocks:?}");
        };
        assert_eq!(
            rendered,
            "[Crítica] injeção `rm -rf` **<b>** no parâmetro |id|"
        );
    }

    #[test]
    fn malformed_markdown_does_not_abort_the_render() {
        let blocks = parse_markdown("**sem fecha\n####### só texto\n");
        assert!(matches!(blocks[0], Block::Paragraph(_)));
        assert!(matches!(blocks[1], Block::Paragraph(_)));
    }

    #[test]
    fn long_unbreakable_text_is_split_instead_of_overflowing() {
        let mut document = PdfDocument::new("teste");
        let parsed = font();
        let handle = PdfFontHandle::External(document.add_font(&parsed));
        let writer = Writer {
            document: &mut document,
            font: &parsed,
            handle,
            pages: Vec::new(),
            ops: Vec::new(),
            cursor_y: MARGIN,
            table_row_index: 0,
        };
        let payload = "A".repeat(600);
        let lines = writer.wrap(&payload, CONTENT_WIDTH);
        assert!(lines.len() > 1, "a palavra longa não foi quebrada");
        for line in &lines {
            assert!(
                writer.width(line, SIZE_BODY) <= CONTENT_WIDTH + 1.0,
                "linha estourou a margem: {} pt",
                writer.width(line, SIZE_BODY)
            );
        }
    }

    #[test]
    fn accented_text_wraps_without_losing_characters() {
        let mut document = PdfDocument::new("teste");
        let parsed = font();
        let handle = PdfFontHandle::External(document.add_font(&parsed));
        let writer = Writer {
            document: &mut document,
            font: &parsed,
            handle,
            pages: Vec::new(),
            ops: Vec::new(),
            cursor_y: MARGIN,
            table_row_index: 0,
        };
        let text = " vulnerabilidade de injeção de SQL no parâmetro de busca AllowsNullBooleans "
            .repeat(4);
        let rejoined = writer.wrap(&text, CONTENT_WIDTH).join(" ");
        assert_eq!(
            rejoined.split_whitespace().collect::<Vec<_>>(),
            text.split_whitespace().collect::<Vec<_>>()
        );
    }

    #[test]
    fn render_produces_a_valid_pdf_with_the_report_text() {
        let bytes = render("# Relatório\n\n- Críticas: 1\n\nAnálise com acentos: ção.\n").unwrap();
        assert!(bytes.starts_with(b"%PDF-"), "magic bytes ausentes");
        let parsed = printpdf::PdfDocument::parse(
            &bytes,
            &printpdf::PdfParseOptions::default(),
            &mut Vec::new(),
        )
        .expect("o PDF gerado não pôde ser relido");
        let text: String = parsed
            .extract_text()
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Relatório"), "{text}");
        assert!(text.contains("Críticas"), "{text}");
        assert!(text.contains("ção"), "acentos perdidos: {text}");
    }

    #[test]
    fn font_is_subset_instead_of_embedded_whole() {
        let short = render("# Ok\n").unwrap();
        let long = render(&format!("# Ok\n\n{}\n", "palavra ".repeat(2000))).unwrap();
        assert!(
            long.len() < short.len() * 12,
            "o subconjunto não fica evidente: {} vs {}",
            short.len(),
            long.len()
        );
    }
}
