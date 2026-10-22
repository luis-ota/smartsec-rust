use crate::domain::vulnerability::FindingSource;
use crate::domain::Severity;
use crate::tui::chrome::{
    self, ACCENT, DANGER, MUTED, SUCCESS, SURFACE, SURFACE_ACTIVE, TEXT, WARNING,
};
use crate::tui::interaction::{FocusTarget, SemanticAction};
use crate::tui::state::AppState;
use crate::utils::helpers::wrap_text;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::Paragraph,
    Frame,
};
use unicode_width::UnicodeWidthStr;

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let vulnerabilities = app.vulnerabilities();
    let critical = vulnerabilities
        .iter()
        .filter(|item| item.severity == Severity::Critical)
        .count();
    let status = if app.has_run_issues() {
        let first = &app.run_issues[0];
        format!(
            "Execução concluída com {} ocorrências · {} {}",
            app.run_issues.len(),
            first.scope.label(),
            chrome::truncate_width(&first.detail, 30)
        )
    } else if let Some(warning) = &app.llm_warning {
        format!(
            "Análise local aplicada · {}",
            chrome::truncate_width(warning, 48)
        )
    } else if app.md_exported {
        "Relatório Markdown exportado".to_string()
    } else if vulnerabilities.is_empty() {
        "Análise concluída sem vulnerabilidades".to_string()
    } else {
        format!("{} achados · {} críticos", vulnerabilities.len(), critical)
    };
    let title = if app.show_didactic {
        "Explicação didática"
    } else if app.result_detail_vuln.is_some() {
        "Detalhe do achado"
    } else {
        "Resultados"
    };
    let shell = chrome::render_shell(app, frame, area, title, &status);
    if app.show_didactic {
        render_didactic(app, frame, shell.content);
    } else if let Some(index) = app.result_detail_vuln {
        render_detail(app, frame, shell.content, index);
    } else {
        render_overview(app, frame, shell.content);
    }
}

fn render_overview(app: &mut AppState, frame: &mut Frame, area: Rect) {
    // Altura do resumo com o aviso de indisponibilidade do CVE/NVD: métricas (2)
    // + alvo e projeto (1) + IA (1) + auditoria (1), mais uma quando o aviso
    // existe. Encolher faria a auditoria sumir em 80x24, que RNF07 exige.
    let summary_height: u16 = if app.enrichment_warning.is_some() {
        8
    } else {
        7
    };
    let rows = Layout::vertical([
        Constraint::Length(summary_height),
        Constraint::Min(1),
        Constraint::Length(2),
    ])
    .split(area);
    render_summary(app, frame, rows[0]);
    render_list(app, frame, rows[1]);
    render_overview_actions(app, frame, rows[2]);
}

fn audit_label(path: Option<&std::path::PathBuf>, pending: &str) -> String {
    path.map_or_else(
        || pending.to_string(),
        |path| {
            path.file_name().map_or_else(
                || path.display().to_string(),
                |name| format!("auditoria  {}", name.to_string_lossy()),
            )
        },
    )
}

fn render_summary(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let block = chrome::panel("Resumo", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let vulnerabilities = app.vulnerabilities();
    let counts = |severity| {
        vulnerabilities
            .iter()
            .filter(|item| item.severity == severity)
            .count()
    };
    let critical = counts(Severity::Critical);
    let high = counts(Severity::High);
    let medium = counts(Severity::Medium);
    let low = counts(Severity::Low);
    let info = counts(Severity::Info);
    let filter = app.severity_filter;
    let severities = [
        Line::from(vec![
            metric(
                "críticas",
                critical,
                DANGER,
                filter == Some(Severity::Critical),
            ),
            Span::raw("   "),
            metric(
                "altas",
                high,
                Color::Rgb(220, 130, 90),
                filter == Some(Severity::High),
            ),
            Span::raw("   "),
            metric("médias", medium, WARNING, filter == Some(Severity::Medium)),
        ]),
        Line::from(vec![
            metric("baixas", low, ACCENT, filter == Some(Severity::Low)),
            Span::raw("   "),
            metric("informativas", info, MUTED, filter == Some(Severity::Info)),
        ]),
    ];
    let critical_width = format!("{critical} críticas").width();
    let high_width = format!("{high} altas").width();
    let medium_width = format!("{medium} médias").width();
    let low_width = format!("{low} baixas").width();
    let info_width = format!("{info} informativas").width();
    let ai_hint = "  ▸ ações da IA";
    let ai_budget = (inner.width as usize).saturating_sub(4 + ai_hint.width());
    let ai = Line::from(vec![
        Span::styled("ia  ", Style::default().fg(MUTED)),
        Span::styled(
            chrome::truncate_width(first_line(app.ai_summary()), ai_budget),
            Style::default().fg(TEXT),
        ),
        Span::styled(ai_hint, Style::default().fg(ACCENT).bold()),
    ]);
    let mut ai_line_index = None;
    let mut severity_line_indices = Vec::new();
    let lines = if app.has_run_issues() {
        let mut lines = Vec::new();
        for issue in app
            .run_issues
            .iter()
            .take(inner.height.saturating_sub(4) as usize)
        {
            let color = if issue.scope.is_warning() {
                WARNING
            } else {
                DANGER
            };
            lines.push(Line::styled(
                chrome::truncate_width(
                    &format!("{}: {}", issue.scope.label(), issue.detail),
                    inner.width as usize,
                ),
                Style::default().fg(color).bold(),
            ));
        }
        let hidden = app
            .run_issues
            .len()
            .saturating_sub(inner.height.saturating_sub(4) as usize);
        if hidden > 0 {
            lines.push(Line::styled(
                format!("+{hidden} ocorrências no log da execução"),
                Style::default().fg(MUTED),
            ));
        }
        severity_line_indices.push(lines.len());
        lines.push(severities[0].clone());
        severity_line_indices.push(lines.len());
        lines.push(severities[1].clone());
        // Com ocorrências, o caminho da auditoria continua acessível no
        // relatório, no log estruturado e na tela de rastreabilidade (f2).
        ai_line_index = Some(lines.len());
        lines.push(ai);
        lines
    } else if vulnerabilities.is_empty() {
        vec![
            Line::styled(
                "Nenhum achado identificado.",
                Style::default().fg(SUCCESS).bold(),
            ),
            Line::styled(
                "Exporte o relatório ou inicie uma nova análise.",
                Style::default().fg(MUTED),
            ),
        ]
    } else {
        // "alvo  " ocupa 7 colunas e "  código " ocupa 9; o que sobra divide-se
        // entre os dois paths, com folga para a borda direita.
        let path_budget = ((inner.width as usize).saturating_sub(18)) / 2;
        severity_line_indices.extend([0, 1]);
        ai_line_index = Some(3);
        vec![
            severities[0].clone(),
            severities[1].clone(),
            // Alvo e projeto dividem a mesma linha: em 80x24 uma linha extra
            // empurraria a auditoria para fora da tela, e a auditoria é o
            // registro que o TCC exige.
            Line::from(vec![
                Span::styled("alvo  ", Style::default().fg(MUTED)),
                Span::styled(
                    chrome::truncate_width(&app.config.target_url, path_budget),
                    Style::default().fg(TEXT),
                ),
                Span::styled("  código ", Style::default().fg(MUTED)),
                Span::styled(
                    chrome::truncate_width(&app.project_dir_label(), path_budget),
                    Style::default().fg(TEXT),
                ),
            ]),
            ai,
            Line::styled(
                audit_label(
                    app.audit_log_path.as_ref(),
                    "auditoria  aguardando persistência",
                ),
                Style::default().fg(MUTED),
            ),
        ]
    };
    if severity_line_indices.len() == 2 {
        let y1 = inner.y + severity_line_indices[0] as u16;
        let y2 = inner.y + severity_line_indices[1] as u16;
        let high_x = inner.x + critical_width as u16 + 3;
        let medium_x = high_x + high_width as u16 + 3;
        let info_x = inner.x + low_width as u16 + 3;
        for (rect, severity) in [
            (
                Rect::new(inner.x, y1, critical_width as u16, 1),
                Severity::Critical,
            ),
            (Rect::new(high_x, y1, high_width as u16, 1), Severity::High),
            (
                Rect::new(medium_x, y1, medium_width as u16, 1),
                Severity::Medium,
            ),
            (Rect::new(inner.x, y2, low_width as u16, 1), Severity::Low),
            (Rect::new(info_x, y2, info_width as u16, 1), Severity::Info),
        ] {
            app.register_hit_region(rect, SemanticAction::FilterSeverity(severity));
        }
    }
    if let Some(index) = ai_line_index {
        app.register_hit_region(
            Rect::new(inner.x, inner.y + index as u16, inner.width, 1),
            SemanticAction::OpenAiTimeline,
        );
    }
    let mut lines = lines;
    if let Some(warning) = &app.enrichment_warning {
        // A indisponibilidade da NVD é um aviso, não uma falha da varredura:
        // aparece em destaque, sem virar `run_error` nem alterar o exit code.
        lines.push(Line::styled(
            chrome::truncate_width(warning, inner.width as usize),
            Style::default().fg(WARNING),
        ));
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        inner,
    );
}

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or(text)
}

fn metric(label: &str, value: usize, color: Color, active: bool) -> Span<'_> {
    let style = Style::default().fg(color).bold();
    Span::styled(
        format!("{value} {label}"),
        if active {
            style.bg(SURFACE_ACTIVE).underlined()
        } else {
            style
        },
    )
}

fn render_list(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let focused = app.focus == FocusTarget::ResultsList;
    // REQ15: o painel anuncia que os críticos estão no topo, para que a
    // ordenação seja visível e não apenas implícita.
    let visible_indices = app.visible_vulnerability_indices();
    let total = app.vulnerabilities().len();
    let title = if let Some(filter) = app.severity_filter {
        format!(
            "Achados · {} de {} · {}",
            visible_indices.len(),
            total,
            severity_label(filter)
        )
    } else {
        let critical = app
            .vulnerabilities()
            .iter()
            .filter(|item| item.severity == Severity::Critical)
            .count();
        if critical > 0 {
            format!("Achados · {critical} crítico(s) no topo")
        } else {
            "Achados".to_string()
        }
    };
    let block = chrome::panel(&title, focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    if visible_indices.is_empty() {
        app.result_cursor = 0;
        app.result_scroll = 0;
        let message = if app.severity_filter.is_some() {
            "Nenhum achado com a severidade selecionada. Clique na severidade de novo para limpar o filtro."
        } else {
            "Nenhuma vulnerabilidade para revisar."
        };
        frame.render_widget(
            Paragraph::new(message).style(Style::default().fg(MUTED).bg(SURFACE)),
            inner,
        );
        return;
    }
    if !visible_indices.contains(&app.result_cursor) {
        app.result_cursor = visible_indices[0];
    }
    let cursor_position = visible_indices
        .iter()
        .position(|index| *index == app.result_cursor)
        .unwrap_or(0);
    let count = visible_indices.len();
    let visible = inner.height as usize;
    let max_scroll = count.saturating_sub(visible);
    app.result_scroll = app.result_scroll.min(max_scroll);
    if cursor_position < app.result_scroll {
        app.result_scroll = cursor_position;
    } else if cursor_position >= app.result_scroll.saturating_add(visible) {
        app.result_scroll = cursor_position.saturating_sub(visible - 1);
    }

    let rows = visible.min(count.saturating_sub(app.result_scroll));
    let first_row = app.result_scroll;
    let cursor = app.result_cursor;
    let all = app.vulnerabilities();
    let row_areas: Vec<Rect> = (0..rows)
        .map(|row| Rect::new(inner.x, inner.y + row as u16, inner.width, 1))
        .collect();
    let mut lines = Vec::new();
    for (row, row_area) in row_areas.iter().enumerate() {
        let index = visible_indices[first_row + row];
        let item = all[index];
        let current = index == cursor;
        let active = current && focused;
        let hovered = app.mouse_over(*row_area);
        lines.push(
            Line::from(vec![
                Span::styled(if current { "> " } else { "  " }, Style::default().bold()),
                Span::styled(
                    format!("{:<8}", severity_label(item.severity)),
                    Style::default().bold(),
                ),
                Span::styled(
                    chrome::truncate_width(&item.title, inner.width.saturating_sub(12) as usize),
                    Style::default(),
                ),
            ])
            // A cor da severidade é autoritativa (TCC_SPEC.md, seção 7) e não
            // pode desaparecer quando a linha está selecionada: o destaque vem
            // do fundo e do marcador, nunca da cor.
            .style(
                Style::default()
                    .fg(severity_color(item.severity))
                    .bg(if active {
                        SURFACE_ACTIVE
                    } else if hovered {
                        chrome::SURFACE_HOVER
                    } else {
                        SURFACE
                    })
                    .add_modifier(if current {
                        ratatui::style::Modifier::BOLD
                    } else {
                        ratatui::style::Modifier::empty()
                    }),
            ),
        );
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        inner,
    );
    // As regiões entram depois do desenho, na mesma ordem de antes: o vetor de
    // achados empresta o estado e não convive com o registro mutável.
    for (row, row_area) in row_areas.iter().enumerate() {
        app.register_hit_region(
            *row_area,
            SemanticAction::OpenVulnerability(visible_indices[first_row + row]),
        );
    }
}

fn render_overview_actions(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let columns = Layout::horizontal([
        Constraint::Length(13),
        Constraint::Min(1),
        Constraint::Length(17),
    ])
    .split(area);
    let new_focused = app.focus == FocusTarget::ResultsNewScan;
    let export_focused = app.focus == FocusTarget::ResultsExport;
    chrome::render_button(
        app,
        frame,
        columns[0],
        "Nova análise",
        SemanticAction::NewScan,
        chrome::ButtonState::secondary(new_focused),
    );
    if let Some(path) = app
        .exported_report_path
        .as_ref()
        .filter(|_| app.md_exported)
    {
        let mut saved = format!("salvo em {}", path.display());
        if let Some(pdf) = app.exported_pdf_path.as_ref() {
            saved.push_str(&format!(" (+ {})", pdf.display()));
        }
        frame.render_widget(
            Paragraph::new(chrome::truncate_width(&saved, columns[1].width as usize))
                .style(Style::default().fg(MUTED)),
            columns[1],
        );
    }
    let (export_label, export_action) = if app.md_exported {
        ("Ver relatório", SemanticAction::OpenReportViewer)
    } else {
        ("Exportar", SemanticAction::ExportMarkdown)
    };
    chrome::render_button(
        app,
        frame,
        columns[2],
        export_label,
        export_action,
        chrome::ButtonState::primary(export_focused),
    );
}

/// Acrescenta o contexto CVE/NVD e a multi-origem ao detalhe do achado.
///
/// O contexto da NVD é informativo: ele **não** reclassifica a severidade, e a
/// eventual divergência entre scanner e NVD aparece como nota explícita.
fn append_enrichment(
    lines: &mut Vec<Line<'static>>,
    item: &crate::domain::vulnerability::Vulnerability,
    width: usize,
) {
    if let Some(enrichment) = item.enrichment.as_ref() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "Contexto NVD",
            Style::default().fg(TEXT).bold(),
        ));
        push_wrapped_owned(lines, enrichment.summary_pt_br(), width, MUTED);
        if let Some(vector) = enrichment.cvss_vector.as_deref() {
            push_wrapped_owned(lines, format!("vetor CVSS: {vector}"), width, MUTED);
        }
        if let Some(reference) = enrichment.reference.as_deref() {
            push_wrapped_owned(lines, format!("referência: {reference}"), width, MUTED);
        }
    }
    if let Some(conflict) = item.severity_conflict.as_ref() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "Divergência de severidade",
            Style::default().fg(WARNING).bold(),
        ));
        push_wrapped_owned(lines, conflict.detail.clone(), width, WARNING);
    }
    if item.origins.len() > 1 {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "Origens do mesmo problema",
            Style::default().fg(TEXT).bold(),
        ));
        for origin in &item.origins {
            push_wrapped_owned(
                lines,
                format!(
                    "{} · {} · {}",
                    origin.tool,
                    origin.severity.label_pt_br(),
                    origin.evidence
                ),
                width,
                MUTED,
            );
        }
    }
}

/// Quebra um texto **possuído** em linhas do terminal para `Line<'static>`:
/// o texto precisa ser propriedade do `Line`, não apontar para o `Vulnerability`.
fn push_wrapped_owned<'a>(lines: &mut Vec<Line<'a>>, value: String, width: usize, color: Color) {
    for (index, paragraph) in value.split("\n\n").enumerate() {
        if index > 0 {
            lines.push(Line::from(""));
        }
        for line in wrap_text(paragraph, width.max(1)) {
            lines.push(Line::styled(line, Style::default().fg(color)));
        }
    }
}

fn render_detail(app: &mut AppState, frame: &mut Frame, area: Rect, index: usize) {
    let rows = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(area);
    let focused = app.focus == FocusTarget::ResultsDetail;
    let block = chrome::panel_hover("Evidência e recomendação", focused, app.mouse_over(rows[0]));
    let inner = block.inner(rows[0]);
    frame.render_widget(block, rows[0]);
    let vulnerabilities = app.vulnerabilities();
    // Com a ordem memoizada o vetor devolvido empresta os achados do
    // orquestrador: nada é clonado aqui além do próprio item aberto.
    if let Some(item) = vulnerabilities.get(index).copied() {
        let mut lines: Vec<Line<'static>> = vec![
            Line::from(vec![
                Span::styled(
                    format!("{}  ", severity_label(item.severity)),
                    Style::default().fg(severity_color(item.severity)).bold(),
                ),
                Span::styled(item.title.clone(), Style::default().fg(TEXT).bold()),
            ]),
            Line::from(vec![
                Span::styled("ferramenta  ", Style::default().fg(MUTED)),
                Span::styled(item.tool.clone(), Style::default().fg(TEXT)),
                Span::styled("   alvo  ", Style::default().fg(MUTED)),
                Span::styled(
                    chrome::truncate_width(&item.target, inner.width as usize / 2).to_string(),
                    Style::default().fg(TEXT),
                ),
            ]),
            Line::from(vec![
                Span::styled("detectado  ", Style::default().fg(MUTED)),
                Span::styled(item.detected_at.clone(), Style::default().fg(TEXT)),
                Span::styled("   origem  ", Style::default().fg(MUTED)),
                Span::styled(
                    item.source.to_string(),
                    Style::default().fg(match item.source {
                        FindingSource::Real | FindingSource::CodeAudit => SUCCESS,
                        FindingSource::Demo => WARNING,
                    }),
                ),
            ]),
            Line::from(""),
        ];
        // O código vem primeiro: é o que o operador precisa ver para corrigir.
        append_code_location(
            app,
            &mut lines,
            item.code_location.as_ref(),
            app.detail_code_preview.as_ref(),
            item.code_remediation.clone(),
            inner.width as usize,
        );
        lines.push(Line::from(""));
        lines.push(section_rule("Descrição", inner.width as usize));
        append_wrapped(&mut lines, &item.description, inner.width as usize, MUTED);
        lines.push(Line::from(""));
        lines.push(section_rule("Evidência", inner.width as usize));
        // A evidência é sanitizada na exibição: é o campo que carrega o trecho
        // real do scanner e nunca deve exibir credencial ou corpo de requisição.
        let evidence = crate::utils::redaction::sanitize_text(&item.evidence);
        append_wrapped(&mut lines, &evidence, inner.width as usize, ACCENT);
        lines.push(Line::from(""));
        lines.push(section_rule("Recomendação", inner.width as usize));
        append_wrapped(
            &mut lines,
            &item.recommendation,
            inner.width as usize,
            SUCCESS,
        );
        append_enrichment(&mut lines, item, inner.width as usize);
        let has_scroll = lines.len() > inner.height as usize;
        let indicator_height = u16::from(has_scroll);
        let viewport = Rect::new(
            inner.x,
            inner.y,
            inner.width,
            inner.height.saturating_sub(indicator_height),
        );
        let visible = viewport.height.max(1) as usize;
        app.detail_max_scroll = lines.len().saturating_sub(visible);
        app.detail_scroll = app.detail_scroll.min(app.detail_max_scroll);
        let total = lines.len();
        let visible_lines: Vec<_> = lines
            .into_iter()
            .skip(app.detail_scroll)
            .take(visible)
            .collect();
        frame.render_widget(
            Paragraph::new(Text::from(visible_lines)).style(Style::default().bg(SURFACE)),
            viewport,
        );
        if has_scroll {
            let first = app.detail_scroll + 1;
            let last = (app.detail_scroll + visible).min(total);
            frame.render_widget(
                Paragraph::new(format!("↑↓ rolar · linhas {first}-{last} de {total}"))
                    .alignment(ratatui::layout::Alignment::Right)
                    .style(Style::default().fg(ACCENT).bg(SURFACE)),
                Rect::new(
                    inner.x,
                    inner.y + inner.height.saturating_sub(1),
                    inner.width,
                    1,
                ),
            );
        }
    } else {
        app.detail_scroll = 0;
        app.detail_max_scroll = 0;
        frame.render_widget(
            Paragraph::new("O achado selecionado não está mais disponível.")
                .style(Style::default().fg(DANGER).bg(SURFACE)),
            inner,
        );
    }
    app.register_hit_region(
        rows[0],
        SemanticAction::SetFocus(FocusTarget::ResultsDetail),
    );
    let actions = Layout::horizontal([
        Constraint::Length(10),
        Constraint::Min(1),
        Constraint::Length(16),
    ])
    .split(rows[1]);
    chrome::render_button(
        app,
        frame,
        actions[0],
        "Voltar",
        SemanticAction::Back,
        chrome::ButtonState::secondary(app.focus == FocusTarget::ResultsBack),
    );
    chrome::render_button(
        app,
        frame,
        actions[2],
        "Explicar (IA)",
        SemanticAction::ExplainFinding,
        chrome::ButtonState::primary(app.focus == FocusTarget::ResultsExplain),
    );
}

fn render_didactic(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let rows = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(area);
    let focused = app.focus == FocusTarget::DidacticContent;
    let block = chrome::panel_hover("Em linguagem direta", focused, app.mouse_over(rows[0]));
    let inner = block.inner(rows[0]);
    frame.render_widget(block, rows[0]);
    let vulnerabilities = app.vulnerabilities();
    let mut lines: Vec<Line<'static>> = Vec::new();
    if let Some(index) = app.result_detail_vuln {
        if let Some(item) = vulnerabilities.get(index) {
            lines.push(Line::styled(
                item.title.clone(),
                Style::default().fg(TEXT).bold(),
            ));
            if app.rag_pending == Some(index) {
                lines.push(Line::from(""));
                lines.push(section_rule("Explicação da IA", inner.width as usize));
                push_wrapped_owned(
                    &mut lines,
                    "gerando explicação em linguagem direta…".to_string(),
                    inner.width as usize,
                    MUTED,
                );
            } else if let Some(result) = app.rag_results.get(&index) {
                append_rag_explanation(app, index, &mut lines, inner.width as usize);
                if !result.approved() && !item.didactic.trim().is_empty() {
                    lines.push(Line::from(""));
                    lines.push(section_rule("Resumo determinístico", inner.width as usize));
                    append_wrapped(&mut lines, &item.didactic, inner.width as usize, MUTED);
                }
            } else {
                lines.push(Line::from(""));
                append_wrapped(&mut lines, &item.didactic, inner.width as usize, MUTED);
            }
        }
    } else if vulnerabilities.is_empty() {
        lines.push(Line::styled(
            "Não há achados que precisem de explicação.",
            Style::default().fg(SUCCESS),
        ));
    } else {
        for item in &vulnerabilities {
            lines.push(Line::styled(
                item.title.clone(),
                Style::default().fg(TEXT).bold(),
            ));
            append_wrapped(&mut lines, &item.didactic, inner.width as usize, MUTED);
            lines.push(Line::from(""));
        }
    }
    let has_scroll = lines.len() > inner.height as usize;
    let indicator_height = u16::from(has_scroll);
    let viewport = Rect::new(
        inner.x,
        inner.y,
        inner.width,
        inner.height.saturating_sub(indicator_height),
    );
    let visible = viewport.height.max(1) as usize;
    let total = lines.len();
    app.didactic_max_scroll = total.saturating_sub(visible);
    app.didactic_scroll = app.didactic_scroll.min(app.didactic_max_scroll);
    let visible_lines: Vec<_> = lines
        .into_iter()
        .skip(app.didactic_scroll)
        .take(visible)
        .collect();
    frame.render_widget(
        Paragraph::new(Text::from(visible_lines)).style(Style::default().bg(SURFACE)),
        viewport,
    );
    if has_scroll {
        let first = app.didactic_scroll + 1;
        let last = (app.didactic_scroll + visible).min(total);
        frame.render_widget(
            Paragraph::new(format!("↑↓ rolar · linhas {first}-{last} de {total}"))
                .alignment(ratatui::layout::Alignment::Right)
                .style(Style::default().fg(ACCENT).bg(SURFACE)),
            Rect::new(
                inner.x,
                inner.y + inner.height.saturating_sub(1),
                inner.width,
                1,
            ),
        );
    }
    app.register_hit_region(
        rows[0],
        SemanticAction::SetFocus(FocusTarget::DidacticContent),
    );
    let pending = app
        .result_detail_vuln
        .is_some_and(|index| app.rag_pending == Some(index));
    let has_result = app
        .result_detail_vuln
        .is_some_and(|index| app.rag_results.contains_key(&index));
    let actions = Layout::horizontal([
        Constraint::Length(10),
        Constraint::Min(1),
        Constraint::Length(18),
    ])
    .split(rows[1]);
    chrome::render_button(
        app,
        frame,
        actions[0],
        "Voltar",
        SemanticAction::Back,
        chrome::ButtonState::secondary(app.focus == FocusTarget::DidacticBack),
    );
    if pending || !has_result {
        let ai_label = if pending {
            "Gerando…"
        } else {
            "Explicar (IA)"
        };
        chrome::render_button(
            app,
            frame,
            actions[2],
            ai_label,
            SemanticAction::ExplainFinding,
            chrome::ButtonState::primary(app.focus == FocusTarget::DidacticExplain)
                .enabled(!pending),
        );
    }
}

/// Explicação assistida do achado: aprovada (com o exemplo do corpus) ou a
/// recusa explícita — nunca um texto sem veredito.
fn append_rag_explanation(
    app: &AppState,
    index: usize,
    lines: &mut Vec<Line<'static>>,
    width: usize,
) {
    lines.push(Line::from(""));
    lines.push(section_rule("Explicação da IA", width));
    if app.rag_pending == Some(index) {
        push_wrapped_owned(lines, "gerando explicação…".to_string(), width, MUTED);
        return;
    }
    let Some(result) = app.rag_results.get(&index) else {
        push_wrapped_owned(
            lines,
            "use \"Explicar (IA)\" para gerar uma explicação validada por ontologia.".to_string(),
            width,
            MUTED,
        );
        return;
    };
    if !result.conceito.is_empty() {
        push_wrapped_owned(
            lines,
            format!(
                "conceito {} · {} / {} · contexto {}",
                result.conceito, result.provider, result.model, result.retrieval_mode
            ),
            width,
            MUTED,
        );
        lines.push(Line::from(""));
    }
    if !result.approved() {
        push_wrapped_owned(
            lines,
            "não consegui explicar isto com segurança.".to_string(),
            width,
            WARNING,
        );
        if let Some(reason) = result.failure_reason.as_deref() {
            push_wrapped_owned(lines, reason.to_string(), width, MUTED);
        }
        append_rag_claims(lines, result, width);
        return;
    }
    push_wrapped_owned(lines, result.text.clone(), width, MUTED);
    append_rag_claims(lines, result, width);
    if let Some(example) = result.example.as_ref() {
        let language = example
            .linguagem
            .clone()
            .unwrap_or_else(|| "código".to_string());
        lines.push(Line::from(""));
        lines.push(Line::styled(
            format!("exemplo do corpus: {} ({language})", example.titulo),
            Style::default().fg(ACCENT).bold(),
        ));
        lines.push(Line::from(""));
        append_example_block(
            lines,
            "vulnerável",
            example.vulneravel.as_deref(),
            &language,
            width,
            DANGER,
        );
        lines.push(Line::from(""));
        append_example_block(
            lines,
            "corrigido",
            example.corrigido.as_deref(),
            &language,
            width,
            SUCCESS,
        );
        lines.push(Line::from(""));
        push_wrapped_owned(
            lines,
            format!("padrão seguro: {}", example.padrao_seguro),
            width,
            SUCCESS,
        );
    }
    lines.push(Line::from(""));
    push_wrapped_owned(
        lines,
        format!("veredito: {}", result.verdict_summary()),
        width,
        SUCCESS,
    );
}

fn append_example_block(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    code: Option<&str>,
    language: &str,
    width: usize,
    color: Color,
) {
    let Some(code) = code else {
        return;
    };
    let language = crate::tui::code_preview::CodeLanguage::from_label(language);
    let background = if color == DANGER {
        Color::Rgb(35, 18, 20)
    } else {
        Color::Rgb(18, 30, 20)
    };
    let base = Style::default().bg(background);
    let header = format!("┌─ {label} ");
    let fill = width.saturating_sub(header.width() + 1);
    lines.push(Line::styled(
        format!("{header}{}┐", "─".repeat(fill)),
        base.fg(color).bold(),
    ));
    for (index, line_text) in code.lines().enumerate() {
        let gutter = format!("{:>4} │ ", index + 1);
        let mut remaining = width.saturating_sub(gutter.width() + 1);
        let mut used = gutter.width();
        let mut spans = vec![Span::styled(gutter, base.fg(MUTED))];
        for (text, token_color) in crate::tui::code_preview::highlight_line(line_text, language) {
            if remaining == 0 {
                break;
            }
            let clipped = text.width() > remaining;
            let piece = chrome::truncate_width(&text, remaining);
            remaining = remaining.saturating_sub(piece.width());
            used += piece.width();
            spans.push(Span::styled(piece, base.fg(token_color)));
            if clipped {
                break;
            }
        }
        let padding = width.saturating_sub(used + 1);
        spans.push(Span::styled(" ".repeat(padding), base));
        spans.push(Span::styled("│", base.fg(color)));
        lines.push(Line::from(spans));
    }
    lines.push(Line::styled(
        format!("└{}┘", "─".repeat(width.saturating_sub(2))),
        base.fg(color),
    ));
}

fn append_rag_claims(
    lines: &mut Vec<Line<'static>>,
    result: &crate::cyberrag::service::ExplanationResult,
    width: usize,
) {
    if result.claims.is_empty() && result.verdict.rejeitadas.is_empty() {
        return;
    }
    lines.push(Line::from(""));
    lines.push(Line::styled(
        "Fundamentação (triplas da ontologia)",
        Style::default().fg(TEXT).bold(),
    ));
    for claim in &result.claims {
        push_wrapped_owned(
            lines,
            format!(
                "  • {} → {} → {}",
                claim.sujeito, claim.relacao, claim.objeto
            ),
            width,
            MUTED,
        );
    }
    for rejection in &result.verdict.rejeitadas {
        push_wrapped_owned(
            lines,
            format!(
                "  ✗ {} → {} → {}: {}",
                rejection.claim.sujeito,
                rejection.claim.relacao,
                rejection.claim.objeto,
                rejection.motivo
            ),
            width,
            WARNING,
        );
    }
}

/// Mostra a origem no código e os passos de correção de um achado.
///
/// A ausência de origem é explícita, nunca substituída por um caminho ou linha
/// inventados.
fn section_rule(title: &str, width: usize) -> Line<'static> {
    let label = format!(" {title} ");
    let rule_width = width.saturating_sub(label.width() + 1).max(2);
    Line::from(vec![
        Span::styled("─", Style::default().fg(SURFACE_ACTIVE)),
        Span::styled(label, Style::default().fg(TEXT).bold()),
        Span::styled("─".repeat(rule_width), Style::default().fg(SURFACE_ACTIVE)),
    ])
}

fn append_code_location(
    app: &AppState,
    lines: &mut Vec<Line<'static>>,
    location: Option<&crate::domain::vulnerability::CodeLocation>,
    preview: Option<&crate::tui::code_preview::CodePreview>,
    remediation: Vec<String>,
    width: usize,
) {
    // As linhas são `Line<'static>`: as strings são clonadas, não emprestadas do
    // vetor de achados, recriado a cada quadro.
    lines.push(section_rule("Localização no código", width));
    match location {
        Some(location) => {
            let total = preview
                .filter(|preview| preview.file == location.file && preview.line == location.line)
                .and_then(|preview| match &preview.state {
                    crate::tui::code_preview::PreviewState::Ready { total_lines, .. } => {
                        Some(*total_lines)
                    }
                    crate::tui::code_preview::PreviewState::Unavailable { .. } => None,
                });
            let line_label = match total {
                Some(total) => format!("  linha {} de {total}", location.line),
                None => format!("  linha {}", location.line),
            };
            lines.push(Line::from(vec![
                Span::styled("arquivo  ", Style::default().fg(MUTED)),
                Span::styled(
                    chrome::truncate_width(
                        &location.file,
                        width.saturating_sub(12 + line_label.width()),
                    ),
                    Style::default().fg(ACCENT).bold(),
                ),
                Span::styled(line_label, Style::default().fg(TEXT)),
            ]));
            append_code_block(lines, preview, location, width);
            if !remediation.is_empty() {
                lines.push(Line::from(""));
                lines.push(section_rule("Correção sugerida", width));
                for (index, step) in remediation.iter().enumerate() {
                    let prefix = format!("{}. ", index + 1);
                    let step_width = width.saturating_sub(prefix.len());
                    for (offset, part) in wrap_text(step, step_width.max(1)).into_iter().enumerate()
                    {
                        let text = if offset == 0 {
                            format!("{prefix}{part}")
                        } else {
                            format!("   {part}")
                        };
                        lines.push(Line::styled(text, Style::default().fg(SUCCESS)));
                    }
                }
            }
        }
        None => {
            let reason = app
                .code_reason_fallback()
                .unwrap_or_else(|| "a origem no código não foi determinada".to_string());
            lines.push(Line::from(vec![
                Span::styled("arquivo  ", Style::default().fg(MUTED)),
                Span::styled(
                    "localização não determinada",
                    Style::default().fg(WARNING).bold(),
                ),
            ]));
            // Quebra a razão em linhas próprias: o texto vem do relatório da fase e é
            // dinâmico, então não pode ser uma `&'static str` do painel.
            for line in wrap_text(&reason, width.max(1)) {
                lines.push(Line::styled(line, Style::default().fg(MUTED)));
            }
        }
    }
    lines.push(Line::from(""));
}

fn append_code_block(
    lines: &mut Vec<Line<'static>>,
    preview: Option<&crate::tui::code_preview::CodePreview>,
    location: &crate::domain::vulnerability::CodeLocation,
    width: usize,
) {
    let preview =
        preview.filter(|preview| preview.file == location.file && preview.line == location.line);
    if let Some(preview) = preview {
        match &preview.state {
            crate::tui::code_preview::PreviewState::Ready {
                lines: code_lines,
                truncated,
                ..
            } => {
                lines.push(Line::styled(
                    format!("┌{}┐", "─".repeat(width.saturating_sub(2))),
                    Style::default().fg(SURFACE_ACTIVE),
                ));
                if *truncated {
                    push_wrapped_owned(
                        lines,
                        "prévia truncada no limite do arquivo".to_string(),
                        width,
                        WARNING,
                    );
                }
                for code_line in code_lines {
                    let gutter = format!("{:>4} │ ", code_line.number);
                    let gutter_width = gutter.width();
                    let marker = if code_line.is_target { "> " } else { "  " };
                    let text_width = width
                        .saturating_sub(gutter_width)
                        .saturating_sub(marker.width());
                    let base = if code_line.is_target {
                        Style::default().bg(Color::Rgb(55, 22, 22))
                    } else {
                        Style::default().bg(Color::Rgb(13, 16, 20))
                    };
                    let mut spans = vec![
                        Span::styled(
                            marker,
                            base.fg(if code_line.is_target { DANGER } else { MUTED })
                                .bold(),
                        ),
                        Span::styled(gutter, base.fg(MUTED)),
                    ];
                    let mut remaining = text_width;
                    let mut used = marker.width() + gutter_width;
                    for (text, color) in
                        crate::tui::code_preview::highlight_line(&code_line.text, preview.language)
                    {
                        if remaining == 0 {
                            break;
                        }
                        let clipped = text.width() > remaining;
                        let piece = chrome::truncate_width(&text, remaining);
                        let style = if code_line.is_target {
                            base.fg(color).bold()
                        } else {
                            base.fg(color)
                        };
                        remaining = remaining.saturating_sub(piece.width());
                        used += piece.width();
                        spans.push(Span::styled(piece, style));
                        if clipped {
                            break;
                        }
                    }
                    let padding = width.saturating_sub(used + 1);
                    spans.push(Span::styled(" ".repeat(padding), base));
                    spans.push(Span::styled(
                        "│",
                        base.fg(if code_line.is_target { DANGER } else { MUTED }),
                    ));
                    lines.push(Line::from(spans));
                }
                lines.push(Line::styled(
                    format!("└{}┘", "─".repeat(width.saturating_sub(2))),
                    Style::default().fg(SURFACE_ACTIVE),
                ));
            }
            crate::tui::code_preview::PreviewState::Unavailable { reason } => {
                push_wrapped_owned(
                    lines,
                    format!("prévia indisponível: {reason}"),
                    width,
                    WARNING,
                );
                append_logged_snippet(lines, location, width);
            }
        }
        return;
    }
    append_logged_snippet(lines, location, width);
}

fn append_logged_snippet(
    lines: &mut Vec<Line<'static>>,
    location: &crate::domain::vulnerability::CodeLocation,
    width: usize,
) {
    if location.snippet.trim().is_empty() {
        return;
    }
    lines.push(Line::styled(
        "trecho registrado no log",
        Style::default().fg(MUTED),
    ));
    push_wrapped_owned(lines, location.snippet.trim().to_string(), width, MUTED);
}

fn append_wrapped(lines: &mut Vec<Line<'static>>, value: &str, width: usize, color: Color) {
    for (index, paragraph) in value.split("\n\n").enumerate() {
        if index > 0 {
            lines.push(Line::from(""));
        }
        for line in wrap_text(paragraph, width.max(1)) {
            lines.push(Line::styled(line, Style::default().fg(color)));
        }
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRÍTICA",
        Severity::High => "ALTA",
        Severity::Medium => "MÉDIA",
        Severity::Low => "BAIXA",
        Severity::Info => "INFORM.",
    }
}

fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Critical => DANGER,
        Severity::High => Color::Rgb(220, 130, 90),
        Severity::Medium => WARNING,
        Severity::Low => ACCENT,
        Severity::Info => MUTED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Configuration;
    use crate::domain::vulnerability::{CodeLocation, FindingSource, Vulnerability};
    use crate::tui::state::{AppState, AppStep};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn finding(title: &str) -> Vulnerability {
        Vulnerability {
            title: title.to_string(),
            severity: Severity::High,
            description: "Descrição do achado".to_string(),
            tool: "Nuclei".to_string(),
            recommendation: "Revise a configuração".to_string(),
            didactic: "Explicação".to_string(),
            source: FindingSource::Real,
            target: "http://alvo.local".to_string(),
            evidence: "evidência".to_string(),
            detected_at: "2026-09-30T12:00:00Z".to_string(),
            ..Default::default()
        }
    }

    fn draw(app: &mut AppState, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(app, frame, frame.area()))
            .unwrap();
        terminal.backend().to_string()
    }

    /// Critério de aceite da issue #76: a TUI exibe a localização e a correção
    /// sugerida por achado, legíveis em 80x24 (RNF07).
    #[test]
    fn the_detail_shows_the_location_and_the_remediation_at_80x24() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        let mut item = finding("Autenticação fraca em /api/login");
        item.code_location = Some(CodeLocation {
            file: "src/app.py".to_string(),
            line: 4,
            snippet: "raise ValueError".to_string(),
        });
        item.code_remediation = vec![
            "Valide o usuário antes de prosseguir".to_string(),
            "Adicione teste de regressão".to_string(),
        ];
        app.orchestrator.findings.push(item);
        app.step = AppStep::Results;
        app.result_detail_vuln = Some(0);
        app.focus = crate::tui::interaction::FocusTarget::ResultsDetail;

        let screen = draw(&mut app, 80, 24);

        assert!(screen.contains("Localização no código"), "{screen}");
        assert!(screen.contains("src/app.py"), "{screen}");
        assert!(screen.contains("linha 4"), "{screen}");
        assert!(screen.contains("Correção sugerida"), "{screen}");
        assert!(screen.contains("Valide o usuário"), "{screen}");
    }

    #[test]
    fn the_detail_shows_the_code_window_with_the_target_line() {
        let root =
            std::env::temp_dir().join(format!("smartsec-preview-results-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/app.py"),
            "def login(user):\n    if not user:\n        raise ValueError('falha')\n    return user\n",
        )
        .unwrap();

        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        let mut item = finding("Falha no login");
        item.code_location = Some(CodeLocation {
            file: "src/app.py".to_string(),
            line: 3,
            snippet: "raise ValueError('falha')".to_string(),
        });
        app.orchestrator.findings.push(item);
        app.step = AppStep::Results;
        app.focus = crate::tui::interaction::FocusTarget::ResultsList;
        app.results_project_dir = Some(root.clone());

        crate::tui::event::dispatch_action(&mut app, SemanticAction::OpenVulnerability(0));

        let screen = draw(&mut app, 80, 24);
        assert!(screen.contains("raise ValueError"), "{screen}");
        assert!(screen.contains(">"), "{screen}");
        assert!(app.detail_code_preview.is_some());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Sem origem, a TUI diz isso e mostra o motivo — nunca um caminho ou uma
    /// linha que o agente não leu.
    #[test]
    fn the_detail_says_when_the_location_was_not_determined() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        app.orchestrator.findings.push(finding("Cabeçalho ausente"));
        app.step = AppStep::Results;
        app.result_detail_vuln = Some(0);
        app.focus = crate::tui::interaction::FocusTarget::ResultsDetail;

        let screen = draw(&mut app, 80, 24);

        assert!(screen.contains("localização não determinada"), "{screen}");
    }

    #[test]
    fn clicking_a_severity_filters_the_list_and_clicking_again_clears_it() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        let mut high = finding("Alta 1");
        high.severity = Severity::High;
        let mut info = finding("Informativa");
        info.severity = Severity::Info;
        let mut high2 = finding("Alta 2");
        high2.severity = Severity::High;
        app.orchestrator.findings.extend([high, info, high2]);
        app.step = AppStep::Results;

        let screen = draw(&mut app, 80, 24);
        assert!(screen.contains("Achados"), "{screen}");

        crate::tui::event::dispatch_action(
            &mut app,
            SemanticAction::FilterSeverity(Severity::Info),
        );
        assert_eq!(app.severity_filter, Some(Severity::Info));
        assert_eq!(app.visible_vulnerability_indices().len(), 1);
        let screen = draw(&mut app, 80, 24);
        assert!(screen.contains("1 de 3"), "{screen}");
        assert!(screen.contains("INFORM."), "{screen}");
        assert!(!screen.contains("Alta 1"), "{screen}");

        crate::tui::event::dispatch_action(
            &mut app,
            SemanticAction::FilterSeverity(Severity::Info),
        );
        assert_eq!(app.severity_filter, None);
        assert_eq!(app.visible_vulnerability_indices().len(), 3);
        let screen = draw(&mut app, 80, 24);
        assert!(screen.contains("Alta 1"), "{screen}");
    }

    #[test]
    fn clicking_the_ai_line_opens_the_tool_activity() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        app.orchestrator.findings.push(finding("Achado"));
        app.step = AppStep::Results;

        let _ = draw(&mut app, 80, 24);

        assert!(app
            .hit_regions
            .iter()
            .any(|region| region.action == SemanticAction::OpenAiTimeline));
        crate::tui::event::dispatch_action(&mut app, SemanticAction::OpenAiTimeline);
        assert!(app.show_ai_timeline);
    }

    /// O resumo exibe o diretório do projeto ao lado do alvo, para que o
    /// operador saiba qual código foi analisado sem abrir o relatório.
    #[test]
    fn the_summary_shows_the_analyzed_project_at_80x24() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        app.config.target_url = "http://alvo.local".to_string();
        app.orchestrator.findings.push(finding("Achado"));
        app.step = AppStep::Results;

        let screen = draw(&mut app, 80, 24);

        assert!(screen.contains("código"), "{screen}");
    }

    /// A linha de auditoria não pode ser sacrificada para caber o diretório do
    /// projeto: em 80x24, o painel de resumo precisa continuar mostrando as
    /// duas informações.
    #[test]
    fn the_summary_keeps_both_the_target_and_the_audit_line_at_80x24() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        app.config.target_url = "http://alvo.local".to_string();
        app.orchestrator.findings.push(finding("Achado"));
        app.step = AppStep::Results;

        let screen = draw(&mut app, 80, 24);

        assert!(screen.contains("alvo"), "{screen}");
        assert!(screen.contains("código"), "{screen}");
        assert!(
            screen.contains("auditoria"),
            "a linha de auditoria sumiu em 80x24: {screen}"
        );
    }
}
