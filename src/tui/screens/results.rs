use crate::domain::vulnerability::FindingSource;
use crate::domain::Severity;
use crate::tui::chrome::{
    self, ACCENT, DANGER, SUCCESS, SURFACE, SURFACE_ACTIVE, TEXT, TEXT_SOFT, WARNING,
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
    // + alvo e projeto (1) + IA (1) + auditoria (1) + comparação (1), mais uma
    // quando o aviso existe. Encolher faria a auditoria sumir em 80x24, que
    // RNF07 exige.
    let summary_height: u16 = 7
        + u16::from(app.scan_comparison.has_previous())
        + u16::from(app.enrichment_warning.is_some());
    let rows = Layout::vertical([
        Constraint::Length(summary_height),
        Constraint::Min(1),
        Constraint::Length(2),
    ])
    .split(area);
    render_summary(app, frame, rows[0]);
    // O painel de corrigidos só aparece quando há o que listar e nunca come a
    // lista inteira: em 80x24 o resumo e os achados continuam visíveis.
    let panel_height = fixed_panel_height(app).min(rows[1].height.saturating_sub(5));
    let list_area = if panel_height >= 3 {
        let split =
            Layout::vertical([Constraint::Length(panel_height), Constraint::Min(1)]).split(rows[1]);
        render_fixed_panel(app, frame, split[0]);
        split[1]
    } else {
        rows[1]
    };
    render_list(app, frame, list_area);
    render_overview_actions(app, frame, rows[2]);
}

fn fixed_panel_height(app: &AppState) -> u16 {
    let fixed = app.scan_comparison.fixed.len();
    if fixed == 0 {
        return 0;
    }
    let rows = fixed.min(3) + usize::from(fixed > 3);
    rows as u16 + 2
}

fn render_fixed_panel(app: &AppState, frame: &mut Frame, area: Rect) {
    if area.height < 3 || area.width == 0 {
        return;
    }
    let block = chrome::panel("Corrigidos desde a execução anterior", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let fixed = &app.scan_comparison.fixed;
    let capacity = inner.height as usize;
    let mut visible = fixed.len().min(3);
    if visible + usize::from(fixed.len() > visible) > capacity {
        // Sem espaço para tudo, o "+N" é mais útil que a última linha cortada.
        visible = capacity.saturating_sub(1).min(visible);
    }
    let mut lines = Vec::new();
    for finding in fixed.iter().take(visible) {
        let title_budget = (inner.width as usize).saturating_sub(11);
        lines.push(Line::from(vec![
            Span::styled("✔ ", Style::default().fg(SUCCESS).bold()),
            Span::styled(
                format!("{:<8}", severity_label(finding.severity)),
                Style::default().fg(severity_color(finding.severity)).bold(),
            ),
            Span::styled(
                chrome::truncate_width(&finding.title, title_budget),
                Style::default().fg(TEXT),
            ),
        ]));
    }
    let hidden = fixed.len().saturating_sub(visible);
    if hidden > 0 {
        lines.push(Line::styled(
            format!("+{hidden}"),
            Style::default().fg(TEXT_SOFT),
        ));
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        inner,
    );
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
    let comparison_present = app.scan_comparison.has_previous();
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
            metric(
                "informativas",
                info,
                TEXT_SOFT,
                filter == Some(Severity::Info),
            ),
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
        Span::styled("ia  ", Style::default().fg(TEXT_SOFT)),
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
        let issue_budget = inner
            .height
            .saturating_sub(4 + u16::from(comparison_present)) as usize;
        for issue in app.run_issues.iter().take(issue_budget) {
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
        let hidden = app.run_issues.len().saturating_sub(issue_budget);
        if hidden > 0 {
            lines.push(Line::styled(
                format!("+{hidden} ocorrências no log da execução"),
                Style::default().fg(TEXT_SOFT),
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
                Style::default().fg(TEXT_SOFT),
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
                Span::styled("alvo  ", Style::default().fg(TEXT_SOFT)),
                Span::styled(
                    chrome::truncate_width(&app.config.target_url, path_budget),
                    Style::default().fg(TEXT),
                ),
                Span::styled("  código ", Style::default().fg(TEXT_SOFT)),
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
                Style::default().fg(TEXT_SOFT),
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
    if let Some(line) = comparison_summary_line(&app.scan_comparison, inner.width as usize) {
        lines.push(line);
    }
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

fn comparison_summary_line(
    comparison: &crate::orchestrator::scan_logger::ScanComparison,
    width: usize,
) -> Option<Line<'static>> {
    if !comparison.has_previous() {
        return None;
    }
    let text = format!(
        "vs. última  -{} corrigidos · +{} novos · {} persistem ({})",
        comparison.fixed.len(),
        comparison.new.len(),
        comparison.persisting,
        comparison.previous_scan_id,
    );
    Some(Line::styled(
        chrome::truncate_width(&text, width),
        Style::default().fg(TEXT_SOFT),
    ))
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
            Paragraph::new(message).style(Style::default().fg(TEXT_SOFT).bg(SURFACE)),
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
        let location = compact_location(item);
        let location_budget = 18usize;
        let tool_budget = 12usize;
        let fixed =
            2 + 8 + 1 + tool_budget + 1 + location.as_ref().map_or(0, |_| location_budget + 1);
        let title_budget = (inner.width as usize).saturating_sub(fixed);
        let tool = chrome::truncate_width(&item.tool, tool_budget);
        let tool_cell = format!(
            "{tool}{} ",
            " ".repeat(tool_budget.saturating_sub(tool.width()))
        );
        let title = chrome::truncate_width(&item.title, title_budget);
        let title_cell = format!(
            "{title}{}",
            " ".repeat(title_budget.saturating_sub(title.width()))
        );
        let mut spans = vec![
            Span::styled(if current { "> " } else { "  " }, Style::default().bold()),
            Span::styled(
                format!("{:<8}", severity_label(item.severity)),
                Style::default().fg(severity_color(item.severity)).bold(),
            ),
            Span::styled(" ", Style::default()),
            Span::styled(tool_cell, Style::default().fg(TEXT_SOFT)),
            Span::styled(title_cell, Style::default().fg(TEXT)),
        ];
        if let Some(location) = location {
            spans.push(Span::styled(" ", Style::default()));
            spans.push(Span::styled(
                chrome::truncate_width(&location, location_budget),
                Style::default().fg(TEXT_SOFT),
            ));
        }
        lines.push(
            Line::from(spans)
                // O destaque da seleção é o fundo; a cor da severidade continua
                // sendo a do scanner (TCC_SPEC.md, seção 7).
                .style(
                    Style::default()
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
                .style(Style::default().fg(TEXT_SOFT)),
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
        push_wrapped_owned(lines, enrichment.summary_pt_br(), width, TEXT_SOFT);
        if let Some(vector) = enrichment.cvss_vector.as_deref() {
            push_wrapped_owned(lines, format!("vetor CVSS: {vector}"), width, TEXT_SOFT);
        }
        if let Some(reference) = enrichment.reference.as_deref() {
            push_wrapped_owned(lines, format!("referência: {reference}"), width, TEXT_SOFT);
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
                TEXT_SOFT,
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
                Span::styled("ferramenta  ", Style::default().fg(TEXT_SOFT)),
                Span::styled(item.tool.clone(), Style::default().fg(TEXT)),
                Span::styled("   alvo  ", Style::default().fg(TEXT_SOFT)),
                Span::styled(
                    chrome::truncate_width(&item.target, inner.width as usize / 2).to_string(),
                    Style::default().fg(TEXT),
                ),
            ]),
            Line::from(vec![
                Span::styled("detectado  ", Style::default().fg(TEXT_SOFT)),
                Span::styled(item.detected_at.clone(), Style::default().fg(TEXT)),
                Span::styled("   origem  ", Style::default().fg(TEXT_SOFT)),
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
        append_wrapped(
            &mut lines,
            &item.description,
            inner.width as usize,
            TEXT_SOFT,
        );
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
    let block = chrome::panel_hover("Explicação educacional", focused, app.mouse_over(rows[0]));
    let inner = block.inner(rows[0]);
    frame.render_widget(block, rows[0]);
    let vulnerabilities = app.vulnerabilities();
    let mut lines: Vec<Line<'static>> = Vec::new();
    if let Some(index) = app.result_detail_vuln {
        if let Some(item) = vulnerabilities.get(index) {
            let width = inner.width as usize;
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{}  ", severity_label(item.severity)),
                    Style::default().fg(severity_color(item.severity)).bold(),
                ),
                Span::styled(item.title.clone(), Style::default().fg(TEXT).bold()),
            ]));
            lines.push(Line::from(vec![
                Span::styled("ferramenta  ", Style::default().fg(TEXT_SOFT)),
                Span::styled(item.tool.clone(), Style::default().fg(TEXT)),
                Span::styled("   arquivo  ", Style::default().fg(TEXT_SOFT)),
                match item.code_location.as_ref() {
                    Some(location) => Span::styled(
                        format!("{}:{}", location.file, location.line),
                        Style::default().fg(ACCENT).bold(),
                    ),
                    None => Span::styled(
                        "localização não determinada",
                        Style::default().fg(WARNING).bold(),
                    ),
                },
            ]));
            if app.rag_pending == Some(index) {
                append_rag_explanation(app, index, &mut lines, width);
            } else if let Some(result) = app.rag_results.get(&index) {
                append_rag_explanation(app, index, &mut lines, width);
                if !result.approved() && !item.didactic.trim().is_empty() {
                    lines.push(Line::from(""));
                    lines.push(section_rule("Resumo determinístico", width));
                    append_wrapped(&mut lines, &item.didactic, width, TEXT_SOFT);
                }
            } else {
                lines.push(Line::from(""));
                lines.push(section_rule("1. O que aconteceu e por que importa", width));
                if item.didactic.trim().is_empty() {
                    push_wrapped_owned(
                        &mut lines,
                        "sem explicação disponível para este achado.".to_string(),
                        width,
                        TEXT_SOFT,
                    );
                } else {
                    append_wrapped(&mut lines, &item.didactic, width, TEXT_SOFT);
                }
                lines.push(Line::from(""));
                push_wrapped_owned(
                    &mut lines,
                    "use \"Explicar (IA)\" para gerar a explicação educacional validada por ontologia."
                        .to_string(),
                    width,
                    TEXT_SOFT,
                );
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
            append_wrapped(&mut lines, &item.didactic, inner.width as usize, TEXT_SOFT);
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
    let has_result = app.result_detail_vuln.is_some_and(|index| {
        app.rag_results
            .get(&index)
            .is_some_and(crate::cyberrag::service::ExplanationResult::approved)
    });
    let has_failed = app.result_detail_vuln.is_some_and(|index| {
        app.rag_results
            .get(&index)
            .is_some_and(|result| !result.approved())
    });
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
        } else if has_failed {
            "Tentar de novo"
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
    if app.rag_pending == Some(index) {
        lines.push(Line::from(""));
        lines.push(section_rule("1. O que aconteceu e por que importa", width));
        push_wrapped_owned(
            lines,
            "gerando explicação educacional…".to_string(),
            width,
            TEXT_SOFT,
        );
        return;
    }
    let Some(result) = app.rag_results.get(&index) else {
        lines.push(Line::from(""));
        lines.push(section_rule("1. O que aconteceu e por que importa", width));
        push_wrapped_owned(
            lines,
            "use \"Explicar (IA)\" para gerar uma explicação validada por ontologia.".to_string(),
            width,
            TEXT_SOFT,
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
            TEXT_SOFT,
        );
    }
    lines.push(Line::from(""));
    lines.push(section_rule("1. O que aconteceu e por que importa", width));
    if !result.approved() {
        push_wrapped_owned(
            lines,
            "não consegui explicar isto com segurança.".to_string(),
            width,
            WARNING,
        );
        if let Some(reason) = result.failure_reason.as_deref() {
            push_wrapped_owned(lines, reason.to_string(), width, TEXT_SOFT);
        }
        append_rag_claims(lines, result, width);
        return;
    }
    push_wrapped_owned(lines, result.text.clone(), width, TEXT);

    lines.push(Line::from(""));
    lines.push(section_rule("2. Do vulnerável ao corrigido", width));
    match result.example.as_ref() {
        Some(example) => {
            let language = example
                .linguagem
                .clone()
                .unwrap_or_else(|| "código".to_string());
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
        None => push_wrapped_owned(
            lines,
            "sem exemplo do corpus para este achado.".to_string(),
            width,
            TEXT_SOFT,
        ),
    }

    lines.push(Line::from(""));
    lines.push(section_rule("3. Como verificar", width));
    push_wrapped_owned(
        lines,
        "Repita o teste que gerou o achado e confirme que ele não aparece mais.".to_string(),
        width,
        TEXT,
    );

    append_rag_claims(lines, result, width);
    lines.push(Line::from(""));
    push_wrapped_owned(
        lines,
        format!("veredito: {}", result.verdict_summary()),
        width,
        SUCCESS,
    );
    if result.example.is_some() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "Pergunta de fixação: explique em uma frase por que o exemplo vulnerável falha.",
            Style::default().fg(ACCENT).bold(),
        ));
    }
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
    let gutter_width: usize = 7;
    let continuation = format!("{}│ ", " ".repeat(gutter_width.saturating_sub(2)));
    let content_width = width.saturating_sub(gutter_width + 1).max(1);
    for (index, line_text) in code.lines().enumerate() {
        let gutter = format!("{:>4} │ ", index + 1);
        // Linhas longas viram várias linhas visuais; o número aparece só na
        // primeira e a cor de cada token é preservada nas continuações.
        let wrapped = crate::tui::code_preview::wrap_highlighted_line(
            crate::tui::code_preview::highlight_line(line_text, language),
            content_width,
        );
        for (part_index, tokens) in wrapped.into_iter().enumerate() {
            let gutter = if part_index == 0 {
                gutter.clone()
            } else {
                continuation.clone()
            };
            push_code_visual_line(
                lines, width, "", TEXT_SOFT, &gutter, tokens, base, color, false,
            );
        }
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
    lines.push(Line::from(""));
    lines.push(section_rule(
        "4. Para lembrar · triplas da ontologia",
        width,
    ));
    if result.claims.is_empty() && result.verdict.rejeitadas.is_empty() {
        push_wrapped_owned(
            lines,
            "sem triplas registradas nesta explicação.".to_string(),
            width,
            TEXT_SOFT,
        );
        return;
    }
    for claim in &result.claims {
        push_wrapped_owned(
            lines,
            format!(
                "  • {} → {} → {}",
                claim.sujeito, claim.relacao, claim.objeto
            ),
            width,
            TEXT,
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
                Span::styled("arquivo  ", Style::default().fg(TEXT_SOFT)),
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
                Span::styled("arquivo  ", Style::default().fg(TEXT_SOFT)),
                Span::styled(
                    "localização não determinada",
                    Style::default().fg(WARNING).bold(),
                ),
            ]));
            // Quebra a razão em linhas próprias: o texto vem do relatório da fase e é
            // dinâmico, então não pode ser uma `&'static str` do painel.
            for line in wrap_text(&reason, width.max(1)) {
                lines.push(Line::styled(line, Style::default().fg(TEXT_SOFT)));
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
                let gutter_width: usize = 7;
                let continuation = format!("{}│ ", " ".repeat(gutter_width.saturating_sub(2)));
                for code_line in code_lines {
                    let gutter = format!("{:>4} │ ", code_line.number);
                    let marker = if code_line.is_target { "> " } else { "  " };
                    let base = if code_line.is_target {
                        Style::default().bg(Color::Rgb(55, 22, 22))
                    } else {
                        Style::default().bg(Color::Rgb(13, 16, 20))
                    };
                    let border = if code_line.is_target {
                        DANGER
                    } else {
                        TEXT_SOFT
                    };
                    let content_width = width
                        .saturating_sub(marker.width() + gutter_width + 1)
                        .max(1);
                    // A linha-alvo mantém o fundo vermelho em todas as partes;
                    // o número e o marcador aparecem só na primeira.
                    let wrapped = crate::tui::code_preview::wrap_highlighted_line(
                        crate::tui::code_preview::highlight_line(&code_line.text, preview.language),
                        content_width,
                    );
                    for (part_index, tokens) in wrapped.into_iter().enumerate() {
                        let (marker, gutter) = if part_index == 0 {
                            (marker, gutter.clone())
                        } else {
                            ("  ", continuation.clone())
                        };
                        push_code_visual_line(
                            lines,
                            width,
                            marker,
                            border,
                            &gutter,
                            tokens,
                            base,
                            border,
                            code_line.is_target,
                        );
                    }
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

/// Empilha uma linha visual de bloco de código com gutter fixo, padding e borda
/// direita; as continuações reusam o mesmo gutter sem repetir o número.
#[allow(clippy::too_many_arguments)]
fn push_code_visual_line(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    marker: &str,
    marker_color: Color,
    gutter: &str,
    tokens: Vec<(String, Color)>,
    base: Style,
    border_color: Color,
    bold_tokens: bool,
) {
    let mut spans = Vec::new();
    if !marker.is_empty() {
        spans.push(Span::styled(
            marker.to_string(),
            base.fg(marker_color).bold(),
        ));
    }
    spans.push(Span::styled(gutter.to_string(), base.fg(TEXT_SOFT)));
    let mut used = marker.width() + gutter.width();
    for (text, color) in tokens {
        used += text.width();
        let style = if bold_tokens {
            base.fg(color).bold()
        } else {
            base.fg(color)
        };
        spans.push(Span::styled(text, style));
    }
    let padding = width.saturating_sub(used + 1);
    spans.push(Span::styled(" ".repeat(padding), base));
    spans.push(Span::styled("│", base.fg(border_color)));
    lines.push(Line::from(spans));
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
        Style::default().fg(TEXT_SOFT),
    ));
    push_wrapped_owned(lines, location.snippet.trim().to_string(), width, TEXT_SOFT);
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

/// Nome do arquivo + linha, como aparece na lista sem abrir o detalhe.
fn compact_location(item: &crate::domain::vulnerability::Vulnerability) -> Option<String> {
    let location = item.code_location.as_ref()?;
    let file = std::path::Path::new(&location.file)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| location.file.clone());
    Some(format!("{file}:{}", location.line))
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
        Severity::Info => TEXT_SOFT,
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

    fn comparison() -> crate::orchestrator::scan_logger::ScanComparison {
        use crate::orchestrator::scan_logger::{ComparedFinding, ScanComparison};
        let compared = |title: &str, severity: Severity| ComparedFinding {
            title: title.to_string(),
            severity,
            tool: "Nuclei".to_string(),
            target: "http://alvo.local".to_string(),
            file: None,
            line: None,
        };
        ScanComparison {
            previous_scan_id: "scan_anterior".to_string(),
            previous_completed_at: "2026-10-23T09:00:00Z".to_string(),
            previous_count: 3,
            current_count: 2,
            fixed: vec![
                compared("Painel administrativo exposto", Severity::Critical),
                compared("Versão do servidor exposta", Severity::Low),
            ],
            new: vec![compared("Segredo no código", Severity::Medium)],
            persisting: 1,
        }
    }

    /// Replay de um log com comparação: o resumo e o painel de corrigidos
    /// precisam caber em 80x24 sem esconder a auditoria nem a lista.
    #[test]
    fn the_results_show_the_comparison_and_the_fixed_panel_at_80x24_and_100x30() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        let metadata = crate::orchestrator::scan_logger::ScanMetadata::new(
            "scan_atual".to_string(),
            "http://alvo.local".to_string(),
            "2026-10-24T10:00:00Z".to_string(),
            "2026-10-24T10:05:00Z".to_string(),
            "Auto".to_string(),
            "Ollama".to_string(),
            Vec::new(),
            vec![finding("Cabeçalho ausente")],
            "Análise concluída".to_string(),
        );
        let metadata = crate::orchestrator::scan_logger::ScanMetadata {
            comparison: comparison(),
            ..metadata
        };

        app.load_replayed_scan(metadata).expect("replay válido");
        assert_eq!(app.scan_comparison.fixed.len(), 2);
        assert_eq!(app.scan_comparison.new.len(), 1);

        for (width, height) in [(80, 24), (100, 30)] {
            let screen = draw(&mut app, width, height);

            assert!(
                screen.contains("vs. última  -2 corrigidos · +1 novos · 1 persistem"),
                "resumo sem a comparação em {width}x{height}: {screen}"
            );
            assert!(
                screen.contains("scan_anterior"),
                "o id da execução anterior sumiu em {width}x{height}: {screen}"
            );
            assert!(
                screen.contains("Corrigidos desde a execução anterior"),
                "painel ausente em {width}x{height}: {screen}"
            );
            assert!(
                screen.contains("✔ CRÍTICA"),
                "o corrigido crítico não aparece em {width}x{height}: {screen}"
            );
            assert!(
                screen.contains("Painel administrativo exposto"),
                "título do corrigido truncado em {width}x{height}: {screen}"
            );
            assert!(
                screen.contains("auditoria"),
                "a comparação empurrou a auditoria para fora em {width}x{height}: {screen}"
            );
            assert!(
                screen.contains("Achados"),
                "a lista sumiu em {width}x{height}: {screen}"
            );
        }
    }

    /// Com mais corrigidos do que o painel comporta, só três linhas aparecem e
    /// o restante é anunciado por `+N` — em 80x24 o resumo e a lista continuam.
    #[test]
    fn the_fixed_panel_caps_at_three_lines_and_announces_the_rest() {
        use crate::orchestrator::scan_logger::{ComparedFinding, ScanComparison};

        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        app.orchestrator.findings.push(finding("Achado atual"));
        app.step = AppStep::Results;
        app.scan_comparison = ScanComparison {
            previous_scan_id: "scan_anterior".to_string(),
            previous_count: 5,
            current_count: 1,
            fixed: (0..5)
                .map(|index| ComparedFinding {
                    title: format!("Corrigido número {index}"),
                    severity: Severity::High,
                    tool: "Nuclei".to_string(),
                    target: "http://alvo.local".to_string(),
                    file: None,
                    line: None,
                })
                .collect(),
            ..Default::default()
        };

        let screen = draw(&mut app, 80, 24);

        assert_eq!(screen.matches('✔').count(), 3, "{screen}");
        assert!(
            screen.contains("+2"),
            "o excedente não foi anunciado: {screen}"
        );
        assert!(
            !screen.contains("Corrigido número 4"),
            "o quarto corrigido não deveria ocupar linha: {screen}"
        );
        assert!(screen.contains("auditoria"), "{screen}");
        assert!(screen.contains("Achados"), "{screen}");
    }

    /// Sem execução anterior não há linha de comparação nem painel: a tela
    /// permanece a de sempre.
    #[test]
    fn the_results_omit_the_comparison_without_a_previous_execution() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        app.orchestrator.findings.push(finding("Achado"));
        app.step = AppStep::Results;

        let screen = draw(&mut app, 80, 24);

        assert!(!screen.contains("vs. última"), "{screen}");
        assert!(
            !screen.contains("Corrigidos desde a execução anterior"),
            "{screen}"
        );
    }

    /// A linha-alvo longa vira várias linhas visuais: o número e o marcador
    /// ficam na primeira, as continuações usam o mesmo gutter e todas mantêm o
    /// fundo vermelho — sem `…` cortando código.
    #[test]
    fn long_target_code_wraps_into_visual_lines_with_the_same_gutter() {
        use crate::domain::vulnerability::CodeLocation;
        use crate::tui::code_preview::{CodeLanguage, CodePreview, PreviewLine, PreviewState};

        let location = CodeLocation {
            file: "src/app.ts".to_string(),
            line: 7,
            snippet: String::new(),
        };
        let preview = CodePreview {
            finding_index: 0,
            file: "src/app.ts".to_string(),
            line: 7,
            root: std::path::PathBuf::new(),
            language: CodeLanguage::JavaScript,
            state: PreviewState::Ready {
                first: 7,
                lines: vec![PreviewLine {
                    number: 7,
                    text: "const resultado = funcaoMuitoLonga(argumentoUm, argumentoDois, argumentoTres);"
                        .to_string(),
                    is_target: true,
                }],
                total_lines: 20,
                truncated: false,
            },
        };
        let mut lines = Vec::new();

        append_code_block(&mut lines, Some(&preview), &location, 40);

        let text_of = |line: &Line<'static>| -> String {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect()
        };
        let code_rows: Vec<&Line<'static>> = lines
            .iter()
            .filter(|line| {
                let text = text_of(line);
                text.contains('│') && !text.starts_with('┌') && !text.starts_with('└')
            })
            .collect();
        assert!(code_rows.len() > 1, "a linha longa precisa quebrar");
        let first = text_of(code_rows[0]);
        assert!(first.contains("   7 │ "), "{first}");
        assert!(first.contains("> "), "{first}");
        for row in &code_rows {
            let text = text_of(row);
            assert!(!text.contains('…'), "código não pode ser cortado: {text}");
            assert_eq!(
                row.spans[0].style.bg,
                Some(Color::Rgb(55, 22, 22)),
                "o fundo da linha-alvo precisa continuar em todas as partes: {text}"
            );
        }
        let continuation = text_of(code_rows[1]);
        assert!(
            continuation.starts_with("       │ "),
            "continuação sem repetir o número: {continuation}"
        );
    }

    #[test]
    fn long_example_code_wraps_without_an_ellipsis() {
        let mut lines = Vec::new();

        append_example_block(
            &mut lines,
            "vulnerável",
            Some("cursor.execute(\"SELECT * FROM users WHERE name = '\" + user + \"'\")"),
            "python",
            40,
            DANGER,
        );

        let text_of = |line: &Line<'static>| -> String {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect()
        };
        let code_rows: Vec<&Line<'static>> = lines
            .iter()
            .filter(|line| {
                let text = text_of(line);
                text.contains('│') && !text.starts_with('┌') && !text.starts_with('└')
            })
            .collect();
        assert!(code_rows.len() > 1, "o exemplo longo precisa quebrar");
        let first = text_of(code_rows[0]);
        assert!(first.contains("   1 │ "), "{first}");
        for row in &code_rows {
            let text = text_of(row);
            assert!(!text.contains('…'), "{text}");
            assert_eq!(
                row.spans[0].style.bg,
                Some(Color::Rgb(35, 18, 20)),
                "{text}"
            );
        }
        let continuation = text_of(code_rows[1]);
        assert!(continuation.starts_with("     │ "), "{continuation}");
    }
}
