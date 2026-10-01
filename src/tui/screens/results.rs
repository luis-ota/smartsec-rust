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
    // Uma linha extra é reservada quando o enriquecimento CVE/NVD degradou, para
    // que a indisponibilidade da NVD fique visível sem cortar o painel de 80x24.
    // Altura do resumo: metricas (2) + alvo e projeto na mesma linha (1) +
    // resumo da IA (1) + auditoria (1), e mais uma quando o aviso de
    // indisponibilidade do enriquecimento CVE/NVD esta presente. Encolher faria
    // a linha de auditoria sumir em 80x24, que e o terminal que RNF07 exige.
    let summary_height: u16 = if app.enrichment_warning.is_some() {
        8
    } else {
        7
    };
    let rows = Layout::vertical([
        // A altura acompanha o conteudo: com o aviso de indisponibilidade do
        // enriquecimento CVE/NVD o resumo ganha uma linha. Encolher faria a
        // linha de auditoria sumir em 80x24, que e o terminal que RNF07 exige.
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

fn render_summary(app: &AppState, frame: &mut Frame, area: Rect) {
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
    let severities = [
        Line::from(vec![
            metric("críticas", critical, DANGER),
            Span::raw("   "),
            metric("altas", high, Color::Rgb(220, 130, 90)),
            Span::raw("   "),
            metric("médias", medium, WARNING),
        ]),
        Line::from(vec![
            metric("baixas", low, ACCENT),
            Span::raw("   "),
            metric("informativas", info, MUTED),
        ]),
    ];
    // A linha da IA traz o resumo real devolvido pelo agente; o texto completo
    // permanece no relatório Markdown e no log de auditoria.
    let ai = Line::from(vec![
        Span::styled("ia  ", Style::default().fg(MUTED)),
        Span::styled(
            chrome::truncate_width(first_line(app.ai_summary()), inner.width as usize - 4),
            Style::default().fg(TEXT),
        ),
    ]);
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
        lines.push(severities[0].clone());
        lines.push(severities[1].clone());
        // Com ocorrências, o caminho da auditoria continua acessível no
        // relatório, no log estruturado e na tela de rastreabilidade (f2).
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
        vec![
            severities[0].clone(),
            severities[1].clone(),
            // Alvo e projeto analisado dividem a mesma linha: em 80x24 cada
            // linha extra empurra a linha de auditoria para fora da tela, e a
            // auditoria e o registro que o TCC exige. Os dois paths continuam
            // visiveis, cada um com a sua cota de largura.
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

fn metric(label: &str, value: usize, color: Color) -> Span<'_> {
    Span::styled(
        format!("{value} {label}"),
        Style::default().fg(color).bold(),
    )
}

fn render_list(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let focused = app.focus == FocusTarget::ResultsList;
    // REQ15: o painel anuncia que os críticos estão no topo, para que a
    // ordenação seja visível e não apenas implícita.
    let critical = app
        .vulnerabilities()
        .iter()
        .filter(|item| item.severity == Severity::Critical)
        .count();
    let title = if critical > 0 {
        format!("Achados · {critical} crítico(s) no topo")
    } else {
        "Achados".to_string()
    };
    let block = chrome::panel(&title, focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let vulnerabilities = app.vulnerabilities();
    if vulnerabilities.is_empty() {
        app.result_cursor = 0;
        app.result_scroll = 0;
        frame.render_widget(
            Paragraph::new("Nenhuma vulnerabilidade para revisar.")
                .style(Style::default().fg(MUTED).bg(SURFACE)),
            inner,
        );
        return;
    }
    let visible = inner.height as usize;
    app.result_cursor = app.result_cursor.min(vulnerabilities.len() - 1);
    let max_scroll = vulnerabilities.len().saturating_sub(visible);
    app.result_scroll = app.result_scroll.min(max_scroll);
    if app.result_cursor < app.result_scroll {
        app.result_scroll = app.result_cursor;
    } else if app.result_cursor >= app.result_scroll.saturating_add(visible) {
        app.result_scroll = app.result_cursor.saturating_sub(visible - 1);
    }

    let mut lines = Vec::new();
    for row in 0..visible.min(vulnerabilities.len().saturating_sub(app.result_scroll)) {
        let index = app.result_scroll + row;
        let item = &vulnerabilities[index];
        let current = index == app.result_cursor;
        let active = current && focused;
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
                    .bg(if active { SURFACE_ACTIVE } else { SURFACE })
                    .add_modifier(if current {
                        ratatui::style::Modifier::BOLD
                    } else {
                        ratatui::style::Modifier::empty()
                    }),
            ),
        );
        app.register_hit_region(
            Rect::new(inner.x, inner.y + row as u16, inner.width, 1),
            SemanticAction::OpenVulnerability(index),
        );
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        inner,
    );
}

fn render_overview_actions(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let columns = Layout::horizontal([
        Constraint::Length(13),
        Constraint::Min(1),
        Constraint::Length(17),
        Constraint::Length(1),
        Constraint::Length(12),
    ])
    .split(area);
    let new_focused = app.focus == FocusTarget::ResultsNewScan;
    let export_focused = app.focus == FocusTarget::ResultsExport;
    let didactic_focused = app.focus == FocusTarget::ResultsDidactic;
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
    chrome::render_button(
        app,
        frame,
        columns[4],
        "Explicação",
        SemanticAction::ShowDidactic,
        chrome::ButtonState::secondary(didactic_focused),
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

/// Quebra um texto **possuído** em linhas do terminal.
///
/// `append_wrapped` aceita qualquer referência, mas o detalhe do resultado é
/// montado com `Line<'static>`, então o texto precisa ser propriedade do
/// próprio `Line` em vez de apontar para o `Vulnerability`.
fn push_wrapped_owned<'a>(lines: &mut Vec<Line<'a>>, value: String, width: usize, color: Color) {
    for line in wrap_text(&value, width.max(1)) {
        lines.push(Line::styled(line, Style::default().fg(color)));
    }
}

fn render_detail(app: &mut AppState, frame: &mut Frame, area: Rect, index: usize) {
    let rows = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(area);
    let focused = app.focus == FocusTarget::ResultsDetail;
    let block = chrome::panel("Evidência e recomendação", focused);
    let inner = block.inner(rows[0]);
    frame.render_widget(block, rows[0]);
    let vulnerabilities = app.vulnerabilities();
    // O item e clonado, e nao emprestado: as linhas do painel sao `Line<'static>`
    // porque o painel e redesenhado a cada quadro e o vetor de achados e recriado
    // a cada chamada, entao elas nao podem depender do emprestimo.
    if let Some(item) = vulnerabilities.get(index).cloned() {
        // `Line<'static>` explicito: as linhas precisam ser independentes do
        // vetor de achados, que morre no fim desta funcao.
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
                    Style::default().fg(if item.source == FindingSource::Real {
                        SUCCESS
                    } else {
                        WARNING
                    }),
                ),
            ]),
            Line::from(""),
            Line::styled("Descrição", Style::default().fg(TEXT).bold()),
        ];
        append_wrapped(&mut lines, &item.description, inner.width as usize, MUTED);
        lines.push(Line::from(""));
        lines.push(Line::styled("Evidência", Style::default().fg(TEXT).bold()));
        // A evidência é sanitizada na exibição: é o campo que carrega o trecho
        // real do scanner e nunca deve exibir credencial ou corpo de requisição.
        let evidence = crate::utils::redaction::sanitize_text(&item.evidence);
        append_wrapped(&mut lines, &evidence, inner.width as usize, ACCENT);
        lines.push(Line::from(""));
        // A origem no código e a correcao proposta pelo agente de codigo (#76)
        // vem depois da evidencia: a evidencia prova o que o scanner viu, e a
        // localizacao aponta onde corrigir.
        append_code_location(
            app,
            &mut lines,
            item.code_location
                .as_ref()
                .map(|found| (found.file.clone(), found.line)),
            item.code_remediation.clone(),
            inner.width as usize,
        );
        lines.push(Line::styled(
            "Recomendação",
            Style::default().fg(TEXT).bold(),
        ));
        append_wrapped(
            &mut lines,
            &item.recommendation,
            inner.width as usize,
            SUCCESS,
        );
        append_enrichment(&mut lines, &item, inner.width as usize);
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
        Constraint::Length(13),
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
        "Explicação",
        SemanticAction::ShowDidactic,
        chrome::ButtonState::primary(app.focus == FocusTarget::ResultsDidactic),
    );
}

fn render_didactic(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let rows = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(area);
    let focused = app.focus == FocusTarget::DidacticContent;
    let block = chrome::panel("Em linguagem direta", focused);
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
            lines.push(Line::from(""));
            append_wrapped(&mut lines, &item.didactic, inner.width as usize, MUTED);
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
    let visible = inner.height.max(1) as usize;
    app.didactic_max_scroll = lines.len().saturating_sub(visible);
    app.didactic_scroll = app.didactic_scroll.min(app.didactic_max_scroll);
    let visible_lines: Vec<_> = lines
        .into_iter()
        .skip(app.didactic_scroll)
        .take(visible)
        .collect();
    frame.render_widget(
        Paragraph::new(Text::from(visible_lines)).style(Style::default().bg(SURFACE)),
        inner,
    );
    app.register_hit_region(
        rows[0],
        SemanticAction::SetFocus(FocusTarget::DidacticContent),
    );
    let actions = Layout::horizontal([Constraint::Length(10), Constraint::Min(1)]).split(rows[1]);
    chrome::render_button(
        app,
        frame,
        actions[0],
        "Voltar",
        SemanticAction::Back,
        chrome::ButtonState::secondary(app.focus == FocusTarget::DidacticBack),
    );
}

/// Mostra a origem no código e os passos de correção de um achado.
///
/// A ausência de origem é explícita e nunca é substituída por um caminho ou
/// linha inventados: o painel diz "localização não determinada" e o operador
/// sabe que precisa de outra fonte, em vez de perseguir um arquivo errado.
fn append_code_location(
    app: &AppState,
    lines: &mut Vec<Line<'static>>,
    location: Option<(String, usize)>,
    remediation: Vec<String>,
    width: usize,
) {
    // As linhas são `Line<'static>`: o painel é redesenhado a cada quadro e o
    // relatório da fase é reconstruído a cada execução, então as poucas strings
    // envolvidas são clonadas em vez de emprestarem o lifetime do vetor de
    // achados.
    lines.push(Line::styled(
        "Localização no código",
        Style::default().fg(TEXT).bold(),
    ));
    match location {
        Some((file, line)) => {
            lines.push(Line::from(vec![
                Span::styled("arquivo  ", Style::default().fg(MUTED)),
                Span::styled(
                    chrome::truncate_width(&file, width.saturating_sub(9)),
                    Style::default().fg(ACCENT).bold(),
                ),
                Span::styled(format!("  linha {line}"), Style::default().fg(TEXT)),
            ]));
            if !remediation.is_empty() {
                lines.push(Line::styled(
                    "Correção sugerida",
                    Style::default().fg(TEXT).bold(),
                ));
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

fn append_wrapped(lines: &mut Vec<Line<'static>>, value: &str, width: usize, color: Color) {
    for paragraph in value.split("\n\n") {
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
