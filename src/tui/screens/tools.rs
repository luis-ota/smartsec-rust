use crate::tui::chrome::{self, ACCENT, DANGER, MUTED, SUCCESS, SURFACE, TEXT, WARNING};
use crate::tui::interaction::{FocusTarget, SemanticAction};
use crate::tui::state::{AppState, ToolStatus};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Paragraph, Wrap},
    Frame,
};

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    // A tela é o momento de montagem: a pré-seleção pelo perfil do projeto é
    // aplicada aqui, uma vez por projeto, e nunca no meio do scan.
    app.apply_tool_preselection();
    let selected = app.tools.iter().filter(|tool| tool.selected).count();
    let status = if app.tools.is_empty() {
        "Nenhuma ferramenta disponível".to_string()
    } else {
        format!("{selected} de {} ferramentas selecionadas", app.tools.len())
    };
    let shell = chrome::render_shell(app, frame, area, "Ferramentas", &status);
    let rows = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(shell.content);
    if rows[0].width < 120 {
        let list_height = (app.tools.len() as u16).saturating_add(2).clamp(4, 8);
        let stacked =
            Layout::vertical([Constraint::Length(list_height), Constraint::Min(3)]).split(rows[0]);
        render_tool_list(app, frame, stacked[0]);
        render_tool_detail(app, frame, stacked[1]);
    } else {
        let columns = Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)])
            .split(rows[0]);
        render_tool_list(app, frame, columns[0]);
        render_tool_detail(app, frame, columns[1]);
    }
    render_actions(app, frame, rows[1]);
}

fn render_tool_list(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let focused = app.focus == FocusTarget::ToolList;
    let block = chrome::panel("Ferramentas de segurança", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    app.tool_visible_height = inner.height.max(1) as usize;

    if app.tools.is_empty() {
        frame.render_widget(
            Paragraph::new(" Nenhuma ferramenta foi encontrada. Volte e revise a configuração.")
                .style(Style::default().fg(MUTED).bg(SURFACE)),
            inner,
        );
        return;
    }

    let mut lines = Vec::new();
    let visible = inner
        .height
        .min(app.tools.len().saturating_sub(app.tool_scroll) as u16);
    for row in 0..visible {
        let index = app.tool_scroll + row as usize;
        let row_area = Rect::new(inner.x, inner.y + row, inner.width, 1);
        let hovered = app.mouse_over(row_area);
        let line = {
            let tool = &app.tools[index];
            let current = index == app.tool_cursor;
            let active = focused && current;
            let state = if tool.selected { "[x]" } else { "[ ]" };
            let prefix = if current { ">" } else { " " };
            let mut spans = vec![
                Span::styled(format!("{prefix} {state} "), Style::default()),
                Span::styled(format!("{:<12}", tool.tool.name), Style::default().bold()),
                Span::styled(format!("{:<9}", tool.tool.category), Style::default()),
            ];
            if let Some(reason) = tool.recommendation {
                const COLUMNS_BEFORE_REASON: usize = 6 + 12 + 9;
                let remaining = (inner.width as usize).saturating_sub(COLUMNS_BEFORE_REASON);
                spans.push(Span::styled(
                    chrome::truncate_width(reason, remaining),
                    Style::default().fg(if active { Color::Black } else { MUTED }),
                ));
            }
            Line::from(spans).style(
                Style::default()
                    .fg(if active { Color::Black } else { TEXT })
                    .bg(if active {
                        ACCENT
                    } else if hovered {
                        chrome::SURFACE_HOVER
                    } else {
                        SURFACE
                    }),
            )
        };
        lines.push(line);
        app.register_hit_region(row_area, SemanticAction::ToggleTool(index));
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .style(Style::default().bg(SURFACE))
            .wrap(Wrap { trim: false }),
        inner,
    );
}

fn render_tool_detail(app: &AppState, frame: &mut Frame, area: Rect) {
    let block = chrome::panel("Contexto", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(tool) = app.tools.get(app.tool_cursor) else {
        frame.render_widget(
            Paragraph::new("Selecione uma ferramenta para ver os detalhes.")
                .style(Style::default().fg(MUTED).bg(SURFACE)),
            inner,
        );
        return;
    };
    let (status, color) = match tool.status {
        ToolStatus::Pending => ("pendente", MUTED),
        ToolStatus::Running => ("em execução", ACCENT),
        ToolStatus::Paused => ("pausada", WARNING),
        ToolStatus::Done => ("concluída", SUCCESS),
        ToolStatus::Failed => ("falhou", DANGER),
    };
    let mut lines = vec![
        Line::styled(&tool.tool.name, Style::default().fg(TEXT).bold()),
        Line::styled(&tool.tool.description, Style::default().fg(MUTED)),
        Line::from(""),
        Line::from(vec![
            Span::styled("estado  ", Style::default().fg(MUTED)),
            Span::styled(status, Style::default().fg(color).bold()),
        ]),
    ];
    if let Some(summary) = app.project_profile_summary.as_deref() {
        lines.push(Line::from(vec![
            Span::styled("perfil  ", Style::default().fg(MUTED)),
            Span::styled(summary.to_string(), Style::default().fg(TEXT)),
        ]));
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        inner,
    );
}

fn render_actions(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let columns = Layout::horizontal([
        Constraint::Length(10),
        Constraint::Min(1),
        Constraint::Length(12),
    ])
    .split(area);
    chrome::render_button(
        app,
        frame,
        columns[0],
        "Voltar",
        SemanticAction::Back,
        chrome::ButtonState::secondary(app.focus == FocusTarget::ToolBack),
    );
    chrome::render_button(
        app,
        frame,
        columns[2],
        "Executar",
        SemanticAction::RunTools,
        chrome::ButtonState::primary(app.focus == FocusTarget::ToolRun)
            .enabled(app.tools.iter().any(|tool| tool.selected)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Configuration;
    use crate::tui::state::{AppStep, ToolItem};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::fs;
    use unicode_width::UnicodeWidthStr;

    fn temp_project(label: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "smartsec-tela-ferramentas-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn write(root: &std::path::Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    fn app_for(root: &std::path::Path) -> AppState {
        let config = Configuration {
            project_dir: Some(root.display().to_string()),
            ..Configuration::default()
        };
        let mut app = AppState::new(config).expect("configuração de teste válida");
        app.step = AppStep::ToolSelect;
        app.focus = FocusTarget::ToolList;
        app
    }

    fn render_80x24(app: &mut AppState) -> (String, ratatui::buffer::Buffer) {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("terminal de teste");
        terminal
            .draw(|frame| crate::tui::render(app, frame))
            .expect("render da tela de ferramentas");
        let buffer = terminal.backend().buffer().clone();
        let snapshot = (0..24)
            .map(|row| {
                (0..80)
                    .map(|column| buffer[(column, row)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        (snapshot, buffer)
    }

    fn tool<'a>(app: &'a AppState, name: &str) -> &'a ToolItem {
        app.tools
            .iter()
            .find(|tool| tool.tool.name == name)
            .unwrap_or_else(|| panic!("{name} deveria estar no catálogo da TUI"))
    }

    /// A montagem da tela aplica a recomendação: o projeto NoSQL desmarca o
    /// SQLMap, o Nikto, o ZAP e o TruffleHog, e cada linha desmarcada explica
    /// o porquê em uma linha.
    #[test]
    fn the_nosql_project_explains_the_deselected_tools_at_80x24() {
        let root = temp_project("nosql");
        write(
            &root,
            "package.json",
            r#"{"dependencies":{"mongoose":"^8.0.0","redis":"^4.6.0"}}"#,
        );
        write(
            &root,
            "server.js",
            "const mongoose = require('mongoose');\nconst redis = require('redis');\n",
        );

        let mut app = app_for(&root);
        let (snapshot, _) = render_80x24(&mut app);

        assert_eq!(snapshot.lines().count(), 24, "{snapshot}");
        assert!(
            snapshot.lines().all(|line| line.width() <= 80),
            "{snapshot}"
        );
        assert!(snapshot.contains("[x] Nmap"), "{snapshot}");
        assert!(snapshot.contains("[x] Nuclei"), "{snapshot}");
        assert!(snapshot.contains("[ ] SQLMap"), "{snapshot}");
        assert!(snapshot.contains("[ ] Nikto"), "{snapshot}");
        assert!(snapshot.contains("[ ] ZAP"), "{snapshot}");
        assert!(snapshot.contains("[ ] TruffleHog"), "{snapshot}");
        assert!(
            snapshot.contains("nenhum indício de banco SQL (projeto parece NoSQL)"),
            "{snapshot}"
        );
        assert!(
            snapshot.contains("nenhum indício de aplicação web no projeto"),
            "{snapshot}"
        );
        assert!(
            snapshot.contains("sem repositório git para varrer o histórico"),
            "{snapshot}"
        );
        assert!(
            snapshot.contains("descoberta de portas e serviços"),
            "{snapshot}"
        );
        assert!(snapshot.contains("perfil  JavaScript"), "{snapshot}");

        let _ = fs::remove_dir_all(&root);
    }

    /// Projeto web fica com Nikto e ZAP marcados e com o motivo visível; o
    /// SQLMap sem indícios de banco continua marcado por precaução.
    #[test]
    fn a_web_project_keeps_nikto_and_zap_with_reason_at_80x24() {
        let root = temp_project("web");
        write(
            &root,
            "app.py",
            "from flask import Flask\n\napp = Flask(__name__)\n",
        );
        write(
            &root,
            "templates/index.html",
            "<!doctype html><title>Início</title>\n",
        );

        let mut app = app_for(&root);
        let (snapshot, _) = render_80x24(&mut app);

        assert_eq!(snapshot.lines().count(), 24, "{snapshot}");
        assert!(
            snapshot.lines().all(|line| line.width() <= 80),
            "{snapshot}"
        );
        assert!(snapshot.contains("[x] Nikto"), "{snapshot}");
        assert!(snapshot.contains("[x] ZAP"), "{snapshot}");
        assert!(
            snapshot.contains("indício de aplicação web no projeto"),
            "{snapshot}"
        );
        assert!(snapshot.contains("[x] SQLMap"), "{snapshot}");
        assert!(
            snapshot.contains("sem indícios de banco; mantida por precaução"),
            "{snapshot}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// Lista explícita em `active_tools` é do usuário: a recomendação não a
    /// substitui e nenhuma linha ganha motivo.
    #[test]
    fn explicit_active_tools_disable_the_recommendation_on_screen() {
        let root = temp_project("lista-explicita");
        write(
            &root,
            "package.json",
            r#"{"dependencies":{"mongoose":"^8.0.0"}}"#,
        );
        let config = Configuration {
            project_dir: Some(root.display().to_string()),
            active_tools: vec!["Nmap".to_string(), "Nikto".to_string()],
            ..Configuration::default()
        };
        let mut app = AppState::new(config).expect("configuração de teste válida");
        app.step = AppStep::ToolSelect;
        app.focus = FocusTarget::ToolList;

        let (snapshot, _) = render_80x24(&mut app);

        assert!(snapshot.contains("[x] Nmap"), "{snapshot}");
        assert!(
            snapshot.contains("[x] Nikto"),
            "a lista explícita manda, mesmo sem indício de web: {snapshot}"
        );
        assert!(snapshot.contains("[ ] SQLMap"), "{snapshot}");
        assert!(tool(&app, "SQLMap").recommendation.is_none());
        assert!(tool(&app, "Nmap").recommendation.is_none());
        assert!(app.project_profile_summary.is_none());
        assert!(!snapshot.contains("indício"), "{snapshot}");

        let _ = fs::remove_dir_all(&root);
    }

    /// A recomendação é aplicada uma vez por projeto: o ajuste manual do
    /// usuário não é sobrescrito pelo próximo quadro.
    #[test]
    fn a_manual_toggle_survives_the_next_frame() {
        let root = temp_project("ajuste-manual");
        write(
            &root,
            "package.json",
            r#"{"dependencies":{"mongoose":"^8.0.0"}}"#,
        );
        let mut app = app_for(&root);

        render_80x24(&mut app);
        assert!(!tool(&app, "SQLMap").selected, "a pré-seleção desmarcou");

        app.tools
            .iter_mut()
            .find(|tool| tool.tool.name == "SQLMap")
            .unwrap()
            .selected = true;
        render_80x24(&mut app);

        assert!(
            tool(&app, "SQLMap").selected,
            "o toggle manual do usuário sempre vence"
        );

        let _ = fs::remove_dir_all(&root);
    }
}
