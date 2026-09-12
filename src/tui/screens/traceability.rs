use crate::orchestrator::decision::DecisionSource;
use crate::tui::chrome::{self, ACCENT, MUTED, SUCCESS, SURFACE, TEXT};
use crate::tui::interaction::SemanticAction;
use crate::tui::state::AppState;
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

pub struct RequirementRow {
    pub id: &'static str,
    pub title: &'static str,
    pub detail: String,
    pub evidenced: bool,
}

pub fn requirement_rows(app: &AppState) -> Vec<RequirementRow> {
    vec![
        cli_row(app),
        sandbox_row(app),
        orchestration_row(app),
        logs_row(app),
        ai_row(app),
    ]
}

fn cli_row(app: &AppState) -> RequirementRow {
    let target = app.config.target_url.trim();
    let evidenced = !target.is_empty() && app.config.validate_target().is_ok();
    RequirementRow {
        id: "UC01",
        title: "CLI e configuração",
        detail: if evidenced {
            format!("alvo validado · {target}")
        } else {
            "aguardando alvo válido (IP, domínio ou URL)".to_string()
        },
        evidenced,
    }
}

fn sandbox_row(app: &AppState) -> RequirementRow {
    let verified = app.orchestrator.execution_history.iter().any(|execution| {
        execution
            .podman_trace
            .iter()
            .any(|line| line.contains("rootless verificado"))
    });
    RequirementRow {
        id: "RNF01",
        title: "Sandbox Podman rootless",
        detail: if verified {
            "rootless confirmado · rede pasta · cap-drop all · read-only · tmpfs".to_string()
        } else {
            "aguardando execução isolada no Podman rootless".to_string()
        },
        evidenced: verified,
    }
}

fn orchestration_row(app: &AppState) -> RequirementRow {
    let executed: Vec<_> = app
        .orchestrator
        .execution_history
        .iter()
        .filter(|execution| matches!(execution.tool_name.as_str(), "Nmap" | "Nuclei"))
        .collect();
    let evidenced = executed
        .iter()
        .any(|execution| execution.status == "succeeded");
    let detail = if executed.is_empty() {
        "aguardando disparo sequencial de Nmap e Nuclei".to_string()
    } else {
        executed
            .iter()
            .map(|execution| {
                format!(
                    "{} {} {:.1}s",
                    execution.tool_name,
                    status_label(&execution.status),
                    execution.duration_ms as f64 / 1_000.0
                )
            })
            .collect::<Vec<_>>()
            .join(" · ")
    };
    RequirementRow {
        id: "REQ06",
        title: "Orquestração de Nmap e Nuclei",
        detail,
        evidenced,
    }
}

fn logs_row(app: &AppState) -> RequirementRow {
    let trace_lines: usize = app
        .orchestrator
        .execution_history
        .iter()
        .map(|execution| execution.podman_trace.len())
        .sum();
    let audit = app
        .audit_log_path
        .as_ref()
        .and_then(|path| path.file_name())
        .map(|name| name.to_string_lossy().to_string());
    let evidenced = audit.is_some() || trace_lines > 0;
    let detail = match (audit, trace_lines) {
        (Some(name), lines) => format!(
            "{name} · {} achados · {lines} linhas de trace",
            app.orchestrator.findings.len()
        ),
        (None, lines) if lines > 0 => {
            format!("{lines} linhas capturadas · persistência pendente")
        }
        _ => "aguardando captura de stdout/stderr dos containers".to_string(),
    };
    RequirementRow {
        id: "REQ09",
        title: "Logs e auditoria",
        detail,
        evidenced,
    }
}

fn ai_row(app: &AppState) -> RequirementRow {
    let decision = app.orchestrator.decision_history.last();
    let evidenced = decision.is_some();
    let detail = match decision {
        Some(record) => {
            let source = match record.source {
                DecisionSource::Ai => format!("IA decidiu ({})", record.model),
                DecisionSource::Fallback => {
                    format!("política local decidiu (modelo {})", record.model)
                }
            };
            let mut detail = format!(
                "{source} · {} paralelos · timeout {}s · {}",
                record
                    .parameters
                    .get("concurrency")
                    .cloned()
                    .unwrap_or_else(|| "?".to_string()),
                record
                    .parameters
                    .get("timeout_seconds")
                    .cloned()
                    .unwrap_or_else(|| "?".to_string()),
                record
                    .parameters
                    .get("templates")
                    .cloned()
                    .unwrap_or_default()
            );
            if app
                .orchestrator
                .last_log
                .contains("Orientações complementares da IA")
            {
                detail.push_str(" · orientações da IA aplicadas");
            }
            detail
        }
        None => format!(
            "provedor {} · {} · decisão pendente",
            app.config.llm.provider.label(),
            app.config.llm.model
        ),
    };
    RequirementRow {
        id: "REQ10",
        title: "Agente de IA na decisão",
        detail,
        evidenced,
    }
}

fn status_label(status: &str) -> &'static str {
    match status {
        "succeeded" => "ok",
        "skipped" => "ignorado",
        "timeout" => "tempo esgotado",
        "cancelled" => "cancelado",
        _ => "falhou",
    }
}

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    app.hit_regions.clear();
    let rows = requirement_rows(app);
    let popup = super::overlays::centered_fixed(area, 76, 15);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(" Rastreabilidade · Sprint 1 ")
        .title_style(Style::default().fg(Color::White).bold())
        .style(Style::default().bg(SURFACE));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let evidenced = rows.iter().filter(|row| row.evidenced).count();
    let mut lines = vec![
        Line::styled(
            format!(
                "Evidências reais desta sessão · {evidenced}/{} verificados",
                rows.len()
            ),
            Style::default().fg(MUTED),
        ),
        Line::from(""),
    ];
    for row in &rows {
        let (symbol, color) = if row.evidenced {
            ("✓", SUCCESS)
        } else {
            ("○", MUTED)
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{symbol} "), Style::default().fg(color).bold()),
            Span::styled(
                format!("{} · {}", row.id, row.title),
                Style::default().fg(TEXT).bold(),
            ),
        ]));
        lines.push(Line::styled(
            format!(
                "    {}",
                chrome::truncate_width(&row.detail, inner.width.saturating_sub(5) as usize)
            ),
            Style::default().fg(if row.evidenced {
                Color::Gray
            } else {
                Color::DarkGray
            }),
        ));
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        inner,
    );
    let footer = Rect::new(
        inner.x,
        inner.y + inner.height.saturating_sub(1),
        inner.width,
        1,
    );
    app.register_hit_region(footer, SemanticAction::Back);
    frame.render_widget(
        Paragraph::new("f2 reabre · esc ou enter fecha")
            .alignment(Alignment::Right)
            .style(Style::default().fg(ACCENT).bg(SURFACE)),
        footer,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Configuration;
    use crate::domain::security_tool::SecurityTool;
    use crate::orchestrator::decision::{DecisionRecord, NucleiPlan, NucleiTemplateProfile};
    use std::collections::BTreeMap;

    fn app() -> AppState {
        AppState::new(Configuration::default())
    }

    fn nmap_execution() -> SecurityTool {
        let mut execution = SecurityTool::new("Nmap", "nmap -Pn -sT -sV 169.254.1.2");
        execution.status = "succeeded".to_string();
        execution.duration_ms = 11_500;
        execution.podman_trace = vec![
            "[15:54:54] $ podman info --format {{.Host.Security.Rootless}}".to_string(),
            "[15:54:55] podman rootless verificado".to_string(),
            "[15:54:55] $ podman create --network pasta ...".to_string(),
        ];
        execution
    }

    fn ai_decision() -> DecisionRecord {
        let mut parameters = BTreeMap::new();
        parameters.insert("should_run".to_string(), "true".to_string());
        parameters.insert("concurrency".to_string(), "10".to_string());
        parameters.insert("timeout_seconds".to_string(), "5".to_string());
        parameters.insert(
            "templates".to_string(),
            "http/misconfiguration/,http/exposed-panels/".to_string(),
        );
        DecisionRecord {
            source: DecisionSource::Ai,
            model: "openai/gpt-oss-120b".to_string(),
            justification: "Plano proposto pela IA e aceito pela política segura.".to_string(),
            parameters,
            evidence: Vec::new(),
            plan: NucleiPlan {
                should_run: true,
                profiles: vec![NucleiTemplateProfile::HttpMisconfiguration],
                concurrency: 10,
                timeout_seconds: 5,
            },
        }
    }

    #[test]
    fn pending_session_reports_every_requirement_as_waiting() {
        let rows = requirement_rows(&app());

        assert_eq!(rows.len(), 5);
        assert_eq!(
            rows.iter().map(|row| row.id).collect::<Vec<_>>(),
            vec!["UC01", "RNF01", "REQ06", "REQ09", "REQ10"]
        );
        assert!(rows.iter().all(|row| !row.evidenced));
        assert!(rows
            .iter()
            .all(|row| row.detail.contains("aguardando") || row.detail.contains("pendente")));
    }

    #[test]
    fn completed_session_evidences_all_five_requirements() {
        let mut app = app();
        app.config.target_url = "http://169.254.1.2:3000".to_string();
        app.orchestrator.execution_history.push(nmap_execution());
        app.orchestrator.decision_history.push(ai_decision());
        app.audit_log_path = Some(std::path::PathBuf::from(
            "/home/user/.config/smartsec/scans/scan_1.json",
        ));
        app.orchestrator.last_log =
            "Análise concluída.\n\nOrientações complementares da IA (sem alterar as classificações):\n- Valide a exposição."
                .to_string();

        let rows = requirement_rows(&app);
        assert!(
            rows.iter().all(|row| row.evidenced),
            "pendentes: {:?}",
            rows.iter()
                .filter(|row| !row.evidenced)
                .map(|row| (row.id, row.detail.as_str()))
                .collect::<Vec<_>>()
        );

        let sandbox = rows.iter().find(|row| row.id == "RNF01").unwrap();
        assert!(sandbox.detail.contains("rootless confirmado"));

        let logs = rows.iter().find(|row| row.id == "REQ09").unwrap();
        assert!(logs.detail.contains("scan_1.json"));
        assert!(logs.detail.contains("3 linhas de trace"));

        let ai = rows.iter().find(|row| row.id == "REQ10").unwrap();
        assert!(ai.detail.contains("IA decidiu"));
        assert!(ai.detail.contains("gpt-oss-120b"));
        assert!(ai.detail.contains("10 paralelos"));
        assert!(ai.detail.contains("orientações da IA aplicadas"));
    }

    #[test]
    fn fallback_decision_is_shown_as_the_local_policy() {
        let mut app = app();
        let mut record = ai_decision();
        record.source = DecisionSource::Fallback;
        record.model = "llama3.2:1b".to_string();
        app.orchestrator.decision_history.push(record);

        let rows = requirement_rows(&app);
        let ai = rows.iter().find(|row| row.id == "REQ10").unwrap();
        assert!(ai.detail.contains("política local decidiu"));
        assert!(!ai.detail.contains("IA decidiu"));
    }
}
