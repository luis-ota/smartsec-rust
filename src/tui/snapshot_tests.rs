use super::chrome::{ACCENT, SURFACE};
use super::interaction::{FocusTarget, SemanticAction};
use super::state::{AnalysisPhase, AppState, AppStep, ToolStatus};
use crate::config::Configuration;
use crate::domain::vulnerability::{FindingSource, Vulnerability};
use crate::domain::Severity;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;
use unicode_width::UnicodeWidthStr;

fn render_80x24(app: &mut AppState) -> (String, Buffer) {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| super::render(app, frame)).unwrap();
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

fn assert_snapshot(app: &mut AppState, expected: &[&str]) -> String {
    let (snapshot, _) = render_80x24(app);
    assert_eq!(snapshot.lines().count(), 24, "{snapshot}");
    assert!(
        snapshot.lines().all(|line| line.width() <= 80),
        "{snapshot}"
    );
    assert!(snapshot.contains("SmartSec"), "{snapshot}");
    assert!(snapshot.contains("f1 ajuda"), "{snapshot}");
    assert!(snapshot.contains("ctrl+p comandos"), "{snapshot}");
    for text in expected {
        assert!(snapshot.contains(text), "texto ausente: {text}\n{snapshot}");
    }
    for region in &app.hit_regions {
        assert!(region.area.x.saturating_add(region.area.width) <= 80);
        assert!(region.area.y.saturating_add(region.area.height) <= 24);
    }
    snapshot
}

fn app() -> AppState {
    AppState::new(Configuration::default())
}

fn finding() -> Vulnerability {
    Vulnerability {
        title: "Achado de teste".to_string(),
        severity: Severity::Critical,
        description: "Descrição técnica".to_string(),
        tool: "Nuclei".to_string(),
        recommendation: "Aplique a correção".to_string(),
        didactic: "Explicação didática".to_string(),
        source: FindingSource::Real,
        target: "https://exemplo.local".to_string(),
        evidence: "evidência".to_string(),
        detected_at: "2026-09-04T14:00:00Z".to_string(),
    }
}

#[test]
fn splash_matches_80x24_snapshot() {
    let mut app = app();
    assert_snapshot(
        &mut app,
        &[
            "Nova análise",
            "SMARTSEC",
            "Alvo",
            "Modo selecionado",
            "Iniciar",
        ],
    );
}

#[test]
fn tool_selection_loading_ready_and_empty_match_80x24_snapshots() {
    let mut app = app();
    app.step = AppStep::ToolSelect;
    assert_snapshot(
        &mut app,
        &["Ferramentas", "Verificando catálogo", "Executar"],
    );

    app.tool_detecting = false;
    assert_snapshot(&mut app, &["Nmap", "Contexto", "selecionadas"]);

    app.tools.clear();
    assert_snapshot(&mut app, &["Nenhuma ferramenta disponível"]);
}

#[test]
fn execution_states_match_80x24_snapshots() {
    let mut app = app();
    app.step = AppStep::Execution;
    app.focus = FocusTarget::ExecutionLogs;
    assert_snapshot(
        &mut app,
        &[
            "Execução",
            "Atuação da IA",
            "Aguardando evidências do Nmap",
            "Aguardando a primeira saída",
        ],
    );

    app.ai_activity = super::state::AiActivity::PlanningNuclei;
    assert_snapshot(
        &mut app,
        &["IA definindo o plano do Nuclei", "política segura"],
    );

    app.exec_logs = vec!["FALHA: ferramenta indisponível".to_string()];
    app.tools[0].status = ToolStatus::Failed;
    assert_snapshot(&mut app, &["FALHA: ferramenta indisponível"]);

    for tool in &mut app.tools {
        tool.status = ToolStatus::Done;
        tool.progress = 100;
    }
    assert_snapshot(&mut app, &["Preparando análise da IA", "100%"]);
}

#[test]
fn analysis_states_match_80x24_snapshots_without_neural_decoration() {
    let mut app = app();
    app.step = AppStep::Analysis;
    app.focus = FocusTarget::AnalysisCancel;
    app.analysis_text = "Validando evidências coletadas".to_string();
    assert_snapshot(&mut app, &["examinando resultados", "Validando evidências"]);

    app.analysis_phase = AnalysisPhase::Complete;
    let snapshot = assert_snapshot(&mut app, &["concluída · 100%", "Resultados prontos"]);
    assert!(!snapshot.contains("Neural"));
}

#[test]
fn result_empty_list_detail_and_didactic_match_80x24_snapshots() {
    let mut app = app();
    app.step = AppStep::Results;
    app.focus = FocusTarget::ResultsList;
    assert_snapshot(&mut app, &["Nenhum achado identificado", "Nova análise"]);

    app.orchestrator.findings = vec![finding()];
    assert_snapshot(&mut app, &["Achados", "CRÍTICA", "Exportar"]);

    app.result_detail_vuln = Some(0);
    app.focus = FocusTarget::ResultsDetail;
    assert_snapshot(
        &mut app,
        &["Detalhe do achado", "Descrição", "Recomendação"],
    );

    app.show_didactic = true;
    app.focus = FocusTarget::DidacticContent;
    assert_snapshot(&mut app, &["Explicação didática", "Em linguagem direta"]);
}

#[test]
fn export_path_and_report_viewer_match_80x24_snapshots() {
    let mut app = app();
    app.step = AppStep::Results;
    app.focus = FocusTarget::ResultsExport;
    app.md_exported = true;
    app.exported_report_path = Some(std::path::PathBuf::from("/tmp/smartsec-report.md"));
    assert_snapshot(
        &mut app,
        &["Ver relatório", "salvo em", "smartsec-report.md"],
    );

    app.report_content = "# Relatório\nachado crítico corrigido".to_string();
    app.show_report_viewer = true;
    app.focus = FocusTarget::ReportClose;
    assert_snapshot(
        &mut app,
        &[
            "Relatório exportado",
            "smartsec-report.md",
            "achado crítico corrigido",
            "voltar",
        ],
    );
}

#[test]
fn traceability_overlay_matches_80x24_snapshots() {
    let mut app = app();
    app.step = AppStep::Results;
    app.show_trace_overlay = true;
    app.focus = FocusTarget::TraceClose;
    assert_snapshot(
        &mut app,
        &[
            "Rastreabilidade",
            "UC01",
            "RNF01",
            "REQ06",
            "REQ09",
            "REQ10",
            "0/5 verificados",
        ],
    );

    app.config.target_url = "http://169.254.1.2:3000".to_string();
    app.orchestrator.execution_history.push({
        let mut execution =
            crate::domain::security_tool::SecurityTool::new("Nmap", "nmap -Pn -sT -sV");
        execution.status = "succeeded".to_string();
        execution.duration_ms = 11_500;
        execution.podman_trace = vec![
            "[15:54:54] $ podman info".to_string(),
            "[15:54:55] podman rootless verificado".to_string(),
        ];
        execution
    });
    app.audit_log_path = Some(std::path::PathBuf::from(
        "/home/user/.config/smartsec/scans/scan_1.json",
    ));
    let snapshot = assert_snapshot(
        &mut app,
        &[
            "4/5 verificados",
            "alvo validado",
            "rootless confirmado",
            "Nmap ok",
            "scan_1.json",
            "f2 reabre",
        ],
    );
    assert!(snapshot.contains("○ REQ10"), "{snapshot}");
}

#[test]
fn settings_help_and_palette_match_80x24_snapshots() {
    let mut app = app();
    app.show_settings = true;
    app.focus = FocusTarget::SettingsField(super::state::SettingsField::Provider);
    assert_snapshot(
        &mut app,
        &[
            "Configurações de IA",
            "Provedor",
            "Conexão principal",
            "Confiabilidade",
            "Salvar alterações",
        ],
    );

    app.show_help_overlay = true;
    app.overlay_return_focus = app.focus;
    app.focus = FocusTarget::HelpClose;
    assert_snapshot(
        &mut app,
        &["Ajuda", "f1", "qualquer contexto", "mesmas ações"],
    );

    app.show_help_overlay = false;
    app.show_command_palette = true;
    app.focus = FocusTarget::CommandList;
    assert_snapshot(
        &mut app,
        &["Comandos", "Abrir ajuda", "f1", "Salvar configurações"],
    );
}

#[test]
fn wrapped_log_lines_expand_the_scroll_limit() {
    let mut app = app();
    app.step = AppStep::Execution;
    app.focus = FocusTarget::ExecutionLogs;
    app.exec_logs = (0..6)
        .map(|index| format!("L{index}-INICIO{}{index}FIM", "x".repeat(400)))
        .collect();

    let (bottom, _) = render_80x24(&mut app);
    assert!(
        app.log_total_lines > app.exec_logs.len(),
        "linhas longas devem ocupar mais de uma linha visual"
    );
    assert!(app.log_max_scroll() > 0, "deve haver conteúdo além da tela");
    assert!(
        bottom.contains("5FIM"),
        "o fim do log deve estar visível no auto-follow\n{bottom}"
    );

    app.log_follow = false;
    app.log_scroll = 0;
    let (top, _) = render_80x24(&mut app);
    assert!(
        top.contains("L0-INICIO"),
        "o topo deve permanecer acessível\n{top}"
    );
    assert!(
        !top.contains("5FIM"),
        "o fim não pode aparecer na visão do topo\n{top}"
    );
}

#[test]
fn semantic_focus_changes_the_rendered_list_style() {
    let mut app = app();
    app.step = AppStep::ToolSelect;
    app.tool_detecting = false;
    app.focus = FocusTarget::ToolList;
    let (_, focused_backend) = render_80x24(&mut app);
    let row = app
        .hit_regions
        .iter()
        .find(|region| region.action == SemanticAction::ToggleTool(0))
        .unwrap()
        .area;
    assert_eq!(focused_backend[(row.x, row.y)].bg, ACCENT);

    app.focus = FocusTarget::ToolRun;
    let (_, blurred_backend) = render_80x24(&mut app);
    assert_eq!(blurred_backend[(row.x, row.y)].bg, SURFACE);
}
