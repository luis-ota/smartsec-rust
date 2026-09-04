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
    assert_snapshot(&mut app, &["Execução", "Aguardando a primeira saída"]);

    app.exec_logs = vec!["FALHA: ferramenta indisponível".to_string()];
    app.tools[0].status = ToolStatus::Failed;
    assert_snapshot(&mut app, &["FALHA: ferramenta indisponível"]);

    for tool in &mut app.tools {
        tool.status = ToolStatus::Done;
        tool.progress = 100;
    }
    assert_snapshot(&mut app, &["Varredura concluída", "100%"]);
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
fn settings_help_and_palette_match_80x24_snapshots() {
    let mut app = app();
    app.show_settings = true;
    app.focus = FocusTarget::SettingsField(super::state::SettingsField::Provider);
    assert_snapshot(
        &mut app,
        &[
            "Configurações",
            "Provedor",
            "Consentimento remoto",
            "Salvar",
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
