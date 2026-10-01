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
    AppState::new(Configuration::default()).expect("configuração de teste válida")
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
        origins: Vec::new(),
        enrichment: None,
        severity_conflict: None,
        ..Default::default()
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
fn the_nikto_is_selectable_in_the_tool_catalog_of_the_tui() {
    let mut app = app();
    app.step = AppStep::ToolSelect;
    app.tool_detecting = false;

    // O catálogo da TUI vem do registry, sem lista manual de ferramentas.
    let names: Vec<&str> = app
        .tools
        .iter()
        .map(|tool| tool.tool.name.as_str())
        .collect();
    assert!(
        names.contains(&"Nikto"),
        "o Nikto deveria estar selecionável na TUI: {names:?}"
    );
    assert!(names.contains(&"Nmap"), "{names:?}");
    assert!(names.contains(&"Nuclei"), "{names:?}");

    // E aparece na lista renderizada em 80x24.
    assert_snapshot(&mut app, &["Ferramentas de segurança", "Nikto", "DAST"]);
}

#[test]
fn the_zap_is_selectable_in_the_tool_catalog_of_the_tui() {
    let mut app = app();
    app.step = AppStep::ToolSelect;
    app.tool_detecting = false;

    let names: Vec<&str> = app
        .tools
        .iter()
        .map(|tool| tool.tool.name.as_str())
        .collect();
    assert!(
        names.contains(&"ZAP"),
        "o ZAP deveria estar selecionável na TUI: {names:?}"
    );

    assert_snapshot(&mut app, &["Ferramentas de segurança", "ZAP", "DAST"]);
}

#[test]
fn the_paused_execution_state_is_legible_in_80x24() {
    let mut app = app();
    app.step = AppStep::Execution;
    app.focus = FocusTarget::ExecutionLogs;
    app.tools[0].status = ToolStatus::Running;
    app.orchestrator.pause_execution();
    app.exec_paused = true;
    app.tools[0].status = ToolStatus::Paused;
    app.exec_logs = vec![
        "[14:02:11] [Nmap] container abc123 pausado".to_string(),
        "[14:02:12] [Nmap] $ podman pause abc123".to_string(),
    ];

    let snapshot = assert_snapshot(
        &mut app,
        &[
            "Execução PAUSADA",
            "pausada",
            "Retomar varredura",
            "Cancelar varredura",
        ],
    );
    // RNF07: a pausa precisa ser legível, e o botão precisa ser clicável.
    assert!(snapshot.contains("p retoma"), "{snapshot}");
    assert!(app
        .hit_regions
        .iter()
        .any(|region| { region.action == SemanticAction::ResumeRun }));
    assert!(app
        .hit_regions
        .iter()
        .any(|region| { region.action == SemanticAction::CancelRun }));
}

#[test]
fn the_running_execution_state_offers_the_pause_button() {
    let mut app = app();
    app.step = AppStep::Execution;
    app.tools[0].status = ToolStatus::Running;

    assert_snapshot(
        &mut app,
        &["executando", "Pausar varredura", "Cancelar varredura"],
    );
    assert!(app
        .hit_regions
        .iter()
        .any(|region| region.action == SemanticAction::PauseRun));
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
            "REQ14",
            "REQ05",
            "REQ16",
            "0/8 verificados",
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
            "4/8 verificados",
            "alvo validado",
            "rootless confirmado",
            "Nmap ok",
            "scan_1.json",
            "f2 reabre",
        ],
    );
    assert!(snapshot.contains("○ REQ10"), "{snapshot}");
    assert!(snapshot.contains("○ REQ14"), "{snapshot}");
    assert!(snapshot.contains("○ REQ05"), "{snapshot}");
    // REQ16 fica pendente porque a fase de código ainda não rodou: é isso que
    // distingue "análise de código não executou" de "executou e não achou
    // origem", e a linha precisa dizer qual dos dois é o caso.
    assert!(snapshot.contains("○ REQ16"), "{snapshot}");
    assert!(
        snapshot.contains("aguardando análise de código"),
        "{snapshot}"
    );
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

/// Semeia um histórico real em disco e devolve o diretório isolado do teste.
fn seed_history(label: &str, count: usize) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "smartsec_historico_tui_{label}_{}_{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("diretório de histórico de teste");
    for index in 0..count {
        let metadata = crate::orchestrator::scan_logger::ScanMetadata {
            scan_id: format!("scan_17570000000000000{index:02}"),
            target_url: format!("http://alvo{index}.local"),
            started_at: "2026-09-06T10:00:00Z".to_string(),
            completed_at: format!("2026-09-0{}T10:05:00Z", 6 + index),
            execution_type: "Auto".to_string(),
            llm_provider: "Ollama".to_string(),
            tools_executed: vec![crate::orchestrator::scan_logger::ToolExecutionRecord {
                tool_name: "Nmap".to_string(),
                arguments: vec!["-sT".to_string()],
                executed_at: "2026-09-06T10:01:00Z".to_string(),
                output_bytes: 42,
                output_sample: String::new(),
                stdout: String::new(),
                stderr: String::new(),
                status: "succeeded".to_string(),
                duration_ms: 1500,
                tool_version: Some("7.94".to_string()),
                image: Some("docker.io/library/nmap:7.94".to_string()),
                execution_error: None,
                podman_trace: Vec::new(),
            }],
            findings_count: 2,
            critical_count: 0,
            high_count: 1,
            medium_count: 0,
            low_count: 0,
            info_count: 1,
            findings: vec![serde_json::json!({
                "title": "Versão desatualizada",
                "severity": "High",
                "tool": "Nmap",
            })],
            agent_analysis: "A superfície web expõe serviços antigos.".to_string(),
            enrichment: Default::default(),
            decisions: Vec::new(),
            interruption: None,
            ..Default::default()
        };
        crate::orchestrator::scan_logger::save_scan_log_to_dir(&metadata, &dir)
            .expect("gravação do registro de teste");
    }
    dir
}

#[test]
fn history_list_and_detail_match_80x24_snapshots() {
    let dir = seed_history("snapshots", 2);
    let mut app = app();
    app.history_dir = dir.clone();
    app.step = AppStep::Results;
    app.focus = FocusTarget::ResultsList;
    super::event::dispatch_action(&mut app, SemanticAction::OpenHistory);
    assert_eq!(app.step, AppStep::History);

    assert_snapshot(
        &mut app,
        &[
            "Histórico",
            "Execuções anteriores",
            "scan_1757000000000000001",
            "C0 A1 M0 B0 I1",
            "Abrir",
        ],
    );

    super::event::dispatch_action(&mut app, SemanticAction::OpenHistoryRecord(0));
    assert_snapshot(
        &mut app,
        &[
            "Detalhe da execução",
            "Ferramentas executadas",
            "Nmap",
            "Achados",
            "Versão desatualizada",
            "Análise da IA",
        ],
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn history_without_records_explains_how_to_create_the_first_one() {
    let root = std::env::temp_dir().join(format!(
        "smartsec_historico_tui_vazio_{}_{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let dir = root.join("vazio");
    std::fs::create_dir_all(&dir).unwrap();

    // Diretório inexistente: a tela orienta a criar o primeiro registro.
    let mut app = app();
    app.history_dir = root.join("inexistente");
    app.step = AppStep::History;
    app.focus = FocusTarget::HistoryList;
    app.load_history();
    let (snapshot, _) = render_80x24(&mut app);
    assert!(snapshot.contains("Execuções anteriores"), "{snapshot}");
    assert!(
        snapshot.contains("Nenhuma execução registrada"),
        "{snapshot}"
    );
    assert!(snapshot.contains("Execute uma análise"), "{snapshot}");

    // Diretório existente e vazio: a tela distingue "vazio" de "inexistente".
    app.history_dir = dir;
    app.load_history();
    let (snapshot, _) = render_80x24(&mut app);
    assert!(
        snapshot.contains("O histórico está vazio"),
        "diretório vazio deve ser distinto de inexistente: {snapshot}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn history_reports_unreadable_records_in_80x24() {
    let dir = seed_history("ilegivel", 1);
    std::fs::write(dir.join("scan_1757000000000000009.json"), "{quebrado").unwrap();

    let mut app = app();
    app.history_dir = dir.clone();
    app.step = AppStep::History;
    app.focus = FocusTarget::HistoryList;
    app.load_history();

    let snapshot = assert_snapshot(&mut app, &["Execuções anteriores", "1 registro ilegível"]);

    assert!(
        snapshot.contains("scan_1757000000000000009.json"),
        "{snapshot}"
    );

    let _ = std::fs::remove_dir_all(&dir);
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
    println!("--- topo apos rolar para cima ---\n{top}\n--- fim no auto-follow ---\n{bottom}");
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
