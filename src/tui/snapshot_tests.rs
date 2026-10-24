use super::chrome::{ACCENT, ACCENT_HOVER, DANGER, SURFACE, SURFACE_ACTIVE, SURFACE_HOVER};
use super::interaction::{FocusTarget, SemanticAction};
use super::state::{
    AiTimelineEntry, AiTimelineOrigin, AnalysisPhase, AppState, AppStep, RunIssueScope,
    SettingsField, ToolStatus,
};
use crate::config::environment::{
    EnvironmentReport, KeyringAvailability, LocalEndpoint, PodmanMode,
};
use crate::config::llm_config::LlmProviderKind;
use crate::config::onboarding::{OnboardingState, OnboardingStep};
use crate::config::Configuration;
use crate::domain::vulnerability::{FindingSource, Vulnerability};
use crate::domain::Severity;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::Terminal;
use unicode_width::UnicodeWidthStr;

fn render_80x24(app: &mut AppState) -> (String, Buffer) {
    render_size(app, 80, 24)
}

fn render_size(app: &mut AppState, width: u16, height: u16) -> (String, Buffer) {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| super::render(app, frame)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let snapshot = (0..height)
        .map(|row| {
            (0..width)
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

/// Células de uma área como (símbolo, fg, bg, bold): o hover é estilo, então a
/// comparação precisa enxergar cor e modificador, não só texto.
fn styled_cells(
    buffer: &Buffer,
    area: Rect,
) -> Vec<(String, ratatui::style::Color, ratatui::style::Color, bool)> {
    let mut cells = Vec::new();
    for row in area.y..area.y.saturating_add(area.height) {
        for column in area.x..area.x.saturating_add(area.width) {
            let cell = &buffer[(column, row)];
            cells.push((
                cell.symbol().to_string(),
                cell.fg,
                cell.bg,
                cell.modifier.contains(ratatui::style::Modifier::BOLD),
            ));
        }
    }
    cells
}

fn region_of(app: &AppState, action: &SemanticAction) -> Rect {
    app.hit_regions
        .iter()
        .find(|region| &region.action == action)
        .map(|region| region.area)
        .expect("a ação precisa ter região clicável")
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
        evidence: "template: expo · endpoint https://exemplo.local/atual".to_string(),
        detected_at: "2026-09-04T14:00:00Z".to_string(),
        origins: Vec::new(),
        enrichment: None,
        severity_conflict: None,
        ..Default::default()
    }
}

/// Criterio de aceite 1: a TUI abre com configuracao de IA invalida e mostra o
/// problema na linha de status. O texto e o mesmo do erro do headless, entao a
/// mensagem nao muda conforme a interface.
#[test]
fn the_splash_shows_the_configuration_problem_instead_of_refusing_to_open() {
    let mut app = app();
    app.step = AppStep::Splash;
    app.set_config_warning(Some(
        "IA: As credenciais da LLM remota são obrigatórias".to_string(),
    ));

    let snapshot = assert_snapshot(&mut app, &["Nova análise", "Alvo", "Iniciar"]);

    assert!(
        snapshot.contains("credenciais da LLM remota são obrigatórias"),
        "o aviso de configuracao nao chegou à tela de abertura: {snapshot}"
    );
}

/// Sem problema de configuracao, a linha de status segue o que promete: nada de
/// aviso fantasma.
#[test]
fn a_valid_configuration_shows_no_warning_on_the_splash() {
    let mut app = app();
    app.step = AppStep::Splash;
    app.set_config_warning(None);

    let snapshot = assert_snapshot(&mut app, &["Nova análise", "Alvo", "Iniciar"]);

    assert!(!snapshot.contains("obrigatórias"), "{snapshot}");
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
            "Execuções recentes",
            "Iniciar",
        ],
    );
}

#[test]
fn splash_lists_recent_executions_and_opens_results() {
    let dir = seed_history("splash_recent", 3);
    let mut app = app();
    app.history_dir = dir.clone();
    app.load_history();

    let snapshot = assert_snapshot(
        &mut app,
        &["Execuções recentes", "http://alvo2.local", "2 ach."],
    );
    assert!(
        app.hit_regions
            .iter()
            .any(|region| region.action == SemanticAction::OpenRecentScan(0)),
        "a linha da execução recente precisa ser clicável\n{snapshot}"
    );

    app.focus = FocusTarget::SplashRecent;
    app.splash_recent_cursor = 0;
    crate::tui::event::dispatch_action(&mut app, SemanticAction::OpenRecentScan(0));

    assert_eq!(app.step, AppStep::Results);
    assert!(
        app.config.target_url.starts_with("http://alvo2.local"),
        "{}",
        app.config.target_url
    );
    assert_eq!(app.orchestrator.findings.len(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tool_selection_ready_and_empty_match_80x24_snapshots() {
    let mut app = app();
    app.step = AppStep::ToolSelect;

    // O catálogo vem do registry de forma síncrona: a listagem já está pronta e
    // não existe estado intermediário de "verificando catálogo".
    let snapshot = assert_snapshot(&mut app, &["Ferramentas", "Executar", "Nmap", "Contexto"]);
    assert!(
        !snapshot.contains("Verificando catálogo"),
        "a detecção de catálogo era cenografia de temporizador\n{snapshot}"
    );

    app.tools.clear();
    assert_snapshot(&mut app, &["Nenhuma ferramenta disponível"]);
}

#[test]
fn the_nikto_is_selectable_in_the_tool_catalog_of_the_tui() {
    let mut app = app();
    app.step = AppStep::ToolSelect;

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
    app.set_exec_logs(vec![
        "[14:02:11] [Nmap] container abc123 pausado".to_string(),
        "[14:02:12] [Nmap] $ podman pause abc123".to_string(),
    ]);

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

    app.set_exec_logs(vec!["FALHA: ferramenta indisponível".to_string()]);
    app.tools[0].status = ToolStatus::Failed;
    assert_snapshot(&mut app, &["FALHA: ferramenta indisponível"]);

    for tool in &mut app.tools {
        tool.status = ToolStatus::Done;
    }
    assert_snapshot(&mut app, &["Ferramentas concluídas", "100%"]);
}

/// A tela de Execução mostra todas as ocorrências da execução, não só a
/// primeira, e distingue aviso de IA de falha.
#[test]
fn execution_screen_shows_every_registered_occurrence() {
    let mut app = app();
    app.step = AppStep::Execution;
    app.focus = FocusTarget::ExecutionLogs;
    app.record_run_issue(RunIssueScope::Tool, "Nmap falhou: imagem ausente no Podman");
    app.record_run_issue(
        RunIssueScope::Ai,
        "A LLM principal falhou: conexão recusada; usando o llama.cpp local",
    );
    app.record_run_issue(
        RunIssueScope::Audit,
        "falha ao salvar auditoria: sem permissão",
    );

    let snapshot = assert_snapshot(
        &mut app,
        &[
            "Ocorrências",
            "ferramenta: Nmap falhou",
            "IA: A LLM principal falhou",
            "auditoria: falha ao salvar",
        ],
    );
    assert!(
        snapshot.contains("Execução concluída com 3 ocorrências")
            || snapshot.contains("Executando varredura"),
        "o status precisa acompanhar o painel de ocorrências\n{snapshot}"
    );
}

/// A fase da análise reflete o evento real do pipeline e não um percentual
/// fixo: enquanto a IA trabalha, a tela mostra o tempo decorrido em vez de
/// uma porcentagem inventada.
#[test]
fn analysis_states_match_80x24_snapshots_without_neural_decoration() {
    let mut app = app();
    app.step = AppStep::Analysis;
    app.focus = FocusTarget::AnalysisCancel;
    app.analysis_phase = AnalysisPhase::Correlating;
    app.analysis_findings = 4;
    let snapshot = assert_snapshot(
        &mut app,
        &["4 achados em correlação", "Progresso da análise"],
    );
    assert!(
        !snapshot.contains("25%") && !snapshot.contains("55%"),
        "as fases não podem mais exibir percentuais fixos\n{snapshot}"
    );

    app.analysis_phase = AnalysisPhase::Generating;
    app.analysis_wait_secs = 42;
    let snapshot = assert_snapshot(&mut app, &["gerando orientações · 42s"]);
    assert!(!snapshot.contains("85%"), "{snapshot}");
    assert!(!snapshot.contains("Neural"), "{snapshot}");
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
        &[
            "Detalhe do achado",
            "Descrição",
            "Evidência",
            "Recomendação",
            "template: expo",
        ],
    );

    app.show_didactic = true;
    app.focus = FocusTarget::DidacticContent;
    assert_snapshot(&mut app, &["Explicação didática", "Explicação educacional"]);
}

/// A explicação assistida (RAG) mostra o exemplo e o veredito, ou a recusa
/// explícita com motivo.
#[test]
fn finding_didactic_shows_the_rag_explanation_or_the_refusal() {
    let mut app = app();
    app.step = AppStep::Results;
    app.orchestrator.findings = vec![finding()];
    app.result_detail_vuln = Some(0);
    app.focus = FocusTarget::ResultsDetail;

    app.detail_scroll = usize::MAX;
    let snapshot = assert_snapshot(&mut app, &["Detalhe do achado", "Explicar (IA)"]);
    assert!(
        !snapshot.contains("Explicação assistida (RAG)"),
        "a explicação da IA não fica mais no detalhe\n{snapshot}"
    );

    app.show_didactic = true;
    app.focus = FocusTarget::DidacticContent;
    app.rag_pending = Some(0);
    app.didactic_scroll = 0;
    let snapshot = assert_snapshot(
        &mut app,
        &[
            "Explicação educacional",
            "gerando explicação educacional…",
            "1. O que aconteceu e por que importa",
        ],
    );
    assert!(
        snapshot.contains("ferramenta  Nuclei"),
        "o cabeçalho precisa identificar a ferramenta\n{snapshot}"
    );

    app.rag_pending = None;
    app.rag_results.insert(0, rag_result(true));
    app.didactic_scroll = 0;
    let (snapshot, _) = render_size(&mut app, 100, 40);
    assert!(
        snapshot.contains("A entrada é concatenada na consulta."),
        "{snapshot}"
    );
    assert!(
        snapshot.contains("2. Do vulnerável ao corrigido"),
        "{snapshot}"
    );
    assert!(snapshot.contains("┌─ vulnerável"), "{snapshot}");
    assert!(snapshot.contains("┌─ corrigido"), "{snapshot}");
    assert!(snapshot.contains("padrão seguro"), "{snapshot}");
    assert!(snapshot.contains("3. Como verificar"), "{snapshot}");
    assert!(
        snapshot.contains("4. Para lembrar · triplas da ontologia"),
        "{snapshot}"
    );
    assert!(snapshot.contains("sem triplas registradas"), "{snapshot}");
    assert!(snapshot.contains("veredito"), "{snapshot}");
    assert!(snapshot.contains("Pergunta de fixação"), "{snapshot}");

    app.rag_results.insert(0, rag_result(false));
    app.didactic_scroll = 0;
    let (snapshot, _) = render_size(&mut app, 100, 40);
    assert!(
        snapshot.contains("não consegui explicar isto com segurança."),
        "{snapshot}"
    );
    assert!(snapshot.contains("o provedor falhou"), "{snapshot}");
    assert!(
        snapshot.contains("4. Para lembrar · triplas da ontologia"),
        "{snapshot}"
    );
    assert!(snapshot.contains("Tentar de novo"), "{snapshot}");
    assert!(snapshot.contains("Resumo determinístico"), "{snapshot}");
}

/// A tela educacional identifica o achado (severidade, ferramenta e
/// arquivo:linha) e mantém as triplas da ontologia visíveis.
#[test]
fn the_educational_screen_identifies_the_finding_and_shows_the_ontology() {
    use crate::domain::vulnerability::CodeLocation;

    let mut app = app();
    app.step = AppStep::Results;
    let mut item = finding();
    item.title = "Injeção de SQL no login".to_string();
    item.tool = "Code Audit".to_string();
    item.code_location = Some(CodeLocation {
        file: "src/login.ts".to_string(),
        line: 34,
        snippet: "db.query(`SELECT * FROM users WHERE name = '${user}'`);".to_string(),
    });
    app.orchestrator.findings = vec![item];
    app.result_detail_vuln = Some(0);
    app.show_didactic = true;
    app.focus = FocusTarget::DidacticContent;

    let mut result = rag_result(true);
    result.claims = vec![crate::cyberrag::ontology::OntologyClaim {
        sujeito: "injecao_sql".to_string(),
        relacao: "expoe".to_string(),
        objeto: "banco_de_dados".to_string(),
    }];
    app.rag_results.insert(0, result);

    let (snapshot, _) = render_size(&mut app, 100, 40);

    assert!(
        snapshot.contains("CRÍTICA  Injeção de SQL no login"),
        "{snapshot}"
    );
    assert!(snapshot.contains("ferramenta  Code Audit"), "{snapshot}");
    assert!(snapshot.contains("src/login.ts:34"), "{snapshot}");
    assert!(
        snapshot.contains("4. Para lembrar · triplas da ontologia"),
        "{snapshot}"
    );
    assert!(
        snapshot.contains("• injecao_sql → expoe → banco_de_dados"),
        "{snapshot}"
    );
    assert!(snapshot.contains("Pergunta de fixação"), "{snapshot}");
}

fn rag_result(approved: bool) -> crate::cyberrag::service::ExplanationResult {
    crate::cyberrag::service::ExplanationResult {
        finding_index: 0,
        text: if approved {
            "A entrada é concatenada na consulta.".to_string()
        } else {
            String::new()
        },
        conceito: "injecao_sql".to_string(),
        example: approved.then(|| crate::cyberrag::service::RetrievedExample {
            id: "injecao_sql".to_string(),
            titulo: "Injeção de SQL".to_string(),
            padrao_seguro: "Use consulta parametrizada.".to_string(),
            linguagem: Some("python".to_string()),
            vulneravel: Some("cursor.execute(query + user)".to_string()),
            corrigido: Some("cursor.execute(query, (user,))".to_string()),
            header: None,
        }),
        claims: Vec::new(),
        verdict: crate::cyberrag::ontology::OntologyVerdict {
            aprovado: approved,
            verificadas: usize::from(approved),
            rejeitadas: Vec::new(),
        },
        provider: "NVIDIA NIM".to_string(),
        model: "modelo".to_string(),
        failure_reason: (!approved).then(|| "o provedor falhou".to_string()),
        generated_at: "2026-10-14T00:00:00Z".to_string(),
        retrieval_mode: "lexical".to_string(),
    }
}

/// Detalhe com evidência longa e saneada: o link com o scanner é o elemento
/// central da tela de evidência e nunca pode vazar credencial.
#[test]
fn finding_detail_shows_long_and_sanitized_evidence() {
    let mut app = app();
    app.step = AppStep::Results;
    let mut item = finding();
    item.evidence = format!(
        "template: expose-config · matched-at: https://alvo.local/actuator/env · {}\n\nAuthorization: Bearer token-secreto-1234567890",
        "matched-header muito longo ".repeat(20)
    );
    app.orchestrator.findings = vec![item];
    app.result_detail_vuln = Some(0);
    app.focus = FocusTarget::ResultsDetail;

    let snapshot = assert_snapshot(
        &mut app,
        &[
            "Evidência",
            "template: expose-config",
            "alvo  https://exemplo.local",
            "origem  real",
            "2026-09-04T14:00:00Z",
        ],
    );
    assert!(
        !snapshot.contains("token-secreto"),
        "a evidência precisa ser sanitizada antes de virar texto de tela\n{snapshot}"
    );

    app.detail_scroll = app.detail_max_scroll;
    let (scrolled, _) = render_80x24(&mut app);
    assert!(
        scrolled.contains("[REDACTED]"),
        "a linha com credencial é substituída por [REDACTED]\n{scrolled}"
    );
    assert!(!scrolled.contains("token-secreto"), "{scrolled}");
}

/// A lista identifica cada achado sem abrir o detalhe: severidade, ferramenta,
/// título e arquivo:linha, nessa ordem, legíveis em 80x24.
#[test]
fn the_results_list_identifies_tool_and_location_at_80x24() {
    use crate::domain::vulnerability::CodeLocation;

    let mut app = app();
    app.step = AppStep::Results;
    app.focus = FocusTarget::ResultsList;
    app.orchestrator.findings = vec![Vulnerability {
        title: "Injeção de SQL no login".to_string(),
        severity: Severity::Critical,
        tool: "Code Audit".to_string(),
        code_location: Some(CodeLocation {
            file: "src/login.ts".to_string(),
            line: 34,
            snippet: "db.query(query)".to_string(),
        }),
        ..finding()
    }];

    let (snapshot, _) = render_80x24(&mut app);
    let row = snapshot
        .lines()
        .find(|line| line.contains("Injeção de SQL no login"))
        .expect("a linha do achado precisa estar visível");

    assert!(row.contains("CRÍTICA"), "{snapshot}");
    assert!(row.contains("Code Audit"), "{snapshot}");
    assert!(row.contains("login.ts:34"), "{snapshot}");
    let severity = row.find("CRÍTICA").unwrap();
    let tool = row.find("Code Audit").unwrap();
    let title = row.find("Injeção de SQL no login").unwrap();
    let location = row.find("login.ts:34").unwrap();
    assert!(
        severity < tool && tool < title && title < location,
        "a ordem precisa ser severidade · ferramenta · título · arquivo:linha\n{snapshot}"
    );
}

/// REQ15: os críticos ficam no topo, o painel anuncia isso e a cor da
/// severidade continua presente na linha selecionada.
#[test]
fn critical_findings_lead_the_list_and_keep_their_color_when_selected() {
    let mut app = app();
    app.step = AppStep::Results;
    app.focus = FocusTarget::ResultsList;
    app.orchestrator.findings = vec![
        Vulnerability {
            title: "Versão exposta".to_string(),
            severity: Severity::Info,
            ..finding()
        },
        finding(),
    ];

    let (snapshot, buffer) = render_80x24(&mut app);
    let lines: Vec<&str> = snapshot.lines().collect();
    let critical_row = lines
        .iter()
        .position(|line| line.contains("Shell aberta") || line.contains("CRÍTICA"))
        .expect("linha do achado crítico");
    let info_row = lines
        .iter()
        .position(|line| line.contains("Versão exposta"))
        .expect("linha do achado informativo");
    assert!(
        critical_row < info_row,
        "o crítico precisa vir primeiro\n{snapshot}"
    );
    assert!(snapshot.contains("crítico(s) no topo"), "{snapshot}");

    let column = lines[critical_row]
        .find("CRÍTICA")
        .expect("rótulo de severidade") as u16;
    assert_eq!(
        buffer[(column, critical_row as u16)].fg,
        DANGER,
        "a severidade do scanner é autoritativa e não some com a seleção"
    );
    assert_ne!(
        buffer[(column, critical_row as u16)].bg,
        ACCENT,
        "o destaque da seleção vem do fundo, não da cor da severidade"
    );
}

/// O resumo de Resultados também agrega as ocorrências e mostra o resumo real
/// devolvido pelo agente de IA.
#[test]
fn results_summary_aggregates_occurrences_and_shows_the_ai_summary() {
    let mut app = app();
    app.step = AppStep::Results;
    app.focus = FocusTarget::ResultsList;
    app.config.target_url = "https://alvo.local".to_string();
    app.orchestrator.findings = vec![finding()];
    app.agent.last_analysis =
        "Análise concluída: 1 achados (1 críticos, 0 altos, 0 médios, 0 baixos e 0 informativos)."
            .to_string();
    app.record_run_issue(RunIssueScope::Tool, "Nmap falhou: imagem ausente no Podman");
    app.record_run_issue(
        RunIssueScope::Audit,
        "falha ao salvar auditoria: sem permissão",
    );

    assert_snapshot(
        &mut app,
        &[
            "ferramenta: Nmap falhou",
            "+1 ocorrências no log da execução",
            "1 críticas",
            "ia  Análise concluída: 1 achados",
        ],
    );
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

/// O bloco de IA da Execução anuncia o atalho e é clicável: é a porta de
/// entrada do painel ao vivo enquanto uma ferramenta demora.
#[test]
fn the_execution_ai_block_offers_the_live_timeline() {
    let mut app = app();
    app.step = AppStep::Execution;
    app.focus = FocusTarget::ExecutionLogs;

    let snapshot = assert_snapshot(&mut app, &["Atuação da IA", "i abre"]);
    assert!(
        app.hit_regions
            .iter()
            .any(|region| region.action == SemanticAction::OpenAiTimeline),
        "o bloco de IA precisa ser clicável\n{snapshot}"
    );
}

#[test]
fn ai_timeline_overlay_matches_80x24_snapshots() {
    let mut app = app();
    app.step = AppStep::Execution;
    app.ai_timeline = vec![
        AiTimelineEntry {
            time: "14:02:10".to_string(),
            origin: AiTimelineOrigin::Planning,
            text: "planejando o uso do Nuclei…".to_string(),
        },
        AiTimelineEntry {
            time: "14:02:14".to_string(),
            origin: AiTimelineOrigin::Planning,
            text:
                "plano do Nuclei definido: a IA decidiu · motivo: Plano aceito pela política segura"
                    .to_string(),
        },
        AiTimelineEntry {
            time: "14:03:41".to_string(),
            origin: AiTimelineOrigin::Ai,
            text: "análise em andamento (10s)".to_string(),
        },
        AiTimelineEntry {
            time: "14:04:02".to_string(),
            origin: AiTimelineOrigin::Code,
            text: "ferramenta read_file no achado #1".to_string(),
        },
    ];
    app.show_ai_timeline = true;
    app.focus = FocusTarget::AiTimelineClose;

    let snapshot = assert_snapshot(
        &mut app,
        &[
            "Atividade da IA",
            "4 ação(ões) registradas",
            "14:02:10 planejamento planejando o uso do Nuclei…",
            "14:02:14 planejamento plano do Nuclei definido",
            "fechar",
        ],
    );
    // Cada entrada sai como `HH:MM:SS origem texto`, com a origem da etapa.
    for (time, origin, text) in [
        ("14:03:41", "IA", "análise em andamento (10s)"),
        ("14:04:02", "código", "ferramenta read_file no achado #1"),
    ] {
        let line = snapshot
            .lines()
            .find(|line| line.contains(time))
            .unwrap_or_else(|| panic!("linha de {time} ausente\n{snapshot}"));
        assert!(
            line.contains(origin) && line.contains(text),
            "formato inesperado: {line}"
        );
    }
    assert!(
        app.hit_regions
            .iter()
            .any(|region| region.action == SemanticAction::Back),
        "o botão fechar precisa de região clicável\n{snapshot}"
    );

    // Estado vazio: o painel explica quando a IA age, em vez de parecer travado.
    app.ai_timeline.clear();
    let snapshot = assert_snapshot(
        &mut app,
        &[
            "Atividade da IA",
            "0 ação(ões) registradas",
            "A IA ainda não agiu nesta execução",
            "antes do Nuclei",
            "(planejamento) e depois das ferramentas",
        ],
    );
    assert!(snapshot.contains("agente de código"), "{snapshot}");
}

#[test]
fn settings_help_and_palette_match_80x24_snapshots() {
    let mut app = app();
    app.show_settings = true;
    app.focus = FocusTarget::SettingsField(super::state::SettingsField::Provider);
    assert_snapshot(
        &mut app,
        &[
            "Configurar IA",
            "Provedor de IA",
            "Quem responde",
            "Segurança e limites",
            "Salvar alterações",
        ],
    );

    app.show_help_overlay = true;
    app.overlay_return_focus = app.focus;
    app.focus = FocusTarget::HelpClose;
    assert_snapshot(
        &mut app,
        &[
            "Ajuda",
            "f1",
            "qualquer contexto",
            "mesmas ações",
            "rodapé explica o campo em foco",
        ],
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
            findings: vec![serde_json::to_value(Vulnerability {
                title: "Versão desatualizada".to_string(),
                severity: Severity::High,
                tool: "Nmap".to_string(),
                target: format!("http://alvo{index}.local"),
                evidence: "nmap porta=22/tcp serviço=ssh".to_string(),
                detected_at: "2026-09-06T10:01:00Z".to_string(),
                ..Default::default()
            })
            .expect("achado do seed")],
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

/// Monta o assistente numa etapa, com a sondagem já entregue. Não usa a
/// sondagem de verdade: rede, keyring e Podman ficam fora do snapshot.
fn onboarding_at(step: OnboardingStep) -> AppState {
    let mut app = app();
    let mut onboarding = OnboardingState::start();
    onboarding.step = step;
    if step == OnboardingStep::Environment {
        onboarding.deliver_environment(EnvironmentReport {
            local_llm: Some(LocalEndpoint {
                name: "llama.cpp".to_string(),
                base_url: "http://localhost:8080/v1".to_string(),
            }),
            keyring: KeyringAvailability::Available,
            podman: PodmanMode::Rootless,
        });
    }
    app.onboarding = Some(onboarding);
    app.focus = FocusTarget::OnboardingList;
    app
}

#[test]
fn the_first_run_screen_lists_what_the_machine_has_at_80x24() {
    let mut app = onboarding_at(OnboardingStep::Environment);

    let snapshot = assert_snapshot(
        &mut app,
        &[
            "Primeira configuração",
            "O que encontramos nesta máquina",
            "IA local disponível",
            "llama.cpp responde em http://localhost:8080/v1",
            "Armazenamento de credenciais disponível",
            "Podman rootless disponível",
        ],
    );

    assert!(
        !snapshot.contains("localhost:11434"),
        "a tela não pode afirmar que não existe IA local quando encontrou uma: {snapshot}"
    );
}

#[test]
fn a_machine_without_a_secret_vault_is_told_the_remote_key_cannot_be_saved() {
    let mut app = onboarding_at(OnboardingStep::Environment);
    if let Some(onboarding) = app.onboarding.as_mut() {
        onboarding.deliver_environment(EnvironmentReport {
            local_llm: None,
            keyring: KeyringAvailability::Unavailable(
                "nenhum serviço de segredos ativo".to_string(),
            ),
            podman: PodmanMode::Absent,
        });
    }

    let snapshot = assert_snapshot(
        &mut app,
        &[
            "Nenhuma IA local encontrada",
            "não poderão ser salvas",
            "serviço de segredos ativo",
            "Podman não encontrado",
        ],
    );

    assert!(snapshot.contains("localhost:8080"), "{snapshot}");
    assert!(snapshot.contains("localhost:11434"), "{snapshot}");
}

#[test]
fn the_provider_step_offers_local_remote_and_custom_at_80x24() {
    let mut app = onboarding_at(OnboardingStep::Provider);

    let snapshot = assert_snapshot(&mut app, &["Provedor de IA", "Continuar com esta escolha"]);

    for label in LlmProviderKind::all_labels() {
        assert!(snapshot.contains(label), "faltou {label}: {snapshot}");
    }
}

#[test]
fn the_consent_step_says_what_leaves_the_machine() {
    let mut app = onboarding_at(OnboardingStep::Consent);

    let snapshot = assert_snapshot(
        &mut app,
        &[
            "Consentimento para IA remota",
            "saem desta máquina",
            "Aceitar e usar o provedor remoto",
            "Recusar e usar o modelo local",
        ],
    );

    assert!(snapshot.contains("código do projeto"), "{snapshot}");
}

#[test]
fn the_credential_step_never_shows_the_typed_secret() {
    let mut app = onboarding_at(OnboardingStep::Credential);
    app.settings_input_api_key = "sk-segredo-digitado".to_string();
    app.settings_api_key_touched = true;

    let snapshot = assert_snapshot(
        &mut app,
        &[
            "Credencial do provedor remoto",
            "nunca é gravada no arquivo de configuração",
        ],
    );

    assert!(!snapshot.contains("segredo"), "{snapshot}");
    assert!(snapshot.contains("••••••••"), "{snapshot}");
}

#[test]
fn the_connection_step_offers_an_optional_test() {
    let mut app = onboarding_at(OnboardingStep::Connection);

    assert_snapshot(
        &mut app,
        &[
            "Teste de conexão",
            "Teste ainda não executado",
            "Testar a conexão agora",
            "Concluir e salvar a configuração",
        ],
    );
}

/// Cada escolha precisa de região clicável na linha em que aparece: um
/// registro deslocado faria o clique acionar a opção vizinha.
#[test]
fn every_onboarding_option_is_clickable_on_its_own_line() {
    for step in [
        OnboardingStep::Environment,
        OnboardingStep::Provider,
        OnboardingStep::Credential,
        OnboardingStep::Consent,
        OnboardingStep::Connection,
    ] {
        let mut app = onboarding_at(step);

        for index in 0..super::screens::onboarding::option_count(&app) {
            app.onboarding_cursor = index;
            let (_, buffer) = render_80x24(&mut app);
            let region = app
                .hit_regions
                .iter()
                .find(|region| region.action == SemanticAction::OnboardingActivate(index))
                .unwrap_or_else(|| panic!("{step:?} precisa de região para a opção {index}"));
            let row = region.area.y as usize;
            let text: String = (0..80)
                .map(|column| buffer[(column, row as u16)].symbol())
                .collect();
            assert!(
                text.contains('›'),
                "{step:?} opção {index} foi registrada na linha {row}, que não é a do cursor: {text:?}"
            );
        }
    }
}

#[test]
fn wrapped_log_lines_expand_the_scroll_limit() {
    let mut app = app();
    app.step = AppStep::Execution;
    app.focus = FocusTarget::ExecutionLogs;
    app.set_exec_logs(
        (0..6)
            .map(|index| format!("L{index}-INICIO{}{index}FIM", "x".repeat(400)))
            .collect(),
    );

    let (bottom, _) = render_80x24(&mut app);
    assert!(
        app.log_total_lines > app.exec_logs().len(),
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

/// A navegação da tela de configurações em 80x24: o campo em edição se anuncia,
/// o cursor só existe na digitação e o rascunho pendente aparece marcado.
#[test]
fn settings_navigation_announces_editing_and_pending_changes_at_80x24() {
    let mut app = app();
    app.show_settings = true;
    app.focus = FocusTarget::SettingsField(SettingsField::BaseUrl);
    app.settings_editing = Some(SettingsField::BaseUrl);
    app.settings_input_base_url = "https://rascunho.local/v1".to_string();

    let snapshot = assert_snapshot(
        &mut app,
        &[
            "Configurar IA",
            "Quem responde",
            "Segurança e limites",
            "Editando Endereço do serviço",
            "nada é descartado",
            "▏",
        ],
    );

    let label_row = snapshot
        .lines()
        .position(|line| line.contains("│Endereço do serviço"))
        .expect("o campo em edição precisa estar visível");
    assert!(
        snapshot
            .lines()
            .nth(label_row + 1)
            .is_some_and(|line| line.starts_with("│•")),
        "o campo alterado fica marcado: {snapshot}"
    );
    assert!(
        app.hit_regions
            .iter()
            .any(|region| region.action == SemanticAction::ClearText),
        "com campo de texto em foco o botão de limpar existe"
    );

    // Fora da digitação a tela volta a dizer o que `enter` faz com o campo, o
    // cursor desaparece e o aviso de rascunho pendente aparece.
    app.settings_editing = None;
    let snapshot = assert_snapshot(&mut app, &["enter edita", "1 alteração não salva"]);
    assert!(
        !snapshot.contains('▏'),
        "sem edição não existe cursor: {snapshot}"
    );

    // A seta horizontal leva o foco para a linha equivalente da outra coluna, e
    // o destaque de foco é o que diz onde as teclas vão agir.
    super::event::dispatch_action(&mut app, SemanticAction::MoveRight);
    let (movido, buffer) = render_80x24(&mut app);
    assert!(movido.contains("Tempo limite"), "{movido}");
    let row = app
        .hit_regions
        .iter()
        .find(|region| region.action == SemanticAction::SelectSettingsField(SettingsField::Timeout))
        .expect("a coluna vizinha precisa de região clicável")
        .area;
    assert_eq!(
        buffer[(row.x, row.y + 1)].bg,
        super::chrome::SURFACE_ACTIVE,
        "o painel do campo focado precisa ficar destacado"
    );
}

#[test]
fn semantic_focus_changes_the_rendered_list_style() {
    let mut app = app();
    app.step = AppStep::ToolSelect;
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

/// Hover no botão: o realce aparece sob o mouse e some quando ele sai, sem
/// depender do foco do teclado.
#[test]
fn hovering_a_button_lights_it_and_leaving_restores_the_cells() {
    let mut app = app();
    let (_, plain_buffer) = render_80x24(&mut app);
    let button = region_of(&app, &SemanticAction::StartScan);
    let plain = styled_cells(&plain_buffer, button);
    assert_eq!(plain_buffer[(button.x, button.y)].bg, ACCENT);

    app.mouse_position = Some((button.x + 1, button.y));
    let (_, hover_buffer) = render_80x24(&mut app);
    assert_ne!(plain, styled_cells(&hover_buffer, button));
    assert_eq!(hover_buffer[(button.x, button.y)].bg, ACCENT_HOVER);

    app.mouse_position = Some((0, 0));
    let (_, restored_buffer) = render_80x24(&mut app);
    assert_eq!(styled_cells(&restored_buffer, button), plain);
}

/// Hover numa linha da lista de Resultados: a linha acende e volta ao normal.
#[test]
fn hovering_a_result_row_lights_the_line() {
    let mut app = app();
    app.step = AppStep::Results;
    app.orchestrator.findings.push(finding());
    let (_, plain_buffer) = render_80x24(&mut app);
    let row = region_of(&app, &SemanticAction::OpenVulnerability(0));
    let plain = styled_cells(&plain_buffer, row);
    assert_eq!(plain_buffer[(row.x, row.y)].bg, SURFACE);

    app.mouse_position = Some((row.x + 2, row.y));
    let (_, hover_buffer) = render_80x24(&mut app);
    assert_ne!(plain, styled_cells(&hover_buffer, row));
    assert_eq!(hover_buffer[(row.x, row.y)].bg, SURFACE_HOVER);

    app.mouse_position = Some((0, 0));
    let (_, restored_buffer) = render_80x24(&mut app);
    assert_eq!(styled_cells(&restored_buffer, row), plain);
}

/// Hover numa linha de Configurações: o campo inteiro (rótulo e valor) acende.
#[test]
fn hovering_a_settings_field_lights_both_lines() {
    let mut app = app();
    app.show_settings = true;
    let (_, plain_buffer) = render_80x24(&mut app);
    let field = region_of(
        &app,
        &SemanticAction::SelectSettingsField(SettingsField::Timeout),
    );
    let plain = styled_cells(&plain_buffer, field);

    app.mouse_position = Some((field.x + 2, field.y));
    let (_, hover_buffer) = render_80x24(&mut app);

    assert_ne!(plain, styled_cells(&hover_buffer, field));
    assert_eq!(hover_buffer[(field.x, field.y)].bg, SURFACE_HOVER);
    assert_eq!(hover_buffer[(field.x, field.y + 1)].bg, SURFACE_HOVER);
}

/// A camada sobreposta é quem recebe o clique: o hover não pode acender o que
/// ficou atrás dela.
#[test]
fn hover_does_not_light_elements_behind_an_overlay() {
    let mut app = app();
    let (_, plain_buffer) = render_80x24(&mut app);
    let button = region_of(&app, &SemanticAction::StartScan);
    let plain = styled_cells(&plain_buffer, button);

    app.show_help_overlay = true;
    app.mouse_position = Some((button.x + 1, button.y));
    let (_, overlay_buffer) = render_80x24(&mut app);

    assert_eq!(styled_cells(&overlay_buffer, button), plain);
}

#[test]
fn the_ai_timeline_highlights_the_action_shown_in_the_detail() {
    let mut app = app();
    app.step = AppStep::Execution;
    app.ai_timeline = vec![
        AiTimelineEntry {
            time: "14:02:10".to_string(),
            origin: AiTimelineOrigin::Ai,
            text: "primeira ação".to_string(),
        },
        AiTimelineEntry {
            time: "14:02:11".to_string(),
            origin: AiTimelineOrigin::Code,
            text: "ferramenta search_code no achado #1".to_string(),
        },
    ];
    app.show_ai_timeline = true;
    app.focus = FocusTarget::AiTimelineClose;

    let (snapshot, buffer) = render_80x24(&mut app);
    let row = snapshot
        .lines()
        .position(|line| line.contains("ferramenta search_code"))
        .expect("a última ação precisa aparecer");
    assert!(
        (0..80).any(|column| buffer[(column, row as u16)].bg == SURFACE_ACTIVE),
        "a linha da ação detalhada precisa ficar destacada\n{snapshot}"
    );
    assert!(
        snapshot
            .lines()
            .nth(row)
            .is_some_and(|line| line.contains("> 14:02:11")),
        "a linha selecionada precisa de um marcador\n{snapshot}"
    );
}
