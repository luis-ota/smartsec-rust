use crate::config::execution_type::ExecutionType;
use crate::config::llm_config::LlmProviderKind;
use crate::domain::Severity;
use crate::tui::commands::command_items;
use crate::tui::interaction::{FocusTarget, SemanticAction};
use crate::tui::state::{AppState, AppStep, RunEvent, SettingsField};
use crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use std::time::Duration;
use tokio::sync::mpsc;

pub fn handle_events(app: &mut AppState) -> std::io::Result<bool> {
    if !event::poll(Duration::from_millis(50))? {
        return Ok(false);
    }

    let should_quit = match event::read()? {
        Event::Key(key) if key.kind == KeyEventKind::Press => handle_key(app, key),
        Event::Mouse(mouse) => handle_mouse(app, mouse),
        Event::Paste(text) => dispatch_action(app, SemanticAction::InsertText(text)),
        Event::Resize(_, _) => handle_resize(app),
        _ => false,
    };
    Ok(should_quit)
}

fn handle_key(app: &mut AppState, key: KeyEvent) -> bool {
    if matches!(key.code, KeyCode::Char('t') | KeyCode::Char('T'))
        && key.modifiers.contains(KeyModifiers::CONTROL)
    {
        app.mouse_capture = !app.mouse_capture;
        return false;
    }

    if matches!(key.code, KeyCode::Char('v') | KeyCode::Char('V'))
        && key.modifiers.contains(KeyModifiers::CONTROL)
    {
        paste_from_clipboard(app);
        return false;
    }

    if matches!(key.code, KeyCode::Char('u') | KeyCode::Char('U'))
        && key.modifiers.contains(KeyModifiers::CONTROL)
        && (app.show_settings || onboarding_takes_secret(app))
    {
        return dispatch_action(app, SemanticAction::ClearText);
    }

    if key.code == KeyCode::F(1) {
        return dispatch_action(app, SemanticAction::OpenHelp);
    }

    if key.code == KeyCode::F(2) {
        return dispatch_action(app, SemanticAction::OpenTraceability);
    }

    // Atalhos de pausa, retomada e cancelamento durante a execução. Fica antes
    // das camadas sobrepostas para que elas continuem capturando as teclas.
    if app.step == AppStep::Execution && !app.has_blocking_layer() {
        match key.code {
            KeyCode::Char('p') | KeyCode::Char('P') => {
                return dispatch_action(app, execution_toggle_pause(app));
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                return dispatch_action(app, SemanticAction::CancelRun);
            }
            KeyCode::Char('i') | KeyCode::Char('I') => {
                return dispatch_action(app, SemanticAction::OpenAiTimeline);
            }
            _ => {}
        }
    }

    if app.show_trace_overlay {
        if key.code == KeyCode::Char('p') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return dispatch_action(app, SemanticAction::OpenCommandPalette);
        }
        return key_action(app, key).is_some_and(|action| dispatch_action(app, action));
    }
    if app.show_report_viewer {
        if key.code == KeyCode::Char('p') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return dispatch_action(app, SemanticAction::OpenCommandPalette);
        }
        return key_action(app, key).is_some_and(|action| dispatch_action(app, action));
    }
    if app.show_ai_timeline {
        if key.code == KeyCode::Char('p') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return dispatch_action(app, SemanticAction::OpenCommandPalette);
        }
        return key_action(app, key).is_some_and(|action| dispatch_action(app, action));
    }
    if app.show_help_overlay {
        if key.code == KeyCode::Char('p') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return dispatch_action(app, SemanticAction::OpenCommandPalette);
        }
        return key_action(app, key).is_some_and(|action| dispatch_action(app, action));
    }
    if app.show_command_palette {
        if key.code == KeyCode::Char('p') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return dispatch_action(app, SemanticAction::Back);
        }
        return key_action(app, key).is_some_and(|action| dispatch_action(app, action));
    }

    if key.code == KeyCode::Char('p') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return dispatch_action(app, SemanticAction::OpenCommandPalette);
    }

    if key.code == KeyCode::Char('?') && !accepts_text(app) {
        return dispatch_action(app, SemanticAction::OpenHelp);
    }

    if key.code == KeyCode::Char('h') && !accepts_text(app) && app.step != AppStep::Execution {
        return dispatch_action(app, SemanticAction::OpenHistory);
    }

    key_action(app, key).is_some_and(|action| dispatch_action(app, action))
}

/// Alterna pausa e retomada na tela de execução; pausa vira `podman pause` e
/// retomada vira `podman unpause` no container real.
fn execution_toggle_pause(app: &AppState) -> SemanticAction {
    if app.exec_paused {
        SemanticAction::ResumeRun
    } else {
        SemanticAction::PauseRun
    }
}

fn key_action(app: &AppState, key: KeyEvent) -> Option<SemanticAction> {
    if app.show_trace_overlay {
        return match key.code {
            KeyCode::Esc | KeyCode::Enter => Some(SemanticAction::Back),
            _ => None,
        };
    }
    if app.show_ai_timeline {
        return match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char(' ') => Some(SemanticAction::Back),
            KeyCode::Up => Some(SemanticAction::MoveUp),
            KeyCode::Down => Some(SemanticAction::MoveDown),
            _ => None,
        };
    }
    if app.show_report_viewer {
        return match key.code {
            KeyCode::Esc | KeyCode::Enter => Some(SemanticAction::Back),
            _ => None,
        };
    }
    if app.show_help_overlay {
        return match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('?') => Some(SemanticAction::Back),
            _ => None,
        };
    }
    if app.show_command_palette {
        return match key.code {
            KeyCode::Esc => Some(SemanticAction::Back),
            KeyCode::Up | KeyCode::BackTab => Some(SemanticAction::MoveUp),
            KeyCode::Down | KeyCode::Tab => Some(SemanticAction::MoveDown),
            KeyCode::Enter | KeyCode::Char(' ') => {
                Some(SemanticAction::ExecuteCommand(app.command_cursor))
            }
            _ => None,
        };
    }
    // Dentro da edição o espaço é texto: `espaço` só aciona o item em foco
    // quando o campo não está aberto para digitação.
    if app.settings_editing.is_some() && key.code == KeyCode::Char(' ') {
        return Some(SemanticAction::InsertText(" ".to_string()));
    }
    let navigation = match key.code {
        KeyCode::Tab => Some(SemanticAction::FocusNext),
        KeyCode::BackTab => Some(SemanticAction::FocusPrevious),
        KeyCode::Up => Some(SemanticAction::MoveUp),
        KeyCode::Down => Some(SemanticAction::MoveDown),
        KeyCode::Left => Some(SemanticAction::MoveLeft),
        KeyCode::Right => Some(SemanticAction::MoveRight),
        KeyCode::Enter | KeyCode::Char(' ') => Some(SemanticAction::Activate),
        KeyCode::Esc => Some(SemanticAction::Back),
        KeyCode::Backspace if app.show_settings || onboarding_takes_secret(app) => {
            Some(SemanticAction::DeleteBackward)
        }
        KeyCode::Backspace if app.show_didactic => Some(SemanticAction::Back),
        KeyCode::Backspace if app.result_detail_vuln.is_some() => Some(SemanticAction::Back),
        KeyCode::Backspace => Some(SemanticAction::DeleteBackward),
        _ => None,
    };
    if navigation.is_some() {
        return navigation;
    }

    match key.code {
        KeyCode::Char(character) if accepts_text(app) => {
            Some(SemanticAction::InsertText(character.to_string()))
        }
        _ => None,
    }
}

fn accepts_text(app: &AppState) -> bool {
    if app.onboarding_open() {
        return crate::config::onboarding::OnboardingStep::Credential
            == app
                .onboarding_step()
                .unwrap_or(crate::config::onboarding::OnboardingStep::Environment)
            && app.focus == FocusTarget::OnboardingList;
    }
    if app.show_settings {
        return app
            .focused_settings_field()
            .is_some_and(SettingsField::is_text);
    }
    app.step == AppStep::Splash && app.focus == FocusTarget::SplashTarget
}

fn paste_from_clipboard(app: &mut AppState) {
    let Ok(text) = arboard::Clipboard::new().and_then(|mut clipboard| clipboard.get_text()) else {
        return;
    };
    dispatch_action(app, SemanticAction::InsertText(text));
}

fn handle_mouse(app: &mut AppState, mouse: MouseEvent) -> bool {
    app.set_mouse_position(Some((mouse.column, mouse.row)));
    let action = match mouse.kind {
        MouseEventKind::ScrollUp => Some(SemanticAction::ScrollUp),
        MouseEventKind::ScrollDown => Some(SemanticAction::ScrollDown),
        MouseEventKind::Down(MouseButton::Left) => app.action_at(mouse.column, mouse.row),
        _ => None,
    };
    action.is_some_and(|action| dispatch_action(app, action))
}

/// Depois de um resize as coordenadas antigas não descrevem mais a tela: sem
/// limpá-las, o hover acenderia um elemento que já mudou de lugar.
fn handle_resize(app: &mut AppState) -> bool {
    app.set_mouse_position(None);
    false
}

pub(crate) fn dispatch_action(app: &mut AppState, action: SemanticAction) -> bool {
    match action {
        SemanticAction::SetFocus(focus) => set_focus(app, focus),
        SemanticAction::FocusNext => move_focus(app, true),
        SemanticAction::FocusPrevious => move_focus(app, false),
        SemanticAction::MoveUp => move_vertical(app, false),
        SemanticAction::MoveDown => move_vertical(app, true),
        SemanticAction::MoveLeft => move_horizontal(app, false),
        SemanticAction::MoveRight => move_horizontal(app, true),
        SemanticAction::Activate => activate_focus(app),
        SemanticAction::Back => return go_back(app),
        SemanticAction::Quit => return true,
        SemanticAction::OpenSettings => {
            let from_onboarding = app.onboarding_open();
            app.settings_return_focus = if from_onboarding {
                FocusTarget::OnboardingList
            } else {
                app.focus
            };
            if !from_onboarding {
                app.reload_api_key_from_keyring();
                app.reset_settings_draft();
            }
            app.settings_editing = None;
            app.show_settings = true;
            app.focus = FocusTarget::SettingsField(app.settings_field);
        }
        SemanticAction::StartScan => start_scan(app),
        SemanticAction::SetMode(mode) => {
            app.set_mode(mode);
            app.focus = match mode {
                ExecutionType::Auto => FocusTarget::SplashAuto,
                ExecutionType::Assisted => FocusTarget::SplashAssisted,
            };
        }
        SemanticAction::ToggleTool(index) => toggle_tool(app, index),
        SemanticAction::RunTools => run_tools(app),
        SemanticAction::ScrollUp => scroll(app, false, 3),
        SemanticAction::ScrollDown => scroll(app, true, 3),
        SemanticAction::PauseRun => pause_execution(app),
        SemanticAction::ResumeRun => resume_execution(app),
        SemanticAction::CancelRun => cancel_execution(app),
        SemanticAction::OpenVulnerability(index) => open_vulnerability(app, index),
        SemanticAction::FilterSeverity(severity) => filter_severity(app, severity),
        SemanticAction::ExportMarkdown => export_markdown(app),
        SemanticAction::ShowDidactic => {
            app.didactic_return_focus = app.focus;
            app.show_didactic = true;
            app.didactic_scroll = 0;
            app.focus = FocusTarget::DidacticContent;
        }
        SemanticAction::ExplainFinding => start_rag_explanation(app),
        SemanticAction::NewScan => new_scan(app),
        SemanticAction::SelectSettingsField(field) => select_settings_field(app, field),
        SemanticAction::SaveSettings => match app.apply_settings() {
            Ok(()) => {
                if app.onboarding_open() {
                    app.cancel_onboarding();
                }
                app.focus = app.settings_return_focus;
            }
            Err(error) => app.settings_error = Some(error),
        },
        SemanticAction::CloseSettings => {
            app.reset_settings_draft();
            app.show_settings = false;
            app.focus = app.settings_return_focus;
        }
        SemanticAction::OpenOnboarding => {
            app.start_onboarding();
            app.focus = FocusTarget::OnboardingList;
        }
        SemanticAction::OnboardingActivate(index) => app.onboarding_activate(index),
        SemanticAction::OnboardingBack => app.onboarding_retreat(),
        SemanticAction::OnboardingQuit => app.cancel_onboarding(),
        SemanticAction::InsertText(text) => insert_text(app, &text),
        SemanticAction::DeleteBackward => delete_backward(app),
        SemanticAction::ClearText => clear_text(app),
        SemanticAction::OpenHelp => open_help(app),
        SemanticAction::OpenHistory => app.open_history(),
        SemanticAction::OpenHistoryRecord(index) => app.open_history_record(index),
        SemanticAction::OpenReportViewer => open_report_viewer(app),
        SemanticAction::OpenTraceability => open_traceability(app),
        SemanticAction::OpenCommandPalette => open_command_palette(app),
        SemanticAction::ExecuteCommand(index) => return execute_command(app, index),
        SemanticAction::OpenAiTimeline => open_ai_timeline(app),
    }
    false
}

fn set_focus(app: &mut AppState, focus: FocusTarget) {
    app.focus = focus;
    // Trocar de campo fecha a digitação: é o que faz `tab` e as setas saírem do
    // campo sem precisar de outra tecla.
    app.settings_editing = None;
    if let FocusTarget::SettingsField(field) = focus {
        app.settings_field = field;
    }
}

/// Dispara a explicação RAG do achado aberto sem bloquear o loop da TUI.
fn start_rag_explanation(app: &mut AppState) {
    let Some(index) = app.result_detail_vuln else {
        return;
    };
    if app.rag_pending.is_some() {
        return;
    }
    let Some(finding) = app.orchestrator.findings.get(index).cloned() else {
        return;
    };

    let llm = app.config.llm.clone();
    let embedding_model = app.config.llm.rag_embedding_model.clone();
    let trail = app.orchestrator.agent_trail();
    let (sender, receiver) = mpsc::channel(8);
    app.rag_receiver = Some(receiver);
    app.rag_pending = Some(index);
    app.rag_results.remove(&index);
    app.push_exec_log(format!("[rag] gerando explicação do achado {}…", index + 1));
    app.rag_task = Some(tokio::spawn(async move {
        let agent = crate::ai::agent::AIAgent::from_config(&llm);
        let model = agent.model.clone();
        let label = agent.configured_provider_label();
        let block_reason = agent.target_data_block_reason();
        let allowed = block_reason.is_none();
        let corpus = crate::cyberrag::corpus::Corpus::shared();
        let ontology = crate::cyberrag::ontology::Ontology::shared();
        let result = crate::cyberrag::service::ExplanationService::new()
            .explain(
                &crate::cyberrag::service::ExplanationContext {
                    provider: agent.provider_handle(),
                    model: &model,
                    provider_label: &label,
                    target_data_allowed: allowed,
                    target_data_block_reason: block_reason.as_deref(),
                    embedding_model: &embedding_model,
                    corpus,
                    ontology,
                    trail: Some(trail.as_ref()),
                },
                index,
                &finding,
            )
            .await;
        let _ = sender
            .send(RunEvent::RagExplanationFinished {
                finding_index: index,
                result: Box::new(result),
            })
            .await;
    }));
}

fn focus_order(app: &AppState) -> Vec<FocusTarget> {
    if app.onboarding_open() {
        return vec![FocusTarget::OnboardingList];
    }
    if app.show_ai_timeline {
        return vec![FocusTarget::AiTimelineClose];
    }
    if app.show_trace_overlay {
        return vec![FocusTarget::TraceClose];
    }
    if app.show_report_viewer {
        return vec![FocusTarget::ReportClose];
    }
    if app.show_help_overlay {
        return vec![FocusTarget::HelpClose];
    }
    if app.show_command_palette {
        return vec![FocusTarget::CommandList];
    }
    if app.show_settings {
        let mut order: Vec<_> = app
            .visible_settings_fields()
            .into_iter()
            .map(FocusTarget::SettingsField)
            .collect();
        // A ordem segue a leitura da tela: descartar está à esquerda de salvar,
        // e o botão primário fica como último passo antes de voltar ao topo.
        order.extend([FocusTarget::SettingsCancel, FocusTarget::SettingsSave]);
        return order;
    }
    if app.show_didactic {
        return vec![FocusTarget::DidacticContent, FocusTarget::DidacticBack];
    }
    match app.step {
        AppStep::Splash => vec![
            FocusTarget::SplashTarget,
            FocusTarget::SplashAuto,
            FocusTarget::SplashAssisted,
            FocusTarget::SplashSettings,
            FocusTarget::SplashStart,
        ],
        AppStep::ToolSelect => vec![
            FocusTarget::ToolList,
            FocusTarget::ToolBack,
            FocusTarget::ToolRun,
        ],
        AppStep::Execution => vec![
            FocusTarget::ExecutionLogs,
            FocusTarget::ExecutionPause,
            FocusTarget::ExecutionCancel,
        ],
        AppStep::Analysis => vec![FocusTarget::AnalysisCancel],
        AppStep::Results if app.result_detail_vuln.is_some() => {
            vec![
                FocusTarget::ResultsDetail,
                FocusTarget::ResultsBack,
                FocusTarget::ResultsExplain,
                FocusTarget::ResultsDidactic,
            ]
        }
        AppStep::Results => vec![
            FocusTarget::ResultsList,
            FocusTarget::ResultsNewScan,
            FocusTarget::ResultsExport,
            FocusTarget::ResultsDidactic,
        ],
        AppStep::History => {
            if app.history_detail.is_some() {
                vec![FocusTarget::HistoryDetail, FocusTarget::HistoryBack]
            } else {
                vec![FocusTarget::HistoryList, FocusTarget::HistoryBack]
            }
        }
    }
}

fn move_focus(app: &mut AppState, forward: bool) {
    let order = focus_order(app);
    let current = order
        .iter()
        .position(|focus| *focus == app.focus)
        .unwrap_or(0);
    let next = if forward {
        (current + 1) % order.len()
    } else {
        current.checked_sub(1).unwrap_or(order.len() - 1)
    };
    set_focus(app, order[next]);
}

fn move_vertical(app: &mut AppState, down: bool) {
    // O painel é modal: as setas rolam a atividade mesmo se a conclusão do
    // scan moveu o foco da tela por baixo.
    if app.show_ai_timeline {
        scroll(app, down, 1);
        return;
    }
    match app.focus {
        FocusTarget::ToolList => move_tool_cursor(app, down),
        FocusTarget::ResultsList if app.result_detail_vuln.is_none() => {
            move_result_cursor(app, down)
        }
        FocusTarget::ResultsDetail => scroll_detail(app, down, 1),
        FocusTarget::HistoryList => move_history_cursor(app, down),
        FocusTarget::HistoryDetail => scroll_history_detail(app, down, 1),
        FocusTarget::ExecutionLogs | FocusTarget::DidacticContent | FocusTarget::ReportClose => {
            scroll(app, down, 1)
        }
        FocusTarget::AiTimelineClose => scroll(app, down, 1),
        FocusTarget::SettingsField(field) if app.show_settings => {
            move_settings_field(app, field, SettingsAxis::Vertical, down)
        }
        FocusTarget::CommandList => move_command_cursor(app, down),
        FocusTarget::OnboardingList => move_onboarding_cursor(app, down),
        _ => move_focus(app, down),
    }
}

fn move_onboarding_cursor(app: &mut AppState, down: bool) {
    let count = crate::tui::screens::onboarding::option_count(app);
    if count == 0 {
        app.onboarding_cursor = 0;
        return;
    }
    app.onboarding_cursor = if down {
        (app.onboarding_cursor + 1) % count
    } else {
        app.onboarding_cursor.checked_sub(1).unwrap_or(count - 1)
    };
}

/// Setas navegam (↑/↓ na coluna, ←/→ entre colunas); enter/espaço trocam o valor.
fn move_horizontal(app: &mut AppState, right: bool) {
    match app.focus {
        FocusTarget::SettingsField(field) if app.show_settings => {
            move_settings_field(app, field, SettingsAxis::Horizontal, right);
        }
        _ => move_focus(app, right),
    }
}

enum SettingsAxis {
    Vertical,
    Horizontal,
}

fn move_settings_field(
    app: &mut AppState,
    field: SettingsField,
    axis: SettingsAxis,
    forward: bool,
) {
    if !app.settings_two_columns {
        move_focus(app, forward);
        return;
    }
    let [primary, reliability] = app.settings_columns();
    let columns = [primary, reliability];
    let Some(column) = columns.iter().position(|fields| fields.contains(&field)) else {
        return;
    };
    let row = columns[column]
        .iter()
        .position(|candidate| *candidate == field)
        .unwrap_or(0);
    let target = match axis {
        SettingsAxis::Vertical => {
            let fields = &columns[column];
            let length = fields.len();
            let next = if forward {
                (row + 1) % length
            } else {
                row.checked_sub(1).unwrap_or(length - 1)
            };
            fields[next]
        }
        SettingsAxis::Horizontal => {
            let fields = &columns[1 - column];
            let Some(last) = fields.len().checked_sub(1) else {
                return;
            };
            fields[row.min(last)]
        }
    };
    set_focus(app, FocusTarget::SettingsField(target));
}

fn activate_focus(app: &mut AppState) {
    let action = match app.focus {
        FocusTarget::SplashTarget | FocusTarget::SplashStart => SemanticAction::StartScan,
        FocusTarget::SplashAuto => SemanticAction::SetMode(ExecutionType::Auto),
        FocusTarget::SplashAssisted => SemanticAction::SetMode(ExecutionType::Assisted),
        FocusTarget::SplashSettings => SemanticAction::OpenSettings,
        FocusTarget::ToolList => SemanticAction::ToggleTool(app.tool_cursor),
        FocusTarget::ToolBack
        | FocusTarget::AnalysisCancel
        | FocusTarget::ResultsBack
        | FocusTarget::DidacticBack
        | FocusTarget::HistoryBack => SemanticAction::Back,
        FocusTarget::ToolRun => SemanticAction::RunTools,
        FocusTarget::ExecutionPause if !app.exec_cancelled => execution_toggle_pause(app),
        FocusTarget::ExecutionPause => return,
        FocusTarget::ExecutionCancel if !app.exec_cancelled => SemanticAction::CancelRun,
        FocusTarget::ExecutionCancel => return,
        FocusTarget::ExecutionLogs | FocusTarget::DidacticContent | FocusTarget::HistoryDetail => {
            return
        }
        FocusTarget::ResultsList => SemanticAction::OpenVulnerability(app.result_cursor),
        FocusTarget::HistoryList => SemanticAction::OpenHistoryRecord(app.history_cursor),
        FocusTarget::ResultsDetail => return,
        FocusTarget::ResultsNewScan => SemanticAction::NewScan,
        FocusTarget::ResultsExport => SemanticAction::ExportMarkdown,
        FocusTarget::ResultsExplain => SemanticAction::ExplainFinding,
        FocusTarget::ResultsDidactic => SemanticAction::ShowDidactic,
        FocusTarget::SettingsField(field) => {
            activate_settings_field(app, field);
            return;
        }
        FocusTarget::SettingsSave => SemanticAction::SaveSettings,
        FocusTarget::SettingsCancel => SemanticAction::CloseSettings,
        FocusTarget::OnboardingList => {
            if crate::config::onboarding::OnboardingStep::Credential
                == app
                    .onboarding_step()
                    .unwrap_or(crate::config::onboarding::OnboardingStep::Environment)
            {
                SemanticAction::OnboardingActivate(0)
            } else {
                SemanticAction::OnboardingActivate(app.onboarding_cursor)
            }
        }
        FocusTarget::HelpClose => SemanticAction::Back,
        FocusTarget::ReportClose => SemanticAction::Back,
        FocusTarget::TraceClose => SemanticAction::Back,
        FocusTarget::CommandList => SemanticAction::ExecuteCommand(app.command_cursor),
        FocusTarget::AiTimelineClose => SemanticAction::Back,
    };
    dispatch_action(app, action);
}

fn go_back(app: &mut AppState) -> bool {
    if app.onboarding_open() {
        app.cancel_onboarding();
        return false;
    }
    if app.show_ai_timeline {
        app.show_ai_timeline = false;
        app.focus = app.overlay_return_focus;
        return false;
    }
    if app.show_trace_overlay {
        app.show_trace_overlay = false;
        app.focus = app.overlay_return_focus;
        return false;
    }
    if app.show_report_viewer {
        app.show_report_viewer = false;
        app.focus = app.overlay_return_focus;
        return false;
    }
    if app.show_help_overlay {
        app.show_help_overlay = false;
        app.focus = app.overlay_return_focus;
        return false;
    }
    if app.show_command_palette {
        app.show_command_palette = false;
        app.focus = app.overlay_return_focus;
        return false;
    }
    if app.show_settings {
        // Sair da digitação não descarta o rascunho: o operador que apertou `esc`
        // para fechar o campo não perde o que digitou sem aviso.
        if app.settings_editing.take().is_some() {
            return false;
        }
        app.reset_settings_draft();
        app.show_settings = false;
        app.focus = app.settings_return_focus;
        return false;
    }
    if app.show_didactic {
        app.show_didactic = false;
        app.didactic_scroll = 0;
        app.focus = app.didactic_return_focus;
        return false;
    }
    if app.result_detail_vuln.is_some() {
        app.result_detail_vuln = None;
        app.detail_scroll = 0;
        app.detail_max_scroll = 0;
        app.focus = FocusTarget::ResultsList;
        return false;
    }
    match app.step {
        AppStep::Splash => return true,
        AppStep::ToolSelect => new_scan(app),
        AppStep::Execution => {
            app.cancel_run();
            app.step = AppStep::ToolSelect;
            app.focus = FocusTarget::ToolList;
        }
        AppStep::Analysis => {
            app.cancel_run();
            app.step = AppStep::ToolSelect;
            app.focus = FocusTarget::ToolList;
        }
        AppStep::Results => new_scan(app),
        AppStep::History => {
            if app.history_detail.is_some() {
                app.history_detail = None;
                app.history_detail_scroll = 0;
                app.history_detail_max_scroll = 0;
                app.focus = FocusTarget::HistoryList;
            } else {
                app.step = app.history_return_step;
                app.focus = if app.step == AppStep::Results {
                    FocusTarget::ResultsList
                } else {
                    FocusTarget::SplashTarget
                };
            }
        }
    }
    false
}

fn start_scan(app: &mut AppState) {
    app.config.target_url = app.config.target_url.trim().to_string();
    if let Err(error) = app.config.validate_target() {
        app.record_run_issue(crate::tui::state::RunIssueScope::Validation, error);
        app.focus = FocusTarget::SplashTarget;
        return;
    }
    app.clear_run_issues();
    app.step = AppStep::ToolSelect;
    app.focus = FocusTarget::ToolList;
}

fn run_tools(app: &mut AppState) {
    if app.step == AppStep::ToolSelect && app.tools.iter().any(|tool| tool.selected) {
        app.start_selected_tools();
    }
}

fn toggle_tool(app: &mut AppState, index: usize) {
    if app.step == AppStep::ToolSelect {
        if let Some(tool) = app.tools.get_mut(index) {
            tool.selected = !tool.selected;
            app.tool_cursor = index;
            app.focus = FocusTarget::ToolList;
            ensure_tool_visible(app);
        }
    }
}

fn move_tool_cursor(app: &mut AppState, down: bool) {
    if app.tools.is_empty() {
        app.tool_cursor = 0;
        app.tool_scroll = 0;
        return;
    }
    if down {
        app.tool_cursor = (app.tool_cursor + 1).min(app.tools.len() - 1);
    } else {
        app.tool_cursor = app.tool_cursor.saturating_sub(1);
    }
    ensure_tool_visible(app);
}

fn ensure_tool_visible(app: &mut AppState) {
    let visible = app.tool_visible_height.max(1);
    if app.tool_cursor < app.tool_scroll {
        app.tool_scroll = app.tool_cursor;
    } else if app.tool_cursor >= app.tool_scroll.saturating_add(visible) {
        app.tool_scroll = app.tool_cursor.saturating_sub(visible - 1);
    }
}

fn move_result_cursor(app: &mut AppState, down: bool) {
    let visible = app.visible_vulnerability_indices();
    if visible.is_empty() {
        app.result_cursor = 0;
        app.result_scroll = 0;
        return;
    }
    let position = visible
        .iter()
        .position(|index| *index == app.result_cursor)
        .unwrap_or(0);
    let next = if down {
        (position + 1).min(visible.len() - 1)
    } else {
        position.saturating_sub(1)
    };
    app.result_cursor = visible[next];
}

fn open_vulnerability(app: &mut AppState, index: usize) {
    if index < app.vulnerabilities().len() {
        app.result_cursor = index;
        app.result_detail_vuln = Some(index);
        app.detail_scroll = 0;
        app.detail_max_scroll = 0;
        app.focus = FocusTarget::ResultsDetail;
    }
}

fn filter_severity(app: &mut AppState, severity: Severity) {
    app.severity_filter = if app.severity_filter == Some(severity) {
        None
    } else {
        Some(severity)
    };
    app.result_cursor = app
        .visible_vulnerability_indices()
        .first()
        .copied()
        .unwrap_or(0);
    app.result_scroll = 0;
}

fn scroll(app: &mut AppState, down: bool, amount: usize) {
    if app.onboarding_open() {
        for _ in 0..amount {
            move_onboarding_cursor(app, down);
        }
        return;
    }
    if app.show_trace_overlay {
        return;
    }
    if app.show_ai_timeline {
        let max_scroll = app.ai_timeline_max_scroll;
        app.ai_timeline_scroll = if down {
            app.ai_timeline_scroll
                .saturating_add(amount)
                .min(max_scroll)
        } else {
            app.ai_timeline_scroll.saturating_sub(amount)
        };
        app.ai_timeline_follow = app.ai_timeline_scroll >= max_scroll;
        return;
    }
    if app.show_report_viewer {
        app.report_scroll = if down {
            app.report_scroll
                .saturating_add(amount)
                .min(app.report_max_scroll)
        } else {
            app.report_scroll.saturating_sub(amount)
        };
        return;
    }
    if app.show_help_overlay {
        return;
    }
    if app.show_command_palette {
        move_command_cursor(app, down);
        return;
    }
    if app.show_settings {
        for _ in 0..amount {
            move_focus(app, down);
        }
        return;
    }
    if app.show_didactic {
        app.didactic_scroll = if down {
            app.didactic_scroll
                .saturating_add(amount)
                .min(app.didactic_max_scroll)
        } else {
            app.didactic_scroll.saturating_sub(amount)
        };
        return;
    }
    match app.step {
        AppStep::ToolSelect => {
            for _ in 0..amount {
                move_tool_cursor(app, down);
            }
        }
        AppStep::History => {
            if app.history_detail.is_some() {
                scroll_history_detail(app, down, amount);
            } else {
                for _ in 0..amount {
                    move_history_cursor(app, down);
                }
                app.focus = FocusTarget::HistoryList;
            }
        }
        AppStep::Execution => {
            app.focus = FocusTarget::ExecutionLogs;
            let max_scroll = app.log_max_scroll();
            app.log_scroll = if down {
                app.log_scroll.saturating_add(amount).min(max_scroll)
            } else {
                app.log_scroll.saturating_sub(amount)
            };
            app.log_follow = app.log_scroll >= max_scroll;
        }
        AppStep::Results => {
            if app.result_detail_vuln.is_some() {
                scroll_detail(app, down, amount);
            } else {
                for _ in 0..amount {
                    move_result_cursor(app, down);
                }
                app.focus = FocusTarget::ResultsList;
            }
        }
        _ => {}
    }
}

fn scroll_detail(app: &mut AppState, down: bool, amount: usize) {
    app.detail_scroll = if down {
        app.detail_scroll
            .saturating_add(amount)
            .min(app.detail_max_scroll)
    } else {
        app.detail_scroll.saturating_sub(amount)
    };
}

fn move_history_cursor(app: &mut AppState, down: bool) {
    let count = app.history.records.len();
    if count == 0 {
        app.history_cursor = 0;
        app.history_scroll = 0;
        return;
    }
    if down {
        app.history_cursor = (app.history_cursor + 1).min(count - 1);
    } else {
        app.history_cursor = app.history_cursor.saturating_sub(1);
    }
}

fn scroll_history_detail(app: &mut AppState, down: bool, amount: usize) {
    app.history_detail_scroll = if down {
        app.history_detail_scroll
            .saturating_add(amount)
            .min(app.history_detail_max_scroll)
    } else {
        app.history_detail_scroll.saturating_sub(amount)
    };
}

fn open_help(app: &mut AppState) {
    if app.show_help_overlay {
        return;
    }
    if !app.show_command_palette && !app.show_ai_timeline {
        app.overlay_return_focus = app.focus;
    }
    app.show_command_palette = false;
    app.show_report_viewer = false;
    app.show_trace_overlay = false;
    app.show_ai_timeline = false;
    app.show_help_overlay = true;
    app.focus = FocusTarget::HelpClose;
}

fn open_traceability(app: &mut AppState) {
    if app.show_trace_overlay {
        return;
    }
    if !app.show_help_overlay
        && !app.show_command_palette
        && !app.show_report_viewer
        && !app.show_ai_timeline
    {
        app.overlay_return_focus = app.focus;
    }
    app.show_help_overlay = false;
    app.show_command_palette = false;
    app.show_report_viewer = false;
    app.show_ai_timeline = false;
    app.show_trace_overlay = true;
    app.focus = FocusTarget::TraceClose;
}

fn open_report_viewer(app: &mut AppState) {
    if app.step != AppStep::Results || app.exported_report_path.is_none() {
        return;
    }
    app.overlay_return_focus = app.focus;
    app.show_help_overlay = false;
    app.show_command_palette = false;
    app.show_trace_overlay = false;
    app.report_content = app
        .exported_report_path
        .as_ref()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .unwrap_or_else(|| "Não foi possível ler o relatório exportado.".to_string());
    app.report_scroll = 0;
    app.report_max_scroll = 0;
    app.show_report_viewer = true;
    app.focus = FocusTarget::ReportClose;
}

fn open_command_palette(app: &mut AppState) {
    if !app.show_help_overlay && !app.show_ai_timeline {
        app.overlay_return_focus = app.focus;
    }
    app.show_help_overlay = false;
    app.show_report_viewer = false;
    app.show_trace_overlay = false;
    app.show_ai_timeline = false;
    app.show_command_palette = true;
    app.command_cursor = 0;
    app.focus = FocusTarget::CommandList;
}

/// Abre o painel ao vivo da atividade da IA. Fechar o painel não toca o canal
/// de controle: a varredura continua exatamente como estava.
fn open_ai_timeline(app: &mut AppState) {
    if app.show_ai_timeline {
        return;
    }
    if !app.show_help_overlay && !app.show_command_palette && !app.show_report_viewer {
        app.overlay_return_focus = app.focus;
    }
    app.show_help_overlay = false;
    app.show_command_palette = false;
    app.show_report_viewer = false;
    app.show_trace_overlay = false;
    app.show_ai_timeline = true;
    app.focus = FocusTarget::AiTimelineClose;
}

fn move_command_cursor(app: &mut AppState, down: bool) {
    let count = command_items(app).len();
    if count == 0 {
        app.command_cursor = 0;
    } else if down {
        app.command_cursor = (app.command_cursor + 1) % count;
    } else {
        app.command_cursor = app.command_cursor.checked_sub(1).unwrap_or(count - 1);
    }
}

fn execute_command(app: &mut AppState, index: usize) -> bool {
    let Some(item) = command_items(app).get(index).cloned() else {
        return false;
    };
    if !item.enabled {
        return false;
    }
    app.show_command_palette = false;
    app.focus = app.overlay_return_focus;
    dispatch_action(app, item.action)
}

fn pause_execution(app: &mut AppState) {
    if app.step == AppStep::Execution {
        app.pause_run();
    }
}

fn resume_execution(app: &mut AppState) {
    if app.step == AppStep::Execution {
        app.resume_run();
    }
}

fn cancel_execution(app: &mut AppState) {
    if matches!(app.step, AppStep::Execution | AppStep::Analysis) {
        app.cancel_run();
        app.step = AppStep::ToolSelect;
        app.focus = FocusTarget::ToolList;
    }
}

/// Exporta o relatório nos caminhos pedidos por `output_file`/`output_dir`.
///
/// Usa `report::resolve_report_path`, o mesmo do modo headless, para que os dois
/// modos gravem onde o usuário pediu.
fn export_markdown(app: &mut AppState) {
    if app.step == AppStep::Results {
        let report = app.export_md();
        let exported = (|| -> anyhow::Result<(std::path::PathBuf, std::path::PathBuf)> {
            let markdown = crate::report::resolve_report_path(&app.config)?;
            let pdf = crate::report::resolve_pdf_path(&markdown);
            crate::report::ReportGenerator::export_to_markdown(
                &report,
                &markdown.to_string_lossy(),
            )?;
            crate::report::ReportGenerator::export_to_pdf(&report, &pdf.to_string_lossy())?;
            Ok((markdown, pdf))
        })();
        match exported {
            Ok((markdown, pdf)) => {
                app.md_exported = true;
                app.exported_pdf_path = Some(pdf);
                let absolute = std::env::current_dir()
                    .map(|dir| dir.join(&markdown))
                    .unwrap_or(markdown);
                app.exported_report_path = Some(absolute);
            }
            Err(error) => {
                app.md_exported = false;
                app.exported_report_path = None;
                app.record_run_issue(
                    crate::tui::state::RunIssueScope::Export,
                    format!("Falha ao exportar relatório: {error}"),
                );
                app.exported_pdf_path = None;
                app.run_error = Some(format!("Falha ao exportar relatório: {error:#}"));
            }
        }
        app.focus = FocusTarget::ResultsExport;
    }
}

fn new_scan(app: &mut AppState) {
    app.step = AppStep::Splash;
    app.result_detail_vuln = None;
    app.severity_filter = None;
    app.result_cursor = 0;
    app.result_scroll = 0;
    app.run_started_at = None;
    app.detail_scroll = 0;
    app.detail_max_scroll = 0;
    app.show_didactic = false;
    app.md_exported = false;
    app.exported_report_path = None;
    app.exported_pdf_path = None;
    app.show_report_viewer = false;
    app.report_content = String::new();
    app.report_scroll = 0;
    app.report_max_scroll = 0;
    app.focus = FocusTarget::SplashTarget;
}

fn select_settings_field(app: &mut AppState, field: SettingsField) {
    app.settings_field = field;
    app.focus = FocusTarget::SettingsField(field);
    // O clique abre o campo para digitação: entrar e sair a cada clique tornaria
    // o alvo dependente do estado anterior.
    if field.is_text() {
        app.settings_editing = Some(field);
        app.settings_error = None;
        return;
    }
    activate_settings_field(app, field);
}

fn activate_settings_field(app: &mut AppState, field: SettingsField) {
    app.settings_error = None;
    match field {
        SettingsField::Provider => {
            app.settings_provider_idx =
                (app.settings_provider_idx + 1) % LlmProviderKind::all_labels().len();
            sync_provider_defaults(app);
        }
        SettingsField::RemoteConsent => app.settings_remote_consent = !app.settings_remote_consent,
        SettingsField::FallbackEnabled => {
            app.settings_fallback_enabled = !app.settings_fallback_enabled
        }
        // `enter` abre e fecha a digitação do próprio campo.
        _ if field.is_text() => {
            app.settings_editing = (app.settings_editing != Some(field)).then_some(field);
        }
        _ => {}
    }
}

fn sync_provider_defaults(app: &mut AppState) {
    let labels = LlmProviderKind::all_labels();
    let provider = LlmProviderKind::from_label(labels[app.settings_provider_idx]);
    app.settings_input_base_url = provider.default_base_url().to_string();
    app.settings_input_model = provider.default_model().to_string();
    app.settings_error = None;
}

fn insert_text(app: &mut AppState, text: &str) {
    if !accepts_text(app) {
        return;
    }
    // Digitar abre a edição: o operador não precisa de uma tecla só para isso,
    // e o estado visual passa a dizer a verdade sobre o que o `esc` faz.
    if app.show_settings && !app.onboarding_open() {
        app.settings_editing = app.focused_settings_field();
    }
    if app.onboarding_open() {
        if !app.settings_api_key_touched {
            app.settings_input_api_key.clear();
            app.settings_api_key_touched = true;
        }
        app.settings_input_api_key.push_str(text);
        return;
    }
    match app.focus {
        FocusTarget::SplashTarget => {
            app.config.target_url.push_str(text);
            app.clear_run_issues();
        }
        FocusTarget::SettingsField(SettingsField::BaseUrl) => {
            app.settings_input_base_url.push_str(text)
        }
        FocusTarget::SettingsField(SettingsField::ApiKey) => {
            if !app.settings_api_key_touched {
                app.settings_input_api_key.clear();
                app.settings_api_key_touched = true;
            }
            app.settings_input_api_key.push_str(text)
        }
        FocusTarget::SettingsField(SettingsField::Model) => app.settings_input_model.push_str(text),
        FocusTarget::SettingsField(SettingsField::Timeout)
            if text.chars().all(|character| character.is_ascii_digit()) =>
        {
            app.settings_input_timeout.push_str(text)
        }
        FocusTarget::SettingsField(SettingsField::Retries)
            if text.chars().all(|character| character.is_ascii_digit()) =>
        {
            app.settings_input_retries.push_str(text)
        }
        FocusTarget::SettingsField(SettingsField::FallbackBaseUrl) => {
            app.settings_input_fallback_base_url.push_str(text)
        }
        FocusTarget::SettingsField(SettingsField::FallbackModel) => {
            app.settings_input_fallback_model.push_str(text)
        }
        FocusTarget::SettingsField(SettingsField::ProjectDir) => {
            app.settings_input_project_dir.push_str(text)
        }
        _ => {}
    }
    if app.show_settings {
        app.settings_error = None;
    }
}

fn onboarding_takes_secret(app: &AppState) -> bool {
    app.onboarding_open()
        && crate::config::onboarding::OnboardingStep::Credential
            == app
                .onboarding_step()
                .unwrap_or(crate::config::onboarding::OnboardingStep::Environment)
}

fn delete_backward(app: &mut AppState) {
    if onboarding_takes_secret(app) {
        if !app.settings_api_key_touched {
            app.settings_input_api_key.clear();
            app.settings_api_key_touched = true;
        }
        app.settings_input_api_key.pop();
        return;
    }
    if app.show_settings {
        app.settings_editing = app.focused_settings_field();
    }
    match app.focus {
        FocusTarget::SplashTarget => {
            app.config.target_url.pop();
            app.clear_run_issues();
        }
        FocusTarget::SettingsField(SettingsField::BaseUrl) => {
            app.settings_input_base_url.pop();
        }
        FocusTarget::SettingsField(SettingsField::ApiKey) => {
            if !app.settings_api_key_touched {
                app.settings_input_api_key.clear();
                app.settings_api_key_touched = true;
            }
            app.settings_input_api_key.pop();
        }
        FocusTarget::SettingsField(SettingsField::Model) => {
            app.settings_input_model.pop();
        }
        FocusTarget::SettingsField(SettingsField::Timeout) => {
            app.settings_input_timeout.pop();
        }
        FocusTarget::SettingsField(SettingsField::Retries) => {
            app.settings_input_retries.pop();
        }
        FocusTarget::SettingsField(SettingsField::FallbackBaseUrl) => {
            app.settings_input_fallback_base_url.pop();
        }
        FocusTarget::SettingsField(SettingsField::FallbackModel) => {
            app.settings_input_fallback_model.pop();
        }
        FocusTarget::SettingsField(SettingsField::ProjectDir) => {
            app.settings_input_project_dir.pop();
        }
        _ => {}
    }
    if app.show_settings {
        app.settings_error = None;
    }
}

fn clear_text(app: &mut AppState) {
    if onboarding_takes_secret(app) {
        app.settings_input_api_key.clear();
        app.settings_api_key_touched = true;
        return;
    }
    if app.show_settings {
        app.settings_editing = app.focused_settings_field();
    }
    match app.focus {
        FocusTarget::SettingsField(SettingsField::BaseUrl) => app.settings_input_base_url.clear(),
        FocusTarget::SettingsField(SettingsField::ApiKey) => {
            app.settings_input_api_key.clear();
            app.settings_api_key_touched = true;
        }
        FocusTarget::SettingsField(SettingsField::Model) => app.settings_input_model.clear(),
        FocusTarget::SettingsField(SettingsField::Timeout) => app.settings_input_timeout.clear(),
        FocusTarget::SettingsField(SettingsField::Retries) => app.settings_input_retries.clear(),
        FocusTarget::SettingsField(SettingsField::FallbackBaseUrl) => {
            app.settings_input_fallback_base_url.clear()
        }
        FocusTarget::SettingsField(SettingsField::FallbackModel) => {
            app.settings_input_fallback_model.clear()
        }
        // Limpar o diretório não significa "não analisar": o valor vazio
        // significa diretório atual, e é esse o padrão do agente de código.
        FocusTarget::SettingsField(SettingsField::ProjectDir) => {
            app.settings_input_project_dir.clear()
        }
        _ => return,
    }
    app.settings_error = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Configuration;
    use crate::tui;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    /// A IA remota fica configurada porque o padrão do projeto é API, e um
    /// `Configuration::default()` sem provedor faria o `validate()` recusar antes
    /// do erro que o teste quer observar.
    fn app() -> AppState {
        AppState::new(Configuration {
            llm: crate::config::llm_config::remote_de_teste(),
            ..Configuration::default()
        })
        .expect("configuração de teste válida")
    }

    /// `AppState` com as duas saídas do assistente apontadas para a memória:
    /// um teste de evento não pode gravar no disco do usuário nem no keyring.
    fn app_with_offline_onboarding() -> AppState {
        let mut app = app();
        app.set_onboarding_probe(std::sync::Arc::new(
            crate::config::environment::FixedOnboardingProbe {
                report: crate::config::environment::EnvironmentReport {
                    local_llm: None,
                    keyring: crate::config::environment::KeyringAvailability::Available,
                    podman: crate::config::environment::PodmanMode::Rootless,
                },
                check: crate::config::environment::ConnectionCheck::NotRun,
            },
        ));
        app.set_onboarding_persister(Box::new(RefusingPersister));
        app
    }

    /// Falha de propósito: prova que nenhum teste de evento chegou a gravar.
    struct RefusingPersister;

    impl crate::config::onboarding::OnboardingPersister for RefusingPersister {
        fn save(&self, _config: &Configuration) -> Result<(), String> {
            Err("gravação real não deve acontecer em teste de evento".to_string())
        }
    }

    fn finding() -> crate::domain::vulnerability::Vulnerability {
        crate::domain::vulnerability::Vulnerability {
            title: "Achado de teste".to_string(),
            severity: crate::domain::Severity::High,
            description: "Descrição técnica".to_string(),
            tool: "Nuclei".to_string(),
            recommendation: "Aplique a correção".to_string(),
            didactic: "Explicação didática".to_string(),
            source: crate::domain::vulnerability::FindingSource::Real,
            target: "https://exemplo.local".to_string(),
            evidence: "evidência".to_string(),
            detected_at: "2026-09-04T14:00:00Z".to_string(),
            origins: Vec::new(),
            enrichment: None,
            severity_conflict: None,
            ..Default::default()
        }
    }

    fn press(app: &mut AppState, code: KeyCode) -> bool {
        handle_key(app, KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn click_action(app: &mut AppState, action: &SemanticAction) -> bool {
        let region = app
            .hit_regions
            .iter()
            .find(|region| &region.action == action)
            .expect("a ação deve possuir uma região clicável");
        handle_mouse(
            app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: region.area.x,
                row: region.area.y,
                modifiers: KeyModifiers::NONE,
            },
        )
    }

    fn render_app(app: &mut AppState, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| tui::render(app, frame)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn keyboard_and_mouse_start_scan_are_equivalent() {
        let mut keyboard = app();
        keyboard.config.target_url = "https://exemplo.local".to_string();
        let mut mouse = app();
        mouse.config.target_url = "https://exemplo.local".to_string();
        render_app(&mut mouse, 80, 24);

        assert!(!press(&mut keyboard, KeyCode::Enter));
        assert!(!click_action(&mut mouse, &SemanticAction::StartScan));

        assert_eq!(keyboard.step, mouse.step);
        assert_eq!(keyboard.focus, mouse.focus);
        assert_eq!(keyboard.config.target_url, mouse.config.target_url);
    }

    #[test]
    fn invalid_target_stays_on_splash_and_shows_the_error() {
        let mut app = app();
        app.config.target_url = "ftp://exemplo.local".to_string();

        press(&mut app, KeyCode::Enter);

        assert_eq!(app.step, AppStep::Splash);
        assert!(app.run_error.as_deref().unwrap().contains("HTTP ou HTTPS"));
    }

    #[test]
    fn keyboard_and_mouse_toggle_the_same_tool() {
        let mut keyboard = app();
        keyboard.step = AppStep::ToolSelect;
        keyboard.focus = FocusTarget::ToolList;
        keyboard.tool_cursor = 1;
        let mut mouse = app();
        mouse.step = AppStep::ToolSelect;
        mouse.tool_cursor = 1;
        render_app(&mut mouse, 80, 16);

        press(&mut keyboard, KeyCode::Char(' '));
        click_action(&mut mouse, &SemanticAction::ToggleTool(1));

        let keyboard_selection: Vec<_> = keyboard.tools.iter().map(|tool| tool.selected).collect();
        let mouse_selection: Vec<_> = mouse.tools.iter().map(|tool| tool.selected).collect();
        assert_eq!(keyboard_selection, mouse_selection);
        assert_eq!(mouse.tool_cursor, 1);
    }

    #[test]
    fn settings_toggle_has_keyboard_and_mouse_parity() {
        let mut keyboard = app();
        keyboard.show_settings = true;
        keyboard.settings_provider_idx = 2;
        keyboard.settings_input_base_url = "https://api.openai.com/v1".to_string();
        keyboard.settings_field = SettingsField::RemoteConsent;
        keyboard.focus = FocusTarget::SettingsField(SettingsField::RemoteConsent);
        let mut mouse = app();
        mouse.show_settings = true;
        mouse.settings_provider_idx = 2;
        mouse.settings_input_base_url = "https://api.openai.com/v1".to_string();
        render_app(&mut mouse, 80, 24);

        press(&mut keyboard, KeyCode::Enter);
        click_action(
            &mut mouse,
            &SemanticAction::SelectSettingsField(SettingsField::RemoteConsent),
        );

        assert_eq!(
            keyboard.settings_remote_consent,
            mouse.settings_remote_consent
        );
        assert_eq!(keyboard.focus, mouse.focus);
    }

    #[test]
    fn tab_and_backtab_cycle_focus_in_both_directions() {
        let mut app = app();
        assert_eq!(app.focus, FocusTarget::SplashTarget);

        press(&mut app, KeyCode::Tab);
        assert_eq!(app.focus, FocusTarget::SplashAuto);
        press(&mut app, KeyCode::BackTab);
        assert_eq!(app.focus, FocusTarget::SplashTarget);
        press(&mut app, KeyCode::BackTab);
        assert_eq!(app.focus, FocusTarget::SplashStart);
    }

    #[test]
    fn escape_closes_overlays_then_goes_back_and_only_quits_on_splash() {
        let mut app = app();
        app.step = AppStep::Results;
        app.focus = FocusTarget::ResultsExport;
        dispatch_action(&mut app, SemanticAction::OpenSettings);

        assert!(!press(&mut app, KeyCode::Esc));
        assert!(!app.show_settings);
        assert_eq!(app.step, AppStep::Results);
        assert_eq!(app.focus, FocusTarget::ResultsExport);

        app.result_detail_vuln = Some(0);
        app.focus = FocusTarget::ResultsBack;
        dispatch_action(&mut app, SemanticAction::ShowDidactic);
        assert!(!press(&mut app, KeyCode::Esc));
        assert!(!app.show_didactic);
        assert!(app.result_detail_vuln.is_some());
        assert!(!press(&mut app, KeyCode::Esc));
        assert!(app.result_detail_vuln.is_none());
        assert_eq!(app.step, AppStep::Results);

        assert!(!press(&mut app, KeyCode::Esc));
        assert_eq!(app.step, AppStep::Splash);
        assert!(press(&mut app, KeyCode::Esc));
    }

    #[test]
    fn nested_help_over_didactic_restores_both_focus_layers() {
        let mut app = app();
        app.step = AppStep::Results;
        app.focus = FocusTarget::ResultsExport;
        dispatch_action(&mut app, SemanticAction::ShowDidactic);
        assert_eq!(app.focus, FocusTarget::DidacticContent);

        dispatch_action(&mut app, SemanticAction::OpenHelp);
        assert!(app.show_help_overlay);
        assert!(!press(&mut app, KeyCode::Esc));
        assert!(!app.show_help_overlay);
        assert!(app.show_didactic);
        assert_eq!(app.focus, FocusTarget::DidacticContent);

        assert!(!press(&mut app, KeyCode::Esc));
        assert!(!app.show_didactic);
        assert_eq!(app.focus, FocusTarget::ResultsExport);
    }

    #[test]
    fn report_viewer_opens_closes_and_restores_focus() {
        let path = std::env::temp_dir().join("smartsec-report-viewer-test.md");
        std::fs::write(&path, "# Relatório de teste\nconteúdo\n").unwrap();

        let mut app = app();
        app.step = AppStep::Results;
        app.focus = FocusTarget::ResultsExport;
        dispatch_action(&mut app, SemanticAction::OpenReportViewer);
        assert!(!app.show_report_viewer, "sem path exportado não abre");

        app.step = AppStep::Splash;
        app.md_exported = true;
        app.exported_report_path = Some(path.clone());
        dispatch_action(&mut app, SemanticAction::OpenReportViewer);
        assert!(!app.show_report_viewer, "fora dos resultados não abre");

        app.step = AppStep::Results;
        app.focus = FocusTarget::ResultsExport;
        dispatch_action(&mut app, SemanticAction::OpenReportViewer);
        assert!(app.show_report_viewer);
        assert_eq!(app.focus, FocusTarget::ReportClose);
        assert!(app.report_content.contains("Relatório de teste"));

        assert!(!press(&mut app, KeyCode::Esc));
        assert!(!app.show_report_viewer);
        assert_eq!(app.focus, FocusTarget::ResultsExport);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn traceability_overlay_opens_with_f2_and_closes_restoring_focus() {
        let mut app = app();
        app.step = AppStep::Results;
        app.focus = FocusTarget::ResultsList;

        assert!(!press(&mut app, KeyCode::F(2)));
        assert!(app.show_trace_overlay);
        assert_eq!(app.focus, FocusTarget::TraceClose);

        assert!(!press(&mut app, KeyCode::Esc));
        assert!(!app.show_trace_overlay);
        assert_eq!(app.focus, FocusTarget::ResultsList);
    }

    #[test]
    fn ai_timeline_opens_by_key_and_closes_with_escape() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;

        press(&mut app, KeyCode::Char('i'));
        assert!(app.show_ai_timeline);
        assert_eq!(app.focus, FocusTarget::AiTimelineClose);
        assert_eq!(app.overlay_return_focus, FocusTarget::ExecutionLogs);

        assert!(!press(&mut app, KeyCode::Esc));
        assert!(!app.show_ai_timeline);
        assert_eq!(
            app.focus,
            FocusTarget::ExecutionLogs,
            "fechar devolve o foco"
        );
    }

    #[test]
    fn ai_timeline_opens_by_clicking_the_ai_block_and_closes_by_button() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        render_app(&mut app, 80, 24);

        click_action(&mut app, &SemanticAction::OpenAiTimeline);
        assert!(app.show_ai_timeline);
        assert_eq!(app.focus, FocusTarget::AiTimelineClose);

        render_app(&mut app, 80, 24);
        click_action(&mut app, &SemanticAction::Back);
        assert!(!app.show_ai_timeline, "o botão fechar fecha o painel");
        assert_eq!(app.focus, FocusTarget::ExecutionLogs);
    }

    #[test]
    fn ai_timeline_scroll_stops_following_and_resumes_at_the_end() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        for index in 0..30 {
            app.push_ai_timeline(
                crate::tui::state::AiTimelineOrigin::Ai,
                format!("evento {index}"),
            );
        }

        press(&mut app, KeyCode::Char('i'));
        render_app(&mut app, 80, 24);
        assert!(app.ai_timeline_follow);
        assert_eq!(app.ai_timeline_scroll, app.ai_timeline_max_scroll);
        assert!(
            app.ai_timeline_max_scroll > 0,
            "há mais eventos que a janela"
        );

        press(&mut app, KeyCode::Up);
        assert!(!app.ai_timeline_follow, "rolar para cima desliga o follow");
        let scrolled = app.ai_timeline_scroll;
        assert!(scrolled < app.ai_timeline_max_scroll);

        app.push_ai_timeline(
            crate::tui::state::AiTimelineOrigin::Ai,
            "novo evento".to_string(),
        );
        render_app(&mut app, 80, 24);
        assert_eq!(
            app.ai_timeline_scroll, scrolled,
            "com leitura manual o painel não salta para o fim"
        );

        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Down);
        assert_eq!(app.ai_timeline_scroll, app.ai_timeline_max_scroll);
        assert!(app.ai_timeline_follow, "voltar ao fim religa o follow");
    }

    #[test]
    fn scroll_is_saturating_and_clamped_to_visible_content() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        app.set_exec_logs((0..10).map(|index| index.to_string()).collect());
        app.log_visible_height = 3;

        dispatch_action(&mut app, SemanticAction::ScrollUp);
        assert_eq!(app.log_scroll, 0);
        for _ in 0..10 {
            dispatch_action(&mut app, SemanticAction::ScrollDown);
        }
        assert_eq!(app.log_scroll, 7);

        app.show_didactic = true;
        app.didactic_max_scroll = 4;
        app.didactic_scroll = usize::MAX;
        dispatch_action(&mut app, SemanticAction::ScrollDown);
        assert_eq!(app.didactic_scroll, 4);
        dispatch_action(&mut app, SemanticAction::ScrollUp);
        assert_eq!(app.didactic_scroll, 1);
    }

    #[test]
    fn log_scroll_pauses_follow_and_resumes_at_the_bottom() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        app.set_exec_logs((0..10).map(|index| index.to_string()).collect());
        app.log_total_lines = 20;
        app.log_visible_height = 5;
        app.log_scroll = app.log_max_scroll();

        dispatch_action(&mut app, SemanticAction::ScrollUp);
        assert_eq!(app.log_scroll, 12);
        assert!(!app.log_follow, "subir no histórico pausa o auto-follow");

        dispatch_action(&mut app, SemanticAction::ScrollDown);
        assert_eq!(app.log_scroll, 15);
        assert!(app.log_follow, "voltar ao final retoma o auto-follow");

        dispatch_action(&mut app, SemanticAction::ScrollUp);
        for _ in 0..20 {
            dispatch_action(&mut app, SemanticAction::ScrollDown);
        }
        assert_eq!(app.log_scroll, 15);
        assert!(app.log_follow);
    }

    #[test]
    fn arrow_keys_scroll_the_log_and_toggle_follow() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        app.set_exec_logs((0..10).map(|index| index.to_string()).collect());
        app.log_total_lines = 20;
        app.log_visible_height = 5;
        app.log_scroll = app.log_max_scroll();

        press(&mut app, KeyCode::Up);
        assert_eq!(app.log_scroll, 14);
        assert!(!app.log_follow);

        for _ in 0..5 {
            press(&mut app, KeyCode::Down);
        }
        assert_eq!(app.log_scroll, 15);
        assert!(app.log_follow);
    }

    #[test]
    fn mouse_wheel_over_the_log_scrolls_and_pauses_follow() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        app.set_exec_logs((0..10).map(|index| index.to_string()).collect());
        app.log_total_lines = 20;
        app.log_visible_height = 5;
        app.log_scroll = app.log_max_scroll();

        handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::ScrollUp,
                column: 10,
                row: 12,
                modifiers: KeyModifiers::NONE,
            },
        );
        assert_eq!(app.log_scroll, 12);
        assert!(!app.log_follow);

        handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: 10,
                row: 12,
                modifiers: KeyModifiers::NONE,
            },
        );
        assert_eq!(app.log_scroll, 15);
        assert!(app.log_follow);
    }

    #[test]
    fn list_navigation_handles_empty_lists_and_hitboxes_include_scroll_offset() {
        let mut empty = app();
        empty.step = AppStep::ToolSelect;
        empty.focus = FocusTarget::ToolList;
        empty.tools.clear();
        dispatch_action(&mut empty, SemanticAction::MoveDown);
        assert_eq!(empty.tool_cursor, 0);
        assert_eq!(empty.tool_scroll, 0);

        let mut app = app();
        app.step = AppStep::ToolSelect;
        app.tool_cursor = 1;
        app.tool_scroll = 0;
        render_app(&mut app, 80, 16);
        let indices: Vec<_> = app
            .hit_regions
            .iter()
            .filter_map(|region| match region.action {
                SemanticAction::ToggleTool(index) => Some(index),
                _ => None,
            })
            .collect();
        assert_eq!(indices.first(), Some(&0));
        assert!(indices.iter().all(|index| *index >= app.tool_scroll));
    }

    #[test]
    fn result_hitboxes_include_scroll_offset_and_open_the_right_item() {
        let mut app = app();
        app.orchestrator.findings = vec![finding()];
        app.step = AppStep::Results;
        app.result_cursor = app.vulnerabilities().len() - 1;
        render_app(&mut app, 80, 24);

        let first_visible = app
            .hit_regions
            .iter()
            .find_map(|region| match region.action {
                SemanticAction::OpenVulnerability(index) => Some(index),
                _ => None,
            })
            .expect("a lista deve ter ao menos um item visível");
        assert_eq!(first_visible, app.result_scroll);

        click_action(&mut app, &SemanticAction::OpenVulnerability(first_visible));
        assert_eq!(app.result_detail_vuln, Some(first_visible));
        assert_eq!(app.focus, FocusTarget::ResultsDetail);
    }

    #[test]
    fn hit_regions_are_rebuilt_for_each_frame() {
        let mut app = app();
        render_app(&mut app, 80, 24);
        assert!(app
            .hit_regions
            .iter()
            .any(|region| region.action == SemanticAction::StartScan));

        app.step = AppStep::Analysis;
        app.focus = FocusTarget::AnalysisCancel;
        render_app(&mut app, 80, 24);
        assert!(!app
            .hit_regions
            .iter()
            .any(|region| region.action == SemanticAction::StartScan));
        assert!(app
            .hit_regions
            .iter()
            .any(|region| region.action == SemanticAction::Back));
    }

    /// RNF07 sob carga: com milhares de linhas de log, teclado, mouse e
    /// renderização em 80x24 continuam respondendo.
    #[test]
    fn the_tui_stays_responsive_under_a_full_log() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        app.set_exec_logs(
            (0..5000)
                .map(|index| format!("[Nmap] linha {index} {}", "x".repeat(120)))
                .collect(),
        );

        let screen = render_app(&mut app, 80, 24);
        assert!(
            screen.contains("linha 4999"),
            "o fim do log fica visível no auto-follow\n{screen}"
        );

        app.log_follow = false;
        app.log_scroll = 0;
        let top = render_app(&mut app, 80, 24);
        assert!(top.contains("linha 0"), "o topo continua alcançável\n{top}");

        click_action(
            &mut app,
            &SemanticAction::SetFocus(FocusTarget::ExecutionLogs),
        );
        assert_eq!(app.focus, FocusTarget::ExecutionLogs);
        assert_eq!(app.log_scroll, 0, "o clique não move o histórico");

        let before = app.log_scroll;
        press(&mut app, KeyCode::Down);
        assert!(app.log_scroll > before, "o teclado continua rolando");
        assert!(
            app.log_scroll <= app.log_max_scroll(),
            "a rolagem respeita o limite de linhas visuais"
        );
        assert!(!app.log_follow);

        let after = render_app(&mut app, 80, 24);
        assert!(
            after.contains("SmartSec"),
            "a tela continua sendo renderizada"
        );
    }

    #[test]
    fn help_opens_contextually_and_escape_restores_focus() {
        let mut app = app();
        app.step = AppStep::Results;
        app.focus = FocusTarget::ResultsExport;

        press(&mut app, KeyCode::Char('?'));
        assert!(app.show_help_overlay);
        assert_eq!(app.focus, FocusTarget::HelpClose);
        assert!(!press(&mut app, KeyCode::Char('?')));
        assert!(!app.show_help_overlay);
        assert_eq!(app.focus, FocusTarget::ResultsExport);
    }

    #[test]
    fn question_mark_is_inserted_in_target_and_text_fields() {
        let mut app = app();
        app.config.target_url = "https://exemplo.local/busca".to_string();
        app.focus = FocusTarget::SplashTarget;

        press(&mut app, KeyCode::Char('?'));
        for character in "q=teste".chars() {
            press(&mut app, KeyCode::Char(character));
        }

        assert_eq!(app.config.target_url, "https://exemplo.local/busca?q=teste");
        assert!(!app.show_help_overlay);

        dispatch_action(&mut app, SemanticAction::OpenSettings);
        app.settings_input_base_url = "https://api.exemplo.local/v1".to_string();
        set_focus(&mut app, FocusTarget::SettingsField(SettingsField::BaseUrl));
        press(&mut app, KeyCode::Char('?'));
        assert_eq!(app.settings_input_base_url, "https://api.exemplo.local/v1?");
        assert!(!app.show_help_overlay);

        app.settings_input_timeout = "45".to_string();
        set_focus(&mut app, FocusTarget::SettingsField(SettingsField::Timeout));
        press(&mut app, KeyCode::Char('?'));
        assert_eq!(app.settings_input_timeout, "45");
        assert!(!app.show_help_overlay);
    }

    #[test]
    fn f1_opens_help_globally_and_footer_is_clickable() {
        let mut keyboard = app();
        keyboard.config.target_url = "https://exemplo.local/?q=teste".to_string();
        keyboard.focus = FocusTarget::SplashTarget;

        press(&mut keyboard, KeyCode::F(1));

        assert!(keyboard.show_help_overlay);
        assert_eq!(keyboard.focus, FocusTarget::HelpClose);
        assert_eq!(keyboard.config.target_url, "https://exemplo.local/?q=teste");

        let mut mouse = app();
        render_app(&mut mouse, 80, 24);
        click_action(&mut mouse, &SemanticAction::OpenHelp);
        assert!(mouse.show_help_overlay);
        assert_eq!(mouse.focus, FocusTarget::HelpClose);
    }

    #[test]
    fn command_palette_is_navigable_and_keyboard_mouse_are_equivalent() {
        let mut keyboard = app();
        handle_key(
            &mut keyboard,
            KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL),
        );
        assert!(keyboard.show_command_palette);
        press(&mut keyboard, KeyCode::Down);
        assert_eq!(keyboard.command_cursor, 1);
        press(&mut keyboard, KeyCode::Up);
        press(&mut keyboard, KeyCode::Enter);

        let mut mouse = app();
        dispatch_action(&mut mouse, SemanticAction::OpenCommandPalette);
        render_app(&mut mouse, 80, 24);
        click_action(&mut mouse, &SemanticAction::ExecuteCommand(0));

        assert_eq!(keyboard.show_help_overlay, mouse.show_help_overlay);
        assert_eq!(keyboard.show_command_palette, mouse.show_command_palette);
        assert_eq!(keyboard.focus, mouse.focus);
    }

    #[test]
    fn disabled_palette_command_does_not_execute_or_close() {
        let mut app = app();
        app.step = AppStep::ToolSelect;
        for tool in &mut app.tools {
            tool.selected = false;
        }
        dispatch_action(&mut app, SemanticAction::OpenCommandPalette);
        let run_index = command_items(&app)
            .iter()
            .position(|item| item.action == SemanticAction::RunTools)
            .unwrap();

        dispatch_action(&mut app, SemanticAction::ExecuteCommand(run_index));

        assert_eq!(app.step, AppStep::ToolSelect);
        assert!(app.show_command_palette);
    }

    #[test]
    fn command_from_settings_restores_the_underlying_screen_focus() {
        let mut app = app();
        app.step = AppStep::Results;
        app.focus = FocusTarget::ResultsExport;
        dispatch_action(&mut app, SemanticAction::OpenSettings);
        dispatch_action(&mut app, SemanticAction::OpenCommandPalette);
        let cancel_index = command_items(&app)
            .iter()
            .position(|item| item.action == SemanticAction::CloseSettings)
            .unwrap();

        dispatch_action(&mut app, SemanticAction::ExecuteCommand(cancel_index));

        assert!(!app.show_settings);
        assert!(!app.show_command_palette);
        assert_eq!(app.step, AppStep::Results);
        assert_eq!(app.focus, FocusTarget::ResultsExport);
    }

    #[test]
    fn p_toggles_pause_and_c_cancels_with_keyboard_and_mouse_parity() {
        let mut keyboard = app();
        keyboard.step = AppStep::Execution;
        keyboard.focus = FocusTarget::ExecutionPause;
        keyboard.tools[0].status = crate::tui::state::ToolStatus::Running;
        let mut mouse = app();
        mouse.step = AppStep::Execution;
        mouse.focus = FocusTarget::ExecutionPause;
        mouse.tools[0].status = crate::tui::state::ToolStatus::Running;
        render_app(&mut mouse, 80, 24);

        press(&mut keyboard, KeyCode::Char('p'));
        click_action(&mut mouse, &SemanticAction::PauseRun);

        assert!(keyboard.orchestrator.control.is_paused());
        assert!(mouse.orchestrator.control.is_paused());
        assert_eq!(
            keyboard.tools[0].status,
            crate::tui::state::ToolStatus::Paused
        );
        assert_eq!(mouse.tools[0].status, keyboard.tools[0].status);

        // A mesma tecla retoma: o rótulo do botão acompanha o estado real.
        press(&mut keyboard, KeyCode::Char('p'));
        assert!(!keyboard.orchestrator.control.is_paused());

        press(&mut keyboard, KeyCode::Char('c'));
        assert!(keyboard.orchestrator.is_cancelled());
        assert!(keyboard.exec_cancelled);
    }

    #[test]
    fn pause_and_cancel_shortcuts_are_ignored_inside_overlays() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        dispatch_action(&mut app, SemanticAction::OpenHelp);

        press(&mut app, KeyCode::Char('p'));
        press(&mut app, KeyCode::Char('c'));

        assert!(
            app.show_help_overlay,
            "a ajuda precisa continuar capturando as teclas"
        );
        assert!(!app.orchestrator.control.is_paused());
        assert!(!app.orchestrator.is_cancelled());
    }

    #[test]
    fn the_execution_palette_exposes_pause_resume_and_cancel() {
        let mut app = app();
        app.step = AppStep::Execution;
        dispatch_action(&mut app, SemanticAction::OpenCommandPalette);

        let items = command_items(&app);
        let pause = items
            .iter()
            .position(|item| item.action == SemanticAction::PauseRun)
            .expect("a pausa precisa estar na paleta");
        assert_eq!(items[pause].shortcut, "p");
        dispatch_action(&mut app, SemanticAction::ExecuteCommand(pause));
        assert!(app.orchestrator.control.is_paused());

        dispatch_action(&mut app, SemanticAction::OpenCommandPalette);
        let items = command_items(&app);
        let resume = items
            .iter()
            .position(|item| item.action == SemanticAction::ResumeRun)
            .expect("a retomada precisa estar na paleta depois da pausa");
        dispatch_action(&mut app, SemanticAction::ExecuteCommand(resume));
        assert!(!app.orchestrator.control.is_paused());

        dispatch_action(&mut app, SemanticAction::OpenCommandPalette);
        let cancel = items_index(&app, SemanticAction::CancelRun);
        dispatch_action(&mut app, SemanticAction::ExecuteCommand(cancel));
        assert!(app.orchestrator.is_cancelled());
    }

    fn items_index(app: &AppState, action: SemanticAction) -> usize {
        command_items(app)
            .iter()
            .position(|item| item.action == action)
            .expect("a ação precisa estar na paleta")
    }

    #[test]
    fn help_blocks_scroll_and_cancelled_actions_stay_disabled() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        app.set_exec_logs((0..10).map(|index| index.to_string()).collect());
        app.log_visible_height = 2;
        dispatch_action(&mut app, SemanticAction::OpenHelp);
        dispatch_action(&mut app, SemanticAction::ScrollDown);
        assert_eq!(app.log_scroll, 0);

        dispatch_action(&mut app, SemanticAction::Back);
        app.exec_cancelled = true;
        app.focus = FocusTarget::ExecutionCancel;
        dispatch_action(&mut app, SemanticAction::Activate);
        assert!(app.exec_cancelled);
    }

    #[test]
    fn history_opens_with_h_outside_text_input_and_lists_recorded_runs() {
        let dir = std::env::temp_dir().join(format!(
            "smartsec_historico_eventos_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        crate::orchestrator::scan_logger::save_scan_log_to_dir(
            &crate::orchestrator::scan_logger::ScanMetadata {
                scan_id: "scan_1757000000000000001".to_string(),
                target_url: "http://alvo.local".to_string(),
                started_at: "2026-09-06T10:00:00Z".to_string(),
                completed_at: "2026-09-06T10:05:00Z".to_string(),
                execution_type: "Auto".to_string(),
                llm_provider: "Ollama".to_string(),
                tools_executed: Vec::new(),
                findings_count: 0,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                info_count: 0,
                findings: Vec::new(),
                agent_analysis: "Análise".to_string(),
                decisions: Vec::new(),
                enrichment: Default::default(),
                interruption: None,
                ..Default::default()
            },
            &dir,
        )
        .expect("gravação do registro de teste");

        let mut app = app();
        app.history_dir = dir.clone();
        app.step = AppStep::Results;
        app.focus = FocusTarget::ResultsList;

        assert!(!press(&mut app, KeyCode::Char('h')));
        assert_eq!(app.step, AppStep::History);
        assert_eq!(app.focus, FocusTarget::HistoryList);
        assert_eq!(app.history.records.len(), 1);
        assert_eq!(app.history_cursor, 0);

        // Enter abre o detalhe e Esc volta para a tela de origem.
        assert!(!press(&mut app, KeyCode::Enter));
        assert!(app.history_detail.is_some());
        assert_eq!(app.focus, FocusTarget::HistoryDetail);
        assert!(!press(&mut app, KeyCode::Esc));
        assert!(app.history_detail.is_none());
        assert_eq!(app.focus, FocusTarget::HistoryList);
        assert!(!press(&mut app, KeyCode::Esc));
        assert_eq!(app.step, AppStep::Results, "Esc devolve à tela de origem");
        assert_eq!(app.focus, FocusTarget::ResultsList);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn typing_h_on_the_splash_fills_the_target_instead_of_opening_history() {
        let mut app = app();
        app.config.target_url = "https://".to_string();
        app.focus = FocusTarget::SplashTarget;

        press(&mut app, KeyCode::Char('h'));

        assert_eq!(app.config.target_url, "https://h");
        assert_eq!(app.step, AppStep::Splash);
    }

    #[test]
    fn history_list_navigates_and_the_mouse_opens_the_row_under_the_pointer() {
        let dir = std::env::temp_dir().join(format!(
            "smartsec_historico_mouse_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (index, completed_at) in ["2026-09-06T10:05:00Z", "2026-09-07T10:05:00Z"]
            .iter()
            .enumerate()
        {
            crate::orchestrator::scan_logger::save_scan_log_to_dir(
                &crate::orchestrator::scan_logger::ScanMetadata {
                    scan_id: format!("scan_175700000000000000{index}"),
                    target_url: "http://alvo.local".to_string(),
                    started_at: "2026-09-06T10:00:00Z".to_string(),
                    completed_at: completed_at.to_string(),
                    execution_type: "Auto".to_string(),
                    llm_provider: "Ollama".to_string(),
                    tools_executed: Vec::new(),
                    findings_count: 0,
                    critical_count: 0,
                    high_count: 0,
                    medium_count: 0,
                    low_count: 0,
                    info_count: 0,
                    findings: Vec::new(),
                    agent_analysis: "Análise".to_string(),
                    decisions: Vec::new(),
                    enrichment: Default::default(),
                    interruption: None,
                    ..Default::default()
                },
                &dir,
            )
            .expect("gravação do registro de teste");
        }

        let mut app = app();
        app.history_dir = dir.clone();
        app.step = AppStep::History;
        app.focus = FocusTarget::HistoryList;
        app.load_history();
        assert_eq!(app.history.records.len(), 2);

        // A ordem é da mais recente para a mais antiga, então o índice 1 é a mais antiga.
        assert_eq!(app.history.records[0].scan_id, "scan_1757000000000000001");
        assert_eq!(app.history.records[1].scan_id, "scan_1757000000000000000");

        dispatch_action(&mut app, SemanticAction::MoveDown);
        assert_eq!(app.history_cursor, 1);
        for _ in 0..5 {
            dispatch_action(&mut app, SemanticAction::MoveDown);
        }
        assert_eq!(
            app.history_cursor, 1,
            "a navegação satura no último registro"
        );
        dispatch_action(&mut app, SemanticAction::MoveUp);
        assert_eq!(app.history_cursor, 0);

        render_app(&mut app, 80, 24);
        assert!(
            !click_action(&mut app, &SemanticAction::OpenHistoryRecord(0)),
            "o clique não deve encerrar o ciclo de eventos"
        );
        assert_eq!(app.focus, FocusTarget::HistoryDetail);
        assert_eq!(
            app.history_detail
                .as_ref()
                .map(|meta| meta.scan_id.as_str()),
            Some("scan_1757000000000000001"),
            "o clique precisa abrir a execução da linha apontada"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn opening_a_corrupted_record_keeps_the_list_with_an_actionable_error() {
        let dir = std::env::temp_dir().join(format!(
            "smartsec_historico_corrompido_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("scan_1757000000000000001.json"), "{quebrado").unwrap();

        let mut app = app();
        app.history_dir = dir.clone();
        app.step = AppStep::History;
        app.focus = FocusTarget::HistoryList;
        app.load_history();

        assert!(
            app.history.records.is_empty(),
            "registro corrompido não lista"
        );
        assert_eq!(app.history.unreadable.len(), 1);

        app.open_history_record(0);
        assert!(
            app.history_detail.is_none(),
            "não há registro selecionável quando a leitura falha"
        );
        assert_eq!(app.focus, FocusTarget::HistoryList);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn blocking_layers_suspend_and_resume_underlying_transitions() {
        let mut app = app();
        app.set_mode(ExecutionType::Auto);
        app.step = AppStep::ToolSelect;
        app.focus = FocusTarget::ToolList;
        dispatch_action(&mut app, SemanticAction::OpenSettings);

        app.tick();
        app.step_tick().await;
        assert_eq!(
            app.step,
            AppStep::ToolSelect,
            "a execução não começa por baixo de uma camada sobreposta"
        );
        dispatch_action(&mut app, SemanticAction::CloseSettings);
        assert_eq!(app.focus, FocusTarget::ToolList);
        app.tick();
        assert_eq!(app.step, AppStep::Execution);

        app.step = AppStep::Analysis;
        app.focus = FocusTarget::AnalysisCancel;
        dispatch_action(&mut app, SemanticAction::OpenHelp);
        app.tick();
        app.step_tick().await;
        assert_eq!(
            app.step,
            AppStep::Analysis,
            "a análise em curso continua enquanto a ajuda está aberta"
        );
        dispatch_action(&mut app, SemanticAction::Back);
        assert_eq!(app.focus, FocusTarget::AnalysisCancel);
        app.step_tick().await;
        assert_eq!(
            app.step,
            AppStep::Analysis,
            "só o cancelamento encerra a análise, e ele é explícito"
        );
        dispatch_action(&mut app, SemanticAction::Back);
        app.step_tick().await;
        assert_eq!(app.step, AppStep::ToolSelect);
        assert_eq!(app.focus, FocusTarget::ToolList);
        if let Some(path) = app.audit_log_path.clone() {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn long_vulnerability_detail_scrolls_with_keyboard_and_mouse() {
        let mut app = app();
        let mut finding = finding();
        finding.description = "Descrição técnica extensa com evidência reproduzível. ".repeat(30);
        finding.recommendation = "Aplique a correção indicada e valide novamente. ".repeat(30);
        app.orchestrator.findings = vec![finding];
        app.step = AppStep::Results;
        dispatch_action(&mut app, SemanticAction::OpenVulnerability(0));

        let screen = render_app(&mut app, 80, 24);
        assert!(app.detail_max_scroll > 0);
        assert!(screen.contains("↑↓ rolar · linhas"));

        press(&mut app, KeyCode::Down);
        assert_eq!(app.detail_scroll, 1);
        assert_eq!(app.result_detail_vuln, Some(0));
        handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: 40,
                row: 10,
                modifiers: KeyModifiers::NONE,
            },
        );
        assert_eq!(app.detail_scroll, 4);
        for _ in 0..app.detail_max_scroll + 1 {
            dispatch_action(&mut app, SemanticAction::ScrollDown);
        }
        assert_eq!(app.detail_scroll, app.detail_max_scroll);

        app.detail_scroll = 0;
        dispatch_action(&mut app, SemanticAction::ScrollUp);
        assert_eq!(app.detail_scroll, 0);
        assert_eq!(app.result_detail_vuln, Some(0));
    }

    #[test]
    fn cancelling_settings_discards_draft_before_reopening() {
        let mut app = app();
        app.config.llm.base_url = "https://api.persistida.local/v1".to_string();
        app.config.llm.model = "modelo-persistido".to_string();
        app.config.llm.remote_consent = false;
        dispatch_action(&mut app, SemanticAction::OpenSettings);
        app.settings_input_base_url = "https://rascunho.local/v1".to_string();
        app.settings_input_model = "modelo-rascunho".to_string();
        app.settings_remote_consent = true;

        dispatch_action(&mut app, SemanticAction::CloseSettings);

        assert!(!app.show_settings);
        assert_eq!(app.config.llm.model, "modelo-persistido");
        assert_eq!(
            app.settings_input_base_url,
            "https://api.persistida.local/v1"
        );
        assert_eq!(app.settings_input_model, "modelo-persistido");
        assert!(!app.settings_remote_consent);

        dispatch_action(&mut app, SemanticAction::OpenSettings);
        assert_eq!(
            app.settings_input_base_url,
            "https://api.persistida.local/v1"
        );
        assert_eq!(app.settings_input_model, "modelo-persistido");
        assert!(!app.settings_remote_consent);

        app.settings_input_model = "outro-rascunho".to_string();
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.settings_input_model, "modelo-persistido");
    }

    #[test]
    fn invalid_settings_stay_open_with_an_actionable_error() {
        let mut app = app();
        dispatch_action(&mut app, SemanticAction::OpenSettings);
        app.settings_input_timeout = "99".to_string();

        dispatch_action(&mut app, SemanticAction::SaveSettings);

        assert!(app.show_settings);
        assert!(app
            .settings_error
            .as_deref()
            .is_some_and(|error| error.contains("entre 1 e 45")));
        assert_eq!(app.config.llm.timeout_secs, 45);
    }

    #[test]
    fn ctrl_u_clears_the_active_field_and_first_api_key_input_replaces_the_secret() {
        let mut app = app();
        dispatch_action(&mut app, SemanticAction::OpenSettings);
        set_focus(&mut app, FocusTarget::SettingsField(SettingsField::BaseUrl));
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
        );
        assert!(app.settings_input_base_url.is_empty());

        app.settings_provider_idx = 2;
        app.settings_input_base_url = "https://api.openai.com/v1".to_string();
        app.settings_input_api_key = "chave-antiga".to_string();
        set_focus(&mut app, FocusTarget::SettingsField(SettingsField::ApiKey));
        press(&mut app, KeyCode::Char('n'));

        assert_eq!(app.settings_input_api_key, "n");
        assert!(app.settings_api_key_touched);
    }

    /// O assistente precisa ser alcançável depois da primeira execução, sem
    /// depender de a pessoa lembrar que existe um subcomando.
    #[test]
    fn the_command_palette_offers_the_onboarding_wizard() {
        let mut app = app_with_offline_onboarding();

        dispatch_action(&mut app, SemanticAction::OpenCommandPalette);
        assert!(command_items(&app)
            .iter()
            .any(|item| item.action == SemanticAction::OpenOnboarding));

        let index = command_items(&app)
            .iter()
            .position(|item| item.action == SemanticAction::OpenOnboarding)
            .unwrap();
        dispatch_action(&mut app, SemanticAction::ExecuteCommand(index));

        assert!(app.onboarding_open());
        assert!(!app.show_command_palette);
        assert_eq!(app.focus, FocusTarget::OnboardingList);
    }

    /// Sair do assistente por `esc` é abandono, não conclusão: nada é gravado
    /// e a tela de análise volta a ser a de sempre.
    #[test]
    fn escape_leaves_the_onboarding_without_closing_the_tui() {
        let mut app = app_with_offline_onboarding();
        app.onboarding = Some(crate::config::onboarding::OnboardingState::start());

        let should_quit = press(&mut app, KeyCode::Esc);

        assert!(!should_quit);
        assert!(!app.onboarding_open());
    }

    /// As setas percorrem as escolhas do passo, e o item focado responde ao
    /// mouse com a mesma ação do teclado (RNF07).
    #[test]
    fn onboarding_choices_move_with_the_arrows_and_answer_the_mouse() {
        let mut app = app_with_offline_onboarding();
        let mut onboarding = crate::config::onboarding::OnboardingState::start();
        // Consentimento: as duas escolhas só decidem o caminho, nenhuma grava.
        onboarding.step = crate::config::onboarding::OnboardingStep::Consent;
        app.onboarding = Some(onboarding);
        app.focus = FocusTarget::OnboardingList;
        render_app(&mut app, 80, 24);

        press(&mut app, KeyCode::Down);
        assert_eq!(app.onboarding_cursor, 1);
        press(&mut app, KeyCode::Up);
        assert_eq!(app.onboarding_cursor, 0);

        let region = app
            .hit_regions
            .iter()
            .find(|region| region.action == SemanticAction::OnboardingActivate(1))
            .expect("a segunda escolha precisa de região clicável")
            .clone();
        let clicked = handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: region.area.x,
                row: region.area.y,
                modifiers: KeyModifiers::NONE,
            },
        );

        assert!(!clicked);
        assert_eq!(
            app.onboarding.as_ref().and_then(|state| state.consent),
            Some(false),
            "o clique precisa ter disparado a mesma decisão que a seta+f1 produz"
        );
    }

    /// Na etapa de credencial a tecla escreve no segredo em vez de virar ação,
    /// e o primeiro caractere substitui o que estava em rascunho.
    #[test]
    fn the_credential_step_takes_the_secret_typed_by_keyboard() {
        let mut app = app_with_offline_onboarding();
        let mut onboarding = crate::config::onboarding::OnboardingState::start();
        onboarding.step = crate::config::onboarding::OnboardingStep::Credential;
        app.onboarding = Some(onboarding);
        app.focus = FocusTarget::OnboardingList;
        app.settings_input_api_key = "chave-antiga".to_string();

        press(&mut app, KeyCode::Char('a'));

        assert_eq!(app.settings_input_api_key, "a");
        assert!(app.settings_api_key_touched);
    }

    /// Salvar uma configuração inválida a partir do assistente mantém o fluxo
    /// aberto e mostra a causa, em vez de fechar sobre um erro.
    #[test]
    fn an_invalid_save_inside_the_onboarding_keeps_the_wizard_open_with_an_error() {
        let mut app = app_with_offline_onboarding();
        app.onboarding = Some(crate::config::onboarding::OnboardingState::start());
        dispatch_action(&mut app, SemanticAction::OpenSettings);
        app.settings_input_timeout = "99".to_string();

        dispatch_action(&mut app, SemanticAction::SaveSettings);

        assert!(app.show_settings);
        assert!(app.onboarding_open());
        assert!(app
            .settings_error
            .as_deref()
            .is_some_and(|error| error.contains("entre 1 e 45")));
    }

    fn settings_app() -> AppState {
        let mut app = app();
        dispatch_action(&mut app, SemanticAction::OpenSettings);
        app
    }

    /// `enter` abre a digitação do campo de texto e `esc` sai dela sem descartar
    /// o rascunho; o descarte continua sendo do segundo `esc`, como antes.
    #[test]
    fn enter_opens_the_text_field_and_esc_leaves_it_keeping_the_draft() {
        let mut app = settings_app();
        set_focus(&mut app, FocusTarget::SettingsField(SettingsField::BaseUrl));
        app.settings_input_base_url.clear();

        press(&mut app, KeyCode::Enter);
        assert_eq!(app.settings_editing, Some(SettingsField::BaseUrl));

        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.settings_input_base_url, "a");

        press(&mut app, KeyCode::Esc);
        assert_eq!(app.settings_editing, None);
        assert!(
            app.show_settings,
            "sair da edição não pode fechar a tela nem descartar o rascunho"
        );
        assert_eq!(app.settings_input_base_url, "a");

        press(&mut app, KeyCode::Esc);
        assert!(!app.show_settings, "sem edição aberta, esc fecha a tela");
    }

    /// O primeiro caractere digitado já abre a edição: o operador não precisa
    /// saber de antemão que existe um estado de edição para digitar.
    #[test]
    fn typing_opens_the_editing_and_leaving_the_field_closes_it() {
        let mut app = settings_app();
        set_focus(&mut app, FocusTarget::SettingsField(SettingsField::Model));

        press(&mut app, KeyCode::Char('x'));

        assert_eq!(app.settings_editing, Some(SettingsField::Model));
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.settings_editing, None);
        assert_ne!(app.focus, FocusTarget::SettingsField(SettingsField::Model));
    }

    /// `esc` no meio da digitação é o caminho que o operador usa para sair do
    /// campo: ele não pode fechar a tela e perder tudo sem aviso.
    #[test]
    fn escape_while_editing_keeps_every_field_of_the_draft() {
        let mut app = settings_app();
        set_focus(&mut app, FocusTarget::SettingsField(SettingsField::Timeout));
        app.settings_input_timeout.clear();
        press(&mut app, KeyCode::Char('9'));
        set_focus(&mut app, FocusTarget::SettingsField(SettingsField::Retries));
        app.settings_input_retries.clear();
        press(&mut app, KeyCode::Char('2'));

        set_focus(&mut app, FocusTarget::SettingsField(SettingsField::Timeout));
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Esc);

        assert!(app.show_settings);
        assert_eq!(app.settings_input_timeout, "9");
        assert_eq!(app.settings_input_retries, "2");
    }

    /// Fora da edição, `espaço` aciona o item em foco (como no resto da TUI);
    /// dentro dela, `espaço` é texto.
    #[test]
    fn space_activates_outside_the_editing_and_types_inside_it() {
        let mut app = settings_app();
        set_focus(
            &mut app,
            FocusTarget::SettingsField(SettingsField::ProjectDir),
        );
        app.settings_input_project_dir.clear();

        press(&mut app, KeyCode::Char(' '));
        assert_eq!(
            app.settings_editing,
            Some(SettingsField::ProjectDir),
            "espaço no campo fechado abre a edição"
        );

        press(&mut app, KeyCode::Char(' '));
        assert_eq!(app.settings_input_project_dir, " ", "espaço digitado");

        press(&mut app, KeyCode::Enter);
        assert_eq!(app.settings_editing, None, "enter fecha a edição");
        assert_eq!(app.settings_input_project_dir, " ");
    }

    /// Em duas colunas, `↑`/`↓` andam dentro da coluna do campo em foco, sem
    /// atravessar para a coluna vizinha.
    #[test]
    fn vertical_arrows_walk_inside_the_column_of_the_focused_field() {
        let mut app = settings_app();
        render_app(&mut app, 80, 24);
        assert!(app.settings_two_columns, "80x24 desenha duas colunas");

        set_focus(
            &mut app,
            FocusTarget::SettingsField(SettingsField::Provider),
        );
        press(&mut app, KeyCode::Down);
        assert_eq!(
            app.focus,
            FocusTarget::SettingsField(SettingsField::BaseUrl)
        );
        press(&mut app, KeyCode::Down);
        assert_eq!(app.focus, FocusTarget::SettingsField(SettingsField::Model));
        press(&mut app, KeyCode::Down);
        assert_eq!(
            app.focus,
            FocusTarget::SettingsField(SettingsField::ApiKey),
            "a chave de API fica abaixo do modelo na coluna principal"
        );
        press(&mut app, KeyCode::Up);
        assert_eq!(app.focus, FocusTarget::SettingsField(SettingsField::Model));
        press(&mut app, KeyCode::Up);
        assert_eq!(
            app.focus,
            FocusTarget::SettingsField(SettingsField::BaseUrl)
        );
        press(&mut app, KeyCode::Up);
        assert_eq!(
            app.focus,
            FocusTarget::SettingsField(SettingsField::Provider)
        );
        press(&mut app, KeyCode::Up);
        assert_eq!(
            app.focus,
            FocusTarget::SettingsField(SettingsField::ProjectDir),
            "no fim da coluna a navegação dá a volta"
        );

        set_focus(&mut app, FocusTarget::SettingsField(SettingsField::Timeout));
        press(&mut app, KeyCode::Down);
        assert_eq!(
            app.focus,
            FocusTarget::SettingsField(SettingsField::Retries),
            "a coluna de segurança e limites anda por conta própria"
        );
    }

    /// `←`/`→` trocam de coluna mantendo a linha; quem troca o valor do provedor
    /// e dos interruptores é `enter` ou `espaço`.
    #[test]
    fn horizontal_arrows_switch_columns_on_the_same_row() {
        let mut app = settings_app();
        render_app(&mut app, 80, 24);

        set_focus(&mut app, FocusTarget::SettingsField(SettingsField::BaseUrl));
        press(&mut app, KeyCode::Right);
        assert_eq!(
            app.focus,
            FocusTarget::SettingsField(SettingsField::Timeout),
            "a linha equivalente da coluna vizinha"
        );
        press(&mut app, KeyCode::Left);
        assert_eq!(
            app.focus,
            FocusTarget::SettingsField(SettingsField::BaseUrl)
        );

        set_focus(
            &mut app,
            FocusTarget::SettingsField(SettingsField::RemoteConsent),
        );
        press(&mut app, KeyCode::Right);
        assert_eq!(
            app.focus,
            FocusTarget::SettingsField(SettingsField::Provider),
            "sem linha equivalente, a coluna vizinha usa a última disponível"
        );

        set_focus(
            &mut app,
            FocusTarget::SettingsField(SettingsField::FallbackEnabled),
        );
        press(&mut app, KeyCode::Right);
        assert_eq!(
            app.focus,
            FocusTarget::SettingsField(SettingsField::ApiKey),
            "a coluna vizinha usa a linha equivalente"
        );
        assert!(
            !app.settings_fallback_enabled,
            "a seta move o foco e não troca o valor do interruptor"
        );
    }

    /// No formulário compacto só existe uma coluna: as quatro setas percorrem a
    /// mesma ordem da lista.
    #[test]
    fn in_the_compact_form_the_arrows_walk_the_single_list() {
        let mut app = settings_app();
        render_app(&mut app, 80, 12);
        assert!(!app.settings_two_columns, "80x12 desenha a lista compacta");

        set_focus(&mut app, FocusTarget::SettingsField(SettingsField::Retries));
        press(&mut app, KeyCode::Down);
        assert_eq!(
            app.focus,
            FocusTarget::SettingsField(SettingsField::FallbackEnabled)
        );
        press(&mut app, KeyCode::Right);
        assert_eq!(app.focus, FocusTarget::SettingsCancel);
        press(&mut app, KeyCode::Left);
        assert_eq!(
            app.focus,
            FocusTarget::SettingsField(SettingsField::FallbackEnabled)
        );
    }

    /// A tabulação termina nos botões na ordem em que eles aparecem na tela:
    /// descartar à esquerda, salvar à direita.
    #[test]
    fn tab_reaches_the_buttons_in_screen_order() {
        let mut app = settings_app();

        set_focus(
            &mut app,
            FocusTarget::SettingsField(SettingsField::FallbackEnabled),
        );
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.focus, FocusTarget::SettingsCancel);
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.focus, FocusTarget::SettingsSave);
        press(&mut app, KeyCode::Tab);
        assert_eq!(
            app.focus,
            FocusTarget::SettingsField(SettingsField::Provider),
            "a tabulação dá a volta para o primeiro campo"
        );
    }

    /// O botão de limpar só existe quando há campo de texto em foco: fora dele o
    /// clique não teria efeito nenhum.
    #[test]
    fn the_clear_button_only_answers_with_a_text_field_in_focus() {
        let mut app = settings_app();
        set_focus(&mut app, FocusTarget::SettingsSave);
        render_app(&mut app, 80, 24);
        assert!(
            !app.hit_regions
                .iter()
                .any(|region| region.action == SemanticAction::ClearText),
            "sem campo de texto em foco não deve haver botão de limpar"
        );

        set_focus(&mut app, FocusTarget::SettingsField(SettingsField::BaseUrl));
        render_app(&mut app, 80, 24);
        assert!(app
            .hit_regions
            .iter()
            .any(|region| region.action == SemanticAction::ClearText));
    }

    /// O clique no campo de texto abre a edição, para o mouse ter a mesma
    /// intenção do `enter` no teclado.
    #[test]
    fn clicking_a_text_field_opens_it_for_typing() {
        let mut app = settings_app();
        render_app(&mut app, 80, 24);

        assert!(!click_action(
            &mut app,
            &SemanticAction::SelectSettingsField(SettingsField::BaseUrl)
        ));

        assert_eq!(
            app.focus,
            FocusTarget::SettingsField(SettingsField::BaseUrl)
        );
        assert_eq!(app.settings_editing, Some(SettingsField::BaseUrl));
    }

    /// O movimento do mouse alimenta o hover; um resize invalida as coordenadas
    /// antigas para o realce não apontar para um lugar que já mudou.
    #[test]
    fn mouse_movement_feeds_hover_and_resize_clears_it() {
        let mut app = app();
        assert_eq!(app.mouse_position, None);

        assert!(!handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Moved,
                column: 12,
                row: 5,
                modifiers: KeyModifiers::NONE,
            },
        ));
        assert_eq!(app.mouse_position, Some((12, 5)));

        assert!(!handle_resize(&mut app));
        assert_eq!(app.mouse_position, None);
    }

    #[test]
    fn ctrl_t_toggles_mouse_capture() {
        let mut app = app();
        let key = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::CONTROL);

        assert!(app.mouse_capture);
        assert!(!handle_key(&mut app, key));
        assert!(!app.mouse_capture);
        assert!(!handle_key(&mut app, key));
        assert!(app.mouse_capture);
    }
}
