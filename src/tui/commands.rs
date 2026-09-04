use crate::config::execution_type::ExecutionType;
use crate::tui::interaction::SemanticAction;
use crate::tui::state::{AppState, AppStep};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandItem {
    pub label: &'static str,
    pub shortcut: &'static str,
    pub action: SemanticAction,
    pub enabled: bool,
}

impl CommandItem {
    fn new(label: &'static str, shortcut: &'static str, action: SemanticAction) -> Self {
        Self {
            label,
            shortcut,
            action,
            enabled: true,
        }
    }

    fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

pub fn command_items(app: &AppState) -> Vec<CommandItem> {
    let mut items = vec![CommandItem::new(
        "Abrir ajuda",
        "?",
        SemanticAction::OpenHelp,
    )];
    if app.show_settings {
        items.extend([
            CommandItem::new("Salvar configurações", "", SemanticAction::SaveSettings),
            CommandItem::new("Cancelar alterações", "esc", SemanticAction::CloseSettings),
        ]);
        return items;
    }
    items.push(CommandItem::new(
        "Abrir configurações",
        "",
        SemanticAction::OpenSettings,
    ));

    match app.step {
        AppStep::Splash => items.extend([
            CommandItem::new("Iniciar análise", "enter", SemanticAction::StartScan),
            CommandItem::new(
                "Usar modo automático",
                "",
                SemanticAction::SetMode(ExecutionType::Auto),
            ),
            CommandItem::new(
                "Usar modo assistido",
                "",
                SemanticAction::SetMode(ExecutionType::Assisted),
            ),
            CommandItem::new("Sair do SmartSec", "esc", SemanticAction::Quit),
        ]),
        AppStep::ToolSelect => items.extend([
            CommandItem::new("Executar ferramentas", "enter", SemanticAction::RunTools)
                .enabled(!app.tool_detecting && app.tools.iter().any(|tool| tool.selected)),
            CommandItem::new("Voltar ao início", "esc", SemanticAction::Back),
        ]),
        AppStep::Execution => items.extend([
            CommandItem::new(
                if app.exec_paused {
                    "Retomar execução"
                } else {
                    "Pausar execução"
                },
                "",
                SemanticAction::PauseResume,
            ),
            CommandItem::new("Cancelar execução", "", SemanticAction::CancelRun),
            CommandItem::new("Voltar às ferramentas", "esc", SemanticAction::Back),
        ]),
        AppStep::Analysis => items.push(CommandItem::new(
            "Cancelar análise",
            "esc",
            SemanticAction::Back,
        )),
        AppStep::Results => {
            if app.result_detail_vuln.is_some() {
                items.extend([
                    CommandItem::new(
                        "Explicar de forma didática",
                        "",
                        SemanticAction::ShowDidactic,
                    ),
                    CommandItem::new("Voltar ao resumo", "esc", SemanticAction::Back),
                ]);
            } else {
                items.extend([
                    CommandItem::new(
                        "Exportar relatório Markdown",
                        "",
                        SemanticAction::ExportMarkdown,
                    ),
                    CommandItem::new("Ver explicação didática", "", SemanticAction::ShowDidactic),
                    CommandItem::new("Iniciar nova análise", "", SemanticAction::NewScan),
                    CommandItem::new("Voltar ao início", "esc", SemanticAction::Back),
                ]);
            }
        }
    }
    items
}
