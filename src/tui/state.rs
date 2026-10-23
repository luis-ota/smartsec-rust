use crate::ai::agent::AIAgent;
use crate::config::execution_type::ExecutionType;
use crate::config::llm_config::LlmProviderKind;
use crate::config::llm_config::{MAX_RETRIES, MAX_TIMEOUT_SECS};
use crate::config::Configuration;
use crate::domain::security_tool::SecurityTool;
use crate::domain::vulnerability::Vulnerability;
use crate::orchestrator::control::RunControl;
use crate::orchestrator::decision::{DecisionRecord, DecisionSource};
use crate::orchestrator::Orchestrator;
use crate::tools::registry::RunnerKind;
use crate::tools::ToolManifest;
use crate::tui::interaction::{FocusTarget, HitRegion, SemanticAction};
use ratatui::layout::Rect;
use ratatui::text::{Line, Text};
use ratatui::widgets::{Paragraph, Wrap};
use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::{TryRecvError, TrySendError};
use tokio::task::JoinHandle;
use unicode_width::UnicodeWidthStr;

/// Capacidade do canal de eventos da execução.
///
/// Política de drop (TCC_SPEC.md, seção 7): controle (`ToolStarted`,
/// `ToolFinished`, `Completed`) usa `send().await` e nunca é descartado — a TUI
/// sofre contrapressão e drena o canal a cada quadro, mesmo com camada
/// sobreposta aberta. Log (`ToolLog`) usa `try_send`: sob saturação a linha é
/// descartada e contada em `log_drop_counter`, sem travar a tela, e a contagem é
/// exibida ao usuário.
const RUN_EVENT_CAPACITY: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppStep {
    Splash,
    ToolSelect,
    Execution,
    Analysis,
    Results,
    History,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ToolStatus {
    Pending,
    Running,
    /// Container real pausado com `podman pause` (REQ14).
    Paused,
    Done,
    #[allow(dead_code)]
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(dead_code)]
pub enum ResultAction {
    ExportMd,
    ExplainDidactic,
    BackToSummary,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnalysisPhase {
    /// As ferramentas selecionadas ainda estão em execução.
    Scanning,
    /// Os achados foram construídos pelos parsers e estão prontos para a IA.
    Correlating,
    /// A chamada de análise por IA está em andamento.
    Generating,
    Complete,
}

/// Origem de uma ocorrência registrada durante a execução.
///
/// A TUI não reconstrói nem reclassifica erros: cada registro guarda a etapa do
/// pipeline que o produziu, para a tela dizer de onde veio a falha.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RunIssueScope {
    Tool,
    Audit,
    Ai,
    Executor,
    Validation,
    Export,
}

impl RunIssueScope {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tool => "ferramenta",
            Self::Audit => "auditoria",
            Self::Ai => "IA",
            Self::Executor => "executor",
            Self::Validation => "validação",
            Self::Export => "exportação",
        }
    }

    /// Ocorrências de IA são avisos de proveniência (falha da LLM principal,
    /// uso do modelo local alternativo, resposta descartada por contrato): não
    /// interrompem a execução e não contam como falha.
    pub const fn is_warning(self) -> bool {
        matches!(self, Self::Ai)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RunIssue {
    pub scope: RunIssueScope,
    pub detail: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AiActivity {
    WaitingForEvidence,
    PlanningNuclei,
    PlanReady,
    GeneratingGuidance,
    Complete,
}

/// Etapa do pipeline que produziu uma entrada do painel "Atividade da IA".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AiTimelineOrigin {
    /// Planejamento do Nuclei, antes da varredura.
    Planning,
    /// Análise dos achados e resumo final da IA.
    Ai,
    /// Agente de código, que localiza a origem dos achados.
    Code,
}

impl AiTimelineOrigin {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Planning => "planejamento",
            Self::Ai => "IA",
            Self::Code => "código",
        }
    }
}

/// Uma ação da IA com o horário local em que foi observada na TUI.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AiTimelineEntry {
    pub time: String,
    pub origin: AiTimelineOrigin,
    pub text: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SettingsField {
    Provider,
    BaseUrl,
    ApiKey,
    Model,
    Timeout,
    Retries,
    RemoteConsent,
    FallbackEnabled,
    FallbackBaseUrl,
    FallbackModel,
    /// Diretório do projeto analisado pelo agente de código (issue #76).
    ///
    /// Fica ao lado do provedor porque decide **o que** o agente pode ler:
    /// escondê-lo tornaria invisível uma mudança de escopo da análise.
    ProjectDir,
}

impl SettingsField {
    /// Campos que aceitam texto digitado. `ProjectDir` entra na lista porque o
    /// caminho é editável e validado no salvamento, como os demais.
    pub fn is_text(self) -> bool {
        matches!(
            self,
            SettingsField::BaseUrl
                | SettingsField::ApiKey
                | SettingsField::Model
                | SettingsField::Timeout
                | SettingsField::Retries
                | SettingsField::FallbackBaseUrl
                | SettingsField::FallbackModel
                | SettingsField::ProjectDir
        )
    }

    pub fn is_toggle(self) -> bool {
        matches!(
            self,
            SettingsField::RemoteConsent | SettingsField::FallbackEnabled
        )
    }
}

pub struct ToolItem {
    pub tool: ToolManifest,
    pub runner: RunnerKind,
    pub selected: bool,
    /// Motivo curto da recomendação do perfil do projeto
    /// (`project_profile`); `None` quando a seleção não veio de recomendação.
    pub recommendation: Option<&'static str>,
    /// Estado real da ferramenta no pipeline: não há porcentagem sintética
    /// porque o orquestrador só emite `ToolStarted` e `ToolFinished`.
    pub status: ToolStatus,
}

pub(crate) enum RunEvent {
    ToolStarted(usize),
    /// O container em execução mudou de estado por pausa, retomada ou
    /// cancelamento pedido pelo usuário.
    ToolControl(RunControl),
    ToolLog(String),
    AiDecisionStarted,
    AiDecisionFinished(DecisionRecord),
    ToolFinished {
        index: usize,
        execution: Box<SecurityTool>,
    },
    /// Os parsers concluíram `build_findings`: os achados existem de fato.
    FindingsBuilt {
        count: usize,
    },
    AnalysisProgress {
        elapsed_secs: u64,
    },
    CodeAgent(crate::code_agent::progress::CodeAgentEvent),
    AuditFinished {
        files_scanned: usize,
        findings: usize,
        limitation: Option<String>,
    },
    /// Linha de resumo da correlação e do enriquecimento CVE/NVD.
    EnrichmentSummary(String),
    /// Fim da explicação RAG pedida no detalhe do achado (issue #109).
    RagExplanationFinished {
        finding_index: usize,
        result: Box<crate::cyberrag::service::ExplanationResult>,
    },
    Completed {
        orchestrator: Box<Orchestrator>,
        audit_log: Result<PathBuf, String>,
    },
}

const CODE_TRAIL_LIMIT: usize = 200;

/// Retenção do painel "Atividade da IA": uma execução longa não pode crescer
/// sem limite, e as entradas antigas saem primeiro.
const AI_TIMELINE_LIMIT: usize = 500;

/// Ordem de exibição dos achados, recalculada apenas quando a sequência de
/// severidades muda.
///
/// O índice é a única coisa memoizada: o vetor de achados do orquestrador pode
/// continuar mudando de conteúdo sem invalidar a ordem, porque dentro de cada
/// severidade a ordem do pipeline é preservada e não depende do texto.
#[derive(Default)]
struct FindingsOrder {
    signature: u64,
    indices: Vec<usize>,
}

impl FindingsOrder {
    fn refresh(&mut self, findings: &[Vulnerability]) {
        let signature = findings.iter().fold(0u64, |acc, finding| {
            acc.wrapping_mul(31)
                .wrapping_add(severity_rank(finding.severity) as u64 + 1)
        });
        if signature == self.signature && self.indices.len() == findings.len() {
            return;
        }
        self.signature = signature;
        self.indices = (0..findings.len()).collect();
        self.indices
            .sort_by_key(|index| severity_rank(findings[*index].severity));
    }
}

pub struct AppState {
    pub config: Configuration,
    pub code_agent_trail: Vec<crate::code_agent::progress::CodeAgentEvent>,
    pub code_agent_current: Option<String>,
    pub orchestrator: Orchestrator,
    pub agent: AIAgent,
    pub step: AppStep,
    pub screen_area: Rect,
    pub should_quit: bool,
    /// `false` libera o mouse para a seleção nativa do terminal.
    pub mouse_capture: bool,
    pub tick: u64,
    pub spinner_idx: usize,
    pub tools: Vec<ToolItem>,
    /// Assinatura do projeto em que a pré-seleção foi aplicada: evita reaplicar
    /// a recomendação por quadro e preserva o ajuste manual do usuário.
    pub(crate) tool_preselection: Option<PathBuf>,
    /// Lista explícita em `config.active_tools` desliga a recomendação do perfil.
    pub(crate) tool_preselection_enabled: bool,
    /// Resumo do perfil do projeto exibido na tela de Ferramentas.
    pub project_profile_summary: Option<String>,
    pub tool_cursor: usize,
    pub tool_scroll: usize,
    pub tool_visible_height: usize,
    pub exec_current: usize,
    pub exec_tick: u64,
    /// Início da execução atual; `None` fora de uma varredura.
    pub run_started_at: Option<std::time::Instant>,
    /// Buffer do log de execução; toda mutação passa por `push_exec_log`,
    /// `set_exec_logs` ou `clear_exec_logs` para as medidas seguirem alinhadas.
    exec_logs: Vec<String>,
    /// Linhas visuais de cada entrada do log na largura de `log_rows_width`.
    log_rows: Vec<u32>,
    /// Soma de `log_rows`: total de linhas visuais do buffer.
    log_rows_total: usize,
    /// Largura em que `log_rows` foi medido.
    log_rows_width: u16,
    pub log_scroll: usize,
    pub log_visible_height: usize,
    /// Largura interna usada na última renderização do log (para medir a quebra).
    pub log_width: u16,
    /// Total de linhas visuais do log após a quebra automática do `Paragraph`.
    pub log_total_lines: usize,
    /// Auto-follow do final do log; desligado quando o usuário sobe no histórico.
    pub log_follow: bool,
    pub analysis_phase: AnalysisPhase,
    /// Quantidade de achados já construída pelos parsers no pipeline real.
    pub analysis_findings: usize,
    pub analysis_wait_secs: u64,
    pub ai_activity: AiActivity,
    pub ai_decision: Option<DecisionRecord>,
    /// Painel ao vivo da atividade da IA, alimentado pelos eventos do pipeline.
    pub ai_timeline: Vec<AiTimelineEntry>,
    pub show_ai_timeline: bool,
    pub ai_timeline_scroll: usize,
    /// Limite de rolagem medido na última renderização do painel.
    pub ai_timeline_max_scroll: usize,
    /// Auto-follow do fim do painel; desligado quando o usuário rola para cima.
    pub ai_timeline_follow: bool,
    pub result_cursor: usize,
    pub result_scroll: usize,
    pub severity_filter: Option<crate::domain::Severity>,
    pub result_detail_vuln: Option<usize>,
    pub detail_code_preview: Option<crate::tui::code_preview::CodePreview>,
    /// Raiz usada para ler a prévia; separada do config para o replay não
    /// misturar o projeto atual com o projeto do scan aberto.
    pub results_project_dir: Option<PathBuf>,
    /// Explicação RAG por achado, exibida no detalhe (issue #109).
    pub rag_results: std::collections::BTreeMap<usize, crate::cyberrag::service::ExplanationResult>,
    /// Achado com explicação em andamento.
    pub rag_pending: Option<usize>,
    pub detail_scroll: usize,
    pub detail_max_scroll: usize,
    pub md_exported: bool,
    pub exported_report_path: Option<PathBuf>,
    /// Caminho do PDF gerado junto com o Markdown (REQ18).
    pub exported_pdf_path: Option<PathBuf>,
    pub show_report_viewer: bool,
    pub report_content: String,
    pub report_scroll: usize,
    pub report_max_scroll: usize,
    pub show_trace_overlay: bool,
    pub show_didactic: bool,
    pub didactic_scroll: usize,
    pub didactic_max_scroll: usize,
    pub show_settings: bool,
    pub settings_field: SettingsField,
    /// Memória da ordem de exibição dos achados (evita reordenar por quadro).
    findings_order: RefCell<FindingsOrder>,
    pub settings_provider_idx: usize,
    pub settings_input_base_url: String,
    pub settings_input_api_key: String,
    pub settings_input_model: String,
    pub settings_input_timeout: String,
    pub settings_input_retries: String,
    pub settings_remote_consent: bool,
    pub settings_fallback_enabled: bool,
    pub settings_input_fallback_base_url: String,
    pub settings_input_fallback_model: String,
    pub settings_input_project_dir: String,
    pub settings_api_key_touched: bool,
    pub settings_error: Option<String>,
    /// Assistente de primeira execução: Some quando o operador sai ou conclui.
    pub onboarding: Option<crate::config::onboarding::OnboardingState>,
    pub onboarding_cursor: usize,
    /// Falha de gravação do assistente, exibida na própria tela.
    pub onboarding_error: Option<String>,
    pub(crate) onboarding_probe: Option<Arc<dyn crate::config::environment::OnboardingProbe>>,
    pub(crate) onboarding_sender:
        Option<mpsc::Sender<crate::tui::state_onboarding::OnboardingEvent>>,
    pub(crate) onboarding_events:
        Option<mpsc::Receiver<crate::tui::state_onboarding::OnboardingEvent>>,
    pub(crate) onboarding_task: Option<tokio::task::JoinHandle<()>>,
    /// A sondagem do ambiente só dispara uma vez, no laço assíncrono.
    pub(crate) onboarding_probe_pending: bool,
    /// Gravador da configuração concluída; trocável para não tocar a máquina.
    pub(crate) onboarding_persister: Box<dyn crate::config::onboarding::OnboardingPersister>,
    /// Problema de configuracao detectado na abertura da TUI, antes de qualquer
    /// execucao. Separado de `settings_error`: nasce do carregamento, nao de uma
    /// tentativa de salvar, e continua valendo ate a proxima edicao.
    pub config_warning: Option<String>,
    pub llm_warning: Option<String>,
    pub audit_log_path: Option<PathBuf>,
    pub history: crate::orchestrator::scan_logger::ScanHistory,
    pub history_dir: PathBuf,
    pub splash_recent_cursor: usize,
    pub(crate) history_refresh_pending: bool,
    pub history_cursor: usize,
    pub history_scroll: usize,
    pub history_detail: Option<crate::orchestrator::scan_logger::ScanMetadata>,
    pub history_detail_scroll: usize,
    pub history_detail_max_scroll: usize,
    pub history_error: Option<String>,
    pub history_return_step: AppStep,
    /// Primeiro erro por natureza, usado nas linhas de status resumidas.
    pub run_error: Option<String>,
    /// Aviso de indisponibilidade do enriquecimento CVE/NVD, exibido na TUI.
    pub enrichment_warning: Option<String>,
    /// Todas as ocorrências da execução, na ordem em que foram registradas.
    pub run_issues: Vec<RunIssue>,
    pub exec_cancelled: bool,
    /// Execução pausada com `podman pause`; a retomada usa `podman unpause`.
    pub exec_paused: bool,
    pub show_help_overlay: bool,
    pub show_command_palette: bool,
    pub command_cursor: usize,
    pub settings_scroll: usize,
    /// Campo de texto aberto para digitação. Diferenciar "focado" de "editando"
    /// é o que permite `esc` sair do campo sem descartar o rascunho inteiro.
    pub settings_editing: Option<SettingsField>,
    /// Formulário desenhado em duas colunas na última renderização; as setas
    /// verticais andam dentro da coluna e as horizontais trocam de coluna.
    pub settings_two_columns: bool,
    pub focus: FocusTarget,
    pub settings_return_focus: FocusTarget,
    pub overlay_return_focus: FocusTarget,
    pub didactic_return_focus: FocusTarget,
    pub hit_regions: Vec<HitRegion>,
    /// Última posição do mouse, usada só no realce de hover; nunca move o foco.
    pub mouse_position: Option<(u16, u16)>,
    run_receiver: Option<mpsc::Receiver<RunEvent>>,
    run_task: Option<JoinHandle<()>>,
    pub(crate) rag_receiver: Option<mpsc::Receiver<RunEvent>>,
    pub(crate) rag_task: Option<JoinHandle<()>>,
    /// Linhas de log descartadas por saturação do canal (política de drop).
    log_drop_counter: Arc<AtomicU64>,
}

impl AppState {
    /// Inicializa o estado da TUI validando a configuração de ferramentas; uma
    /// configuração inválida impede a entrada na interface com a mensagem
    /// acionável do registry.
    pub fn new(config: Configuration) -> anyhow::Result<Self> {
        let orchestrator = Orchestrator::new(config.clone())?;
        let agent = orchestrator.agent_handle();

        let tools = orchestrator
            .registry
            .tools()
            .iter()
            .map(|registered| ToolItem {
                tool: registered.manifest.clone(),
                runner: registered.runner,
                selected: selected_from_active_tools(
                    &config.active_tools,
                    &registered.manifest.name,
                ),
                recommendation: None,
                status: ToolStatus::Pending,
            })
            .collect();
        // Lista explícita no arquivo de configuração é do usuário: a
        // recomendação do perfil não a substitui.
        let tool_preselection_enabled = config.active_tools.is_empty();

        let (provider_idx, base_url, api_key, model) = {
            let llm = &config.llm;
            let idx = llm.provider.index();
            (
                idx,
                llm.base_url.clone(),
                llm.api_key.clone(),
                llm.model.clone(),
            )
        };
        let timeout = config.llm.timeout_secs.to_string();
        let retries = config.llm.max_retries.to_string();
        let remote_consent = config.llm.remote_consent;
        let fallback_enabled = config.llm.fallback_enabled;
        let fallback_base_url = config.llm.fallback_base_url.clone();
        let fallback_model = config.llm.fallback_model.clone();
        let project_dir = config
            .project_dir
            .clone()
            .unwrap_or_else(|| config.effective_project_dir().display().to_string());

        Ok(Self {
            config_warning: None,
            code_agent_trail: Vec::new(),
            code_agent_current: None,
            config,
            orchestrator,
            agent,
            step: AppStep::Splash,
            screen_area: Rect::default(),
            should_quit: false,
            mouse_capture: true,
            tick: 0,
            spinner_idx: 0,
            tools,
            tool_preselection: None,
            tool_preselection_enabled,
            project_profile_summary: None,
            tool_cursor: 0,
            tool_scroll: 0,
            tool_visible_height: 8,
            exec_current: 0,
            exec_tick: 0,
            run_started_at: None,
            exec_logs: Vec::new(),
            log_rows: Vec::new(),
            log_rows_total: 0,
            log_rows_width: 80,
            log_scroll: 0,
            log_visible_height: 20,
            log_width: 80,
            log_total_lines: 0,
            log_follow: true,
            analysis_phase: AnalysisPhase::Scanning,
            analysis_findings: 0,
            analysis_wait_secs: 0,
            ai_activity: AiActivity::WaitingForEvidence,
            ai_decision: None,
            ai_timeline: Vec::new(),
            show_ai_timeline: false,
            ai_timeline_scroll: 0,
            ai_timeline_max_scroll: 0,
            ai_timeline_follow: true,
            result_cursor: 0,
            result_scroll: 0,
            severity_filter: None,
            result_detail_vuln: None,
            detail_code_preview: None,
            results_project_dir: None,
            detail_scroll: 0,
            detail_max_scroll: 0,
            md_exported: false,
            exported_report_path: None,
            exported_pdf_path: None,
            show_report_viewer: false,
            report_content: String::new(),
            report_scroll: 0,
            report_max_scroll: 0,
            show_trace_overlay: false,
            show_didactic: false,
            didactic_scroll: 0,
            didactic_max_scroll: 0,
            show_settings: false,
            settings_field: SettingsField::Provider,
            findings_order: RefCell::new(FindingsOrder::default()),
            settings_provider_idx: provider_idx,
            settings_input_base_url: base_url,
            settings_input_api_key: api_key,
            settings_input_model: model,
            settings_input_timeout: timeout,
            settings_input_retries: retries,
            settings_remote_consent: remote_consent,
            settings_fallback_enabled: fallback_enabled,
            settings_input_fallback_base_url: fallback_base_url,
            settings_input_fallback_model: fallback_model,
            settings_input_project_dir: project_dir,
            settings_api_key_touched: false,
            settings_error: None,
            onboarding: None,
            onboarding_cursor: 0,
            onboarding_error: None,
            onboarding_probe: None,
            onboarding_sender: None,
            onboarding_events: None,
            onboarding_task: None,
            onboarding_probe_pending: false,
            onboarding_persister: Box::new(crate::config::onboarding::SystemOnboardingPersister),
            llm_warning: None,
            audit_log_path: None,
            history: crate::orchestrator::scan_logger::ScanHistory::default(),
            history_dir: crate::orchestrator::scan_logger::scans_dir(),
            splash_recent_cursor: 0,
            history_refresh_pending: false,
            history_cursor: 0,
            history_scroll: 0,
            history_detail: None,
            history_detail_scroll: 0,
            history_detail_max_scroll: 0,
            history_error: None,
            history_return_step: AppStep::Splash,
            run_error: None,
            enrichment_warning: None,
            run_issues: Vec::new(),
            exec_cancelled: false,
            exec_paused: false,
            show_help_overlay: false,
            show_command_palette: false,
            command_cursor: 0,
            settings_scroll: 0,
            settings_editing: None,
            settings_two_columns: true,
            focus: FocusTarget::SplashTarget,
            settings_return_focus: FocusTarget::SplashTarget,
            overlay_return_focus: FocusTarget::SplashTarget,
            didactic_return_focus: FocusTarget::SplashTarget,
            hit_regions: Vec::new(),
            mouse_position: None,
            run_receiver: None,
            run_task: None,
            rag_results: std::collections::BTreeMap::new(),
            rag_pending: None,
            rag_receiver: None,
            rag_task: None,
            log_drop_counter: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn begin_frame(&mut self, area: Rect) {
        self.screen_area = area;
        self.hit_regions.clear();
    }

    pub fn register_hit_region(&mut self, area: Rect, action: SemanticAction) {
        if area.width > 0 && area.height > 0 {
            self.hit_regions.push(HitRegion { area, action });
        }
    }

    pub fn action_at(&self, column: u16, row: u16) -> Option<SemanticAction> {
        self.hit_regions
            .iter()
            .rev()
            .find(|region| region.contains(column, row))
            .map(|region| region.action.clone())
    }

    pub fn set_mouse_position(&mut self, position: Option<(u16, u16)>) {
        self.mouse_position = position;
    }

    /// Hover na tela base: desligado com uma camada sobreposta aberta, que
    /// limpou as regiões clicáveis e passou a ser a única superfície de clique.
    pub fn mouse_over(&self, area: Rect) -> bool {
        !self.overlay_on_top() && self.pointer_within(area)
    }

    /// Hover dentro da camada sobreposta, que recebe o clique enquanto aberta.
    pub fn mouse_over_overlay(&self, area: Rect) -> bool {
        self.pointer_within(area)
    }

    fn overlay_on_top(&self) -> bool {
        self.show_help_overlay
            || self.show_command_palette
            || self.show_report_viewer
            || self.show_trace_overlay
    }

    fn pointer_within(&self, area: Rect) -> bool {
        let Some((column, row)) = self.mouse_position else {
            return false;
        };
        area.width > 0
            && area.height > 0
            && column >= area.x
            && column < area.x.saturating_add(area.width)
            && row >= area.y
            && row < area.y.saturating_add(area.height)
    }

    pub fn mode(&self) -> ExecutionType {
        self.config.execution_type
    }

    pub fn set_mode(&mut self, mode: ExecutionType) {
        self.config.execution_type = mode;
    }

    /// Rótulo do estado real do container, lido do canal de controle.
    ///
    /// TUI e executor compartilham o canal, então o rótulo reflete o que o
    /// `podman pause`/`unpause` fez, não a intenção do usuário.
    pub fn run_control_label(&self) -> &'static str {
        self.orchestrator.control.label()
    }

    pub fn spinner_char(&self) -> &str {
        const SPINNERS: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        SPINNERS[self.spinner_idx % SPINNERS.len()]
    }

    /// Achados na ordem de leitura da tela: críticos primeiro (REQ15),
    /// preservando a ordem do pipeline dentro de cada severidade.
    ///
    /// Só a TUI é ordenada; o relatório usa a ordem original do pipeline.
    /// A ordem é memoizada por assinatura de severidades porque as telas de
    /// Resultados chamam este método várias vezes por quadro: reordenar e
    /// clonar todos os achados a cada chamada custava o quadro inteiro.
    pub fn vulnerabilities(&self) -> Vec<&Vulnerability> {
        let findings = &self.orchestrator.findings;
        let mut order = self.findings_order.borrow_mut();
        order.refresh(findings);
        order
            .indices
            .iter()
            .map(|index| &findings[*index])
            .collect()
    }

    /// Carrega a prévia do código do achado aberto, uma vez por abertura.
    pub fn load_detail_preview(&mut self, index: usize) {
        self.detail_code_preview = None;
        let Some((file, line)) = self
            .vulnerabilities()
            .get(index)
            .and_then(|finding| finding.code_location.as_ref())
            .map(|location| (location.file.clone(), location.line))
        else {
            return;
        };
        let Some(root) = self.results_project_dir.clone() else {
            return;
        };
        self.detail_code_preview = Some(crate::tui::code_preview::CodePreview::load(
            index, &root, &file, line,
        ));
    }

    /// Carrega um scan concluído direto na tela de resultados.
    pub fn load_replayed_scan(
        &mut self,
        metadata: crate::orchestrator::scan_logger::ScanMetadata,
    ) -> anyhow::Result<()> {
        let mut findings = Vec::with_capacity(metadata.findings.len());
        for value in metadata.findings {
            let mut finding: Vulnerability = serde_json::from_value(value).map_err(|error| {
                anyhow::anyhow!("achado inválido no scan {}: {error}", metadata.scan_id)
            })?;
            // Logs antigos podem ter uma localização alucinada para porta/serviço
            // de rede; a origem não existe no projeto, então não a exibimos.
            if finding.is_network_port_finding() && finding.code_location.is_some() {
                finding.code_location = None;
                finding.code_remediation.clear();
            }
            findings.push(finding);
        }
        self.config.target_url = metadata.target_url.clone();
        if !metadata.code_project_dir.is_empty() {
            self.config.project_dir = Some(metadata.code_project_dir.clone());
        }
        self.results_project_dir = if metadata.code_project_dir.is_empty() {
            self.config.project_dir.clone().map(PathBuf::from)
        } else {
            Some(PathBuf::from(&metadata.code_project_dir))
        };
        self.detail_code_preview = None;
        self.config.active_tools = metadata
            .tools_executed
            .iter()
            .map(|tool| tool.tool_name.clone())
            .collect();
        self.orchestrator.findings = findings;
        self.rag_results.clear();
        self.rag_pending = None;
        for mut result in metadata.rag_explanations {
            restore_rag_example(&mut result);
            if self
                .orchestrator
                .findings
                .get(result.finding_index)
                .is_some_and(Vulnerability::is_network_port_finding)
            {
                result.example = None;
            }
            self.rag_results.insert(result.finding_index, result);
        }
        self.orchestrator.rag_explanations = self.rag_results.values().cloned().collect();
        self.orchestrator.decision_history = metadata.decisions.clone();
        self.orchestrator.enrichment = metadata.enrichment.clone();
        self.orchestrator.last_log =
            format!("Execução recuperada do histórico {}", metadata.scan_id);
        self.agent.last_analysis = metadata.agent_analysis.clone();
        self.audit_log_path = Some(
            crate::orchestrator::scan_logger::scans_dir()
                .join(format!("{}.json", metadata.scan_id)),
        );
        self.llm_warning = metadata.llm_failure_reason.clone();
        self.ai_timeline.clear();
        for decision in &metadata.decisions {
            self.push_ai_timeline(AiTimelineOrigin::Planning, decision_summary(decision));
        }
        if let Some(summary) = metadata.agent_analysis.lines().next() {
            self.push_ai_timeline(
                AiTimelineOrigin::Ai,
                format!(
                    "análise concluída · {}",
                    crate::tui::chrome::truncate_width(summary, 200)
                ),
            );
        }
        for call in &metadata.code_tool_calls {
            self.push_ai_timeline(
                AiTimelineOrigin::Code,
                format!(
                    "{} · achado #{} · {}",
                    call.tool,
                    call.finding_index + 1,
                    crate::tui::chrome::truncate_width(&call.summary, 160)
                ),
            );
        }
        self.ai_timeline_follow = true;
        self.ai_timeline_scroll = 0;
        self.step = AppStep::Results;
        self.focus = FocusTarget::ResultsList;
        self.result_cursor = 0;
        self.result_scroll = 0;
        self.severity_filter = None;
        self.result_detail_vuln = None;
        self.run_started_at = None;
        self.md_exported = false;
        self.exported_report_path = None;
        self.exported_pdf_path = None;
        Ok(())
    }

    /// Índices visíveis, na mesma ordem de `vulnerabilities()`.
    pub fn visible_vulnerability_indices(&self) -> Vec<usize> {
        let filter = self.severity_filter;
        self.vulnerabilities()
            .into_iter()
            .enumerate()
            .filter(|(_, item)| match filter {
                Some(severity) => item.severity == severity,
                None => true,
            })
            .map(|(index, _)| index)
            .collect()
    }

    /// Registra uma ocorrência preservando todas as anteriores.
    ///
    /// `run_error` fica com o primeiro erro por natureza; `run_issues`, com a
    /// lista completa exibida na Execução e no resumo de Resultados.
    pub fn record_run_issue(&mut self, scope: RunIssueScope, detail: impl Into<String>) {
        let detail = detail.into();
        self.run_issues.push(RunIssue {
            scope,
            detail: detail.clone(),
        });
        if !scope.is_warning() {
            self.run_error.get_or_insert(detail);
        }
    }

    pub fn clear_run_issues(&mut self) {
        self.run_issues.clear();
        self.run_error = None;
    }

    pub fn has_run_issues(&self) -> bool {
        !self.run_issues.is_empty()
    }

    /// Linhas de log perdidas por saturação do canal (política de drop).
    pub fn dropped_log_lines(&self) -> u64 {
        self.log_drop_counter.load(Ordering::Relaxed)
    }

    /// Log de saída em leitura; o buffer é privado para as medidas de quebra de
    /// linha não saírem de sincronia.
    pub fn exec_logs(&self) -> &[String] {
        &self.exec_logs
    }

    /// Acrescenta uma linha ao log, medindo a quebra dela e aplicando o limite
    /// de retenção.
    pub fn push_exec_log(&mut self, line: String) {
        if self.log_rows.len() == self.exec_logs.len() {
            let rows = log_line_rows(&line, self.log_rows_width);
            self.log_rows.push(rows);
            self.log_rows_total += rows as usize;
        }
        self.exec_logs.push(line);
        self.apply_log_limit();
    }

    /// Substitui o buffer do log por inteiro nos testes; em produção o buffer é
    /// preenchido pelos eventos do executor.
    ///
    /// O total exibido é recalculado na próxima renderização, como antes.
    #[cfg(test)]
    pub fn set_exec_logs(&mut self, lines: Vec<String>) {
        self.log_rows = lines
            .iter()
            .map(|line| log_line_rows(line, self.log_rows_width))
            .collect();
        self.log_rows_total = self.log_rows.iter().map(|rows| *rows as usize).sum();
        self.exec_logs = lines;
    }

    pub fn clear_exec_logs(&mut self) {
        self.exec_logs.clear();
        self.log_rows.clear();
        self.log_rows_total = 0;
        self.log_total_lines = 0;
    }

    /// Desconta do offset e do total as linhas que saíram, na mesma unidade
    /// visual usada pela renderização.
    fn apply_log_limit(&mut self) {
        const MAX_EXEC_LOGS: usize = 5000;
        let overflow = self.exec_logs.len().saturating_sub(MAX_EXEC_LOGS);
        if overflow == 0 {
            return;
        }
        // A medida do descarte continua saindo do próprio vetor, na largura da
        // última renderização; o total memoizado é recalculado no próximo
        // quadro por `sync_log_rows`.
        let removed_rows = visual_line_count(&self.exec_logs[..overflow], self.log_width);
        self.log_rows.drain(..self.log_rows.len().min(overflow));
        self.exec_logs.drain(..overflow);
        self.log_rows_total = self.log_rows_total.saturating_sub(removed_rows);
        self.log_total_lines = self.log_total_lines.saturating_sub(removed_rows);
        if !self.log_follow {
            self.log_scroll = self.log_scroll.saturating_sub(removed_rows);
        }
    }

    /// Reconcilia as medidas com o buffer e a largura atuais; é a fonte de
    /// `log_total_lines`, com o mesmo valor de `Paragraph::line_count`.
    pub fn sync_log_rows(&mut self, width: u16) {
        let width = width.max(1);
        if width != self.log_rows_width || self.log_rows.len() != self.exec_logs.len() {
            self.log_rows_width = width;
            self.log_rows = self
                .exec_logs
                .iter()
                .map(|line| log_line_rows(line, width))
                .collect();
        }
        self.log_rows_total = self.log_rows.iter().map(|rows| *rows as usize).sum();
        self.log_total_lines = self.log_rows_total;
    }

    /// Faixa de linhas do log que cobre `viewport_rows` a partir da linha
    /// visual `first_row`: (início, fim, deslocamento dentro do início).
    ///
    /// A varredura começa no fim porque o log abre no tail: desenhar só a
    /// janela pinta os mesmos glifos sem reprocessar o buffer inteiro a cada
    /// quadro.
    pub fn log_window(&self, first_row: usize, viewport_rows: usize) -> (usize, usize, u16) {
        if self.log_rows.is_empty() {
            return (0, 0, 0);
        }
        let first_row = first_row.min(self.log_rows_total.saturating_sub(1));
        let mut start = 0usize;
        let mut offset = 0usize;
        let mut row = self.log_rows_total;
        for index in (0..self.log_rows.len()).rev() {
            let count = self.log_rows[index] as usize;
            let before = row.saturating_sub(count);
            if before <= first_row {
                start = index;
                offset = first_row - before;
                break;
            }
            row = before;
        }
        let mut covered = self.log_rows[start] as usize;
        let mut end = start + 1;
        while end < self.log_rows.len() && covered < offset + viewport_rows {
            covered += self.log_rows[end] as usize;
            end += 1;
        }
        (start, end, offset as u16)
    }

    /// Quantas ferramentas selecionadas já chegaram a um estado terminal real
    /// (`ToolFinished` emitido pelo orquestrador), contando as que falharam.
    pub fn finished_tools(&self) -> (usize, usize) {
        let finished = self
            .tools
            .iter()
            .filter(|tool| {
                tool.selected && matches!(tool.status, ToolStatus::Done | ToolStatus::Failed)
            })
            .count();
        let total = self.tools.iter().filter(|tool| tool.selected).count();
        (finished, total)
    }

    pub fn ai_summary(&self) -> &str {
        if self.agent.last_analysis.is_empty() {
            "[A análise por IA será executada após a varredura]"
        } else {
            &self.agent.last_analysis
        }
    }

    #[allow(dead_code)]
    pub fn agent_last_analysis(&self) -> &str {
        self.ai_summary()
    }

    pub fn run_elapsed_label(&self) -> String {
        self.run_started_at.map_or_else(
            || "00:00".to_string(),
            |start| format_elapsed(start.elapsed().as_secs()),
        )
    }

    pub fn tick(&mut self) {
        self.tick += 1;
        self.spinner_idx = (self.spinner_idx + 1) % 10;
        if self.has_blocking_layer() {
            return;
        }
        match self.mode() {
            ExecutionType::Auto => self.advance_auto(),
            ExecutionType::Assisted => self.advance_assisted(),
        }
    }

    /// Drena os eventos do pipeline real: cada transição de tela acontece no
    /// evento que a justifica, não em contagem de ticks. O drain roda mesmo com
    /// camada sobreposta aberta, para o canal não acumular eventos.
    pub async fn step_tick(&mut self) {
        self.spawn_onboarding_probe();
        self.poll_onboarding_events().await;
        self.process_run_events().await;
        let had_pending = self.rag_pending;
        self.process_rag_events();
        if had_pending.is_some() && self.rag_pending.is_none() {
            self.persist_rag_explanation();
        }
    }

    /// Indica se há uma camada sobreposta capturando a interação.
    ///
    /// Com uma aberta, `p` e `c` são ignorados para não virarem ação no overlay.
    pub fn has_blocking_layer(&self) -> bool {
        self.show_settings
            || self.onboarding.is_some()
            || self.show_help_overlay
            || self.show_command_palette
            || self.show_report_viewer
            || self.show_trace_overlay
            || self.show_ai_timeline
    }

    async fn process_run_events(&mut self) {
        let Some(mut receiver) = self.run_receiver.take() else {
            return;
        };
        let mut completed = false;
        let mut disconnected = false;
        loop {
            let event = match receiver.try_recv() {
                Ok(event) => event,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            };
            match event {
                RunEvent::ToolStarted(index) => {
                    self.exec_current = index;
                    self.tools[index].status = ToolStatus::Running;
                }
                RunEvent::ToolControl(control) => self.apply_run_control(control),
                RunEvent::ToolLog(line) => {
                    let prefix = self
                        .tools
                        .iter()
                        .find(|tool| tool.status == ToolStatus::Running)
                        .map(|tool| format!("[{}] ", tool.tool.name))
                        .unwrap_or_default();
                    let line = compact_operational_log(&line);
                    for part in line.split('\n') {
                        if part.trim().is_empty() {
                            continue;
                        }
                        self.push_exec_log(format!("{prefix}{part}"));
                    }
                }
                RunEvent::AiDecisionStarted => {
                    self.ai_activity = AiActivity::PlanningNuclei;
                    self.push_ai_timeline(
                        AiTimelineOrigin::Planning,
                        "planejando o uso do Nuclei…",
                    );
                }
                RunEvent::AiDecisionFinished(decision) => {
                    self.ai_activity = AiActivity::PlanReady;
                    self.push_ai_timeline(AiTimelineOrigin::Planning, decision_summary(&decision));
                    self.ai_decision = Some(decision);
                }
                RunEvent::ToolFinished { index, execution } => {
                    let succeeded = execution.execution_error.is_none()
                        && matches!(execution.status.as_str(), "succeeded" | "skipped");
                    self.tools[index].status = if succeeded {
                        ToolStatus::Done
                    } else {
                        ToolStatus::Failed
                    };
                    if let Some(error) = &execution.execution_error {
                        self.record_run_issue(RunIssueScope::Tool, error.clone());
                        self.push_exec_log(format!(
                            "[{}] FALHA após {:.1}s: {}",
                            self.tools[index].tool.name,
                            execution.duration_ms as f64 / 1_000.0,
                            error
                        ));
                    } else {
                        self.push_exec_log(format!(
                            "[{}] OK em {:.1}s",
                            self.tools[index].tool.name,
                            execution.duration_ms as f64 / 1_000.0
                        ));
                    }
                    self.orchestrator.execution_history.push(*execution);
                }
                RunEvent::FindingsBuilt { count } => {
                    // Os parsers terminaram: os achados existem de fato e a
                    // análise por IA é a próxima etapa real do pipeline.
                    self.analysis_phase = AnalysisPhase::Correlating;
                    self.analysis_findings = count;
                    if self.step == AppStep::Execution {
                        self.step = AppStep::Analysis;
                        self.focus = FocusTarget::AnalysisCancel;
                    }
                }
                RunEvent::AnalysisProgress { elapsed_secs } => {
                    self.ai_activity = AiActivity::GeneratingGuidance;
                    if self.analysis_phase == AnalysisPhase::Correlating {
                        self.analysis_phase = AnalysisPhase::Generating;
                    }
                    self.analysis_wait_secs = elapsed_secs;
                    if elapsed_secs % 10 == 0 {
                        self.push_exec_log(format!("[ia] análise em andamento… ({elapsed_secs}s)"));
                        self.push_ai_timeline(
                            AiTimelineOrigin::Ai,
                            format!("análise em andamento ({elapsed_secs}s)"),
                        );
                    }
                }
                RunEvent::CodeAgent(event) => self.push_code_agent(event),
                RunEvent::AuditFinished {
                    files_scanned,
                    findings,
                    limitation,
                } => {
                    self.push_exec_log(format!(
                        "[codigo] auditoria leu {files_scanned} arquivo(s) e produziu \
                         {findings} achado(s)"
                    ));
                    if let Some(limit) = limitation {
                        self.push_exec_log(format!("[codigo] cobertura parcial: {limit}"));
                    }
                }
                RunEvent::EnrichmentSummary(line) => {
                    // A indisponibilidade da NVD precisa ser visível na TUI,
                    // não silenciosa: a linha já carrega a causa em pt-BR.
                    self.push_exec_log(format!("[cve/nvd] {line}"));
                    if line.contains("indisponível") {
                        self.enrichment_warning = Some(line.clone());
                    }
                }
                // A explicação RAG usa canal próprio (`process_rag_events`).
                RunEvent::RagExplanationFinished { .. } => {}
                RunEvent::Completed {
                    orchestrator,
                    audit_log,
                } => {
                    self.orchestrator = *orchestrator;
                    let agent_history = self.orchestrator.agent.execution_history.clone();
                    for detail in &agent_history {
                        let detail = crate::utils::redaction::sanitize_text(detail);
                        self.push_exec_log(format!("[ia] {detail}"));
                        self.push_ai_timeline(AiTimelineOrigin::Ai, detail.clone());
                        // Ligação com o serviço de análise (issue #23): toda
                        // entrada de `agent.execution_history` vira ocorrência.
                        self.record_run_issue(RunIssueScope::Ai, detail);
                    }
                    self.llm_warning = agent_history
                        .first()
                        .map(|detail| crate::utils::redaction::sanitize_text(detail));
                    // Cada `ToolFinished` já registrou a falha da ferramenta; aqui o
                    // histórico final apenas confirma o estado exibido.
                    for execution in &self.orchestrator.execution_history {
                        if execution.execution_error.is_none() {
                            continue;
                        }
                        if let Some(tool) = self
                            .tools
                            .iter_mut()
                            .find(|tool| tool.tool.name == execution.tool_name)
                        {
                            tool.status = ToolStatus::Failed;
                        }
                    }
                    self.sync_agent_from_orchestrator();
                    match audit_log {
                        Ok(path) => {
                            self.push_exec_log(format!(
                                "[auditoria] Log salvo em {}",
                                path.display()
                            ));
                            self.audit_log_path = Some(path);
                        }
                        Err(error) => {
                            self.record_run_issue(RunIssueScope::Audit, error.clone());
                            self.push_exec_log(format!("[auditoria] FALHA ao salvar log: {error}"));
                        }
                    }
                    self.analysis_phase = AnalysisPhase::Complete;
                    self.ai_activity = AiActivity::Complete;
                    self.analysis_findings = self.orchestrator.findings.len();
                    // A análise terminou: os resultados já podem ser revisados.
                    self.step = AppStep::Results;
                    self.focus = FocusTarget::ResultsList;
                    self.history_refresh_pending = true;
                    completed = true;
                }
            }
        }
        self.follow_latest_log();
        if completed {
            self.run_task.take();
        } else if disconnected {
            // O `JoinHandle` do executor nunca é aguardado dentro do laço de
            // eventos: o canal já desconectou porque o executor terminou ou
            // foi abortado, e o diagnóstico vem do estado real das ferramentas.
            if let Some(task) = self.run_task.take() {
                task.abort();
            }
            let running = self
                .tools
                .iter()
                .find(|tool| tool.status == ToolStatus::Running)
                .map(|tool| tool.tool.name.clone());
            let detail = match running {
                Some(name) => format!("o executor encerrou durante a execução de {name}"),
                None => "o executor encerrou sem concluir a análise".to_string(),
            };
            self.record_run_issue(RunIssueScope::Executor, detail.clone());
            if let Some(tool) = self
                .tools
                .iter_mut()
                .find(|tool| tool.status == ToolStatus::Running)
            {
                tool.status = ToolStatus::Failed;
            }
            self.push_exec_log(format!("[executor] FALHA: {detail}"));
            self.step = AppStep::Results;
            self.focus = FocusTarget::ResultsList;
        } else {
            self.run_receiver = Some(receiver);
        }
    }

    /// Drena a explicação RAG pedida no detalhe (issue #109).
    fn process_rag_events(&mut self) {
        let Some(mut receiver) = self.rag_receiver.take() else {
            return;
        };
        let mut keep = true;
        loop {
            match receiver.try_recv() {
                Ok(RunEvent::RagExplanationFinished {
                    finding_index,
                    result,
                }) => {
                    self.apply_rag_result(finding_index, *result);
                    keep = false;
                    break;
                }
                Ok(_) => continue,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if self.rag_pending.is_some() {
                        self.rag_pending = None;
                        self.record_run_issue(
                            RunIssueScope::Ai,
                            "a explicação RAG encerrou sem resultado",
                        );
                    }
                    keep = false;
                    break;
                }
            }
        }
        if keep {
            self.rag_receiver = Some(receiver);
        } else {
            self.rag_task.take();
        }
    }

    /// Aplica o resultado da explicação na tela e no log estruturado.
    ///
    /// A gravação do log fica fora daqui: o teste do fluxo de memória não pode
    /// escrever no diretório de configuração do usuário.
    fn apply_rag_result(
        &mut self,
        finding_index: usize,
        result: crate::cyberrag::service::ExplanationResult,
    ) {
        self.rag_pending = None;
        self.push_exec_log(format!("[rag] {}", result.summary()));
        self.orchestrator.record_rag_explanation(&result);
        self.rag_results.insert(finding_index, result);
    }

    /// Re-grava o log do scan com as explicações RAG completas.
    ///
    /// Para um replay, atualiza o arquivo original em vez de criar um scan novo;
    /// assim a explicação salva reaparece sem gastar tokens na próxima abertura.
    fn persist_rag_explanation(&mut self) {
        let update = (|| -> anyhow::Result<()> {
            let Some(path) = self.audit_log_path.clone() else {
                self.orchestrator.persist_scan_log()?;
                return Ok(());
            };
            let mut metadata = crate::orchestrator::scan_logger::load_scan_log_from_file(&path)?;
            metadata.rag_explanations = self.orchestrator.rag_explanations.clone();
            metadata.rag_explanations_count = metadata.rag_explanations.len();
            if let Some(last) = metadata.rag_explanations.last() {
                metadata.rag_ontology_verdict =
                    crate::utils::redaction::sanitize_diagnostic(&last.verdict_summary());
                metadata.rag_failure_reason = last
                    .failure_reason
                    .as_deref()
                    .map(crate::utils::redaction::sanitize_diagnostic);
            }
            let parent = path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("log do scan sem diretório pai"))?
                .to_path_buf();
            crate::orchestrator::scan_logger::save_scan_log_to_dir(&metadata, &parent)?;
            Ok(())
        })();
        if let Err(error) = update {
            self.record_run_issue(
                RunIssueScope::Ai,
                format!("o log do scan não pôde ser regravado após a explicação: {error}"),
            );
        }
    }

    /// Reflete na tela o estado do container que o executor realmente aplicou.
    fn apply_run_control(&mut self, control: RunControl) {
        let index = self
            .tools
            .iter()
            .position(|tool| matches!(tool.status, ToolStatus::Running | ToolStatus::Paused));
        match control {
            RunControl::Running => {
                self.exec_paused = false;
                if let Some(tool) = index.map(|index| &mut self.tools[index]) {
                    tool.status = ToolStatus::Running;
                }
            }
            RunControl::Paused => {
                self.exec_paused = true;
                if let Some(tool) = index
                    .map(|index| &mut self.tools[index])
                    .filter(|tool| tool.status == ToolStatus::Running)
                {
                    tool.status = ToolStatus::Paused;
                }
            }
            RunControl::Cancelled => {
                self.exec_paused = false;
            }
        }
    }

    fn follow_latest_log(&mut self) {
        if !self.log_follow {
            return;
        }
        self.log_scroll = self.log_max_scroll();
    }

    /// Limite de scroll considerando as linhas visuais após a quebra automática.
    ///
    /// Antes do primeiro render `log_total_lines` é zero e a quantidade de
    /// entradas serve de piso, para nunca perder linhas.
    pub fn log_max_scroll(&self) -> usize {
        let total = self.log_total_lines.max(self.exec_logs.len());
        total
            .saturating_sub(self.log_visible_height.max(1))
            .min(u16::MAX as usize)
    }

    fn advance_auto(&mut self) {
        match self.step {
            AppStep::Splash => {}
            // O modo automático inicia a execução sozinho, mas nunca refaz uma
            // execução que o usuário acabou de cancelar: reiniciar é decisão
            // dele, e o cancelamento é registrado na auditoria.
            AppStep::ToolSelect if !self.exec_cancelled => self.start_selected_tools(),
            AppStep::ToolSelect | AppStep::Results => {}
            AppStep::Execution => {
                self.advance_execution();
            }
            // A tela de Análise é movida pelos eventos do pipeline real
            // (`FindingsBuilt` e `Completed`); nada a avançar por contagem.
            AppStep::Analysis => {}
            AppStep::History => {}
        }
    }

    fn advance_assisted(&mut self) {
        match self.step {
            AppStep::Execution => self.advance_execution(),
            AppStep::Analysis => self.advance_execution(),
            _ => {}
        }
    }

    /// Aplica a recomendação do perfil do projeto na seleção das ferramentas.
    ///
    /// Roda quando a tela de Ferramentas é montada e quando o projeto muda; a
    /// assinatura impede reaplicar por quadro, para o ajuste manual sobreviver.
    pub fn apply_tool_preselection(&mut self) {
        if !self.tool_preselection_enabled {
            return;
        }
        let project_dir = self.config.effective_project_dir();
        if self.tool_preselection.as_deref() == Some(project_dir.as_path()) {
            return;
        }
        self.tool_preselection = Some(project_dir.clone());
        match crate::project_profile::profile_project(&project_dir) {
            Some(profile) => {
                for tool in &mut self.tools {
                    match crate::project_profile::recommendation_for(&tool.tool.name, &profile) {
                        Some(recommendation) => {
                            tool.selected = recommendation.selected;
                            tool.recommendation = Some(recommendation.reason);
                        }
                        // Ferramenta fora do catálogo embutido: sem recomendação.
                        None => tool.recommendation = None,
                    }
                }
                self.project_profile_summary =
                    Some(crate::project_profile::summary_pt_br(&profile));
            }
            // Projeto inacessível: sem perfil, vale o comportamento de hoje.
            None => {
                for tool in &mut self.tools {
                    tool.selected = true;
                    tool.recommendation = None;
                }
                self.project_profile_summary = None;
            }
        }
    }

    /// Inicia a execução das ferramentas selecionadas: o catálogo já veio pronto
    /// do registry (`AppState::new`), então a listagem não espera nada quando a
    /// tela aparece.
    pub fn start_selected_tools(&mut self) {
        if self.step != AppStep::ToolSelect || !self.tools.iter().any(|tool| tool.selected) {
            return;
        }
        self.step = AppStep::Execution;
        self.focus = FocusTarget::ExecutionLogs;
        self.init_execution();
    }

    pub fn init_execution(&mut self) {
        for t in &mut self.tools {
            if t.selected {
                t.status = ToolStatus::Pending;
            }
        }
        self.exec_current = 0;
        self.exec_tick = 0;
        self.run_started_at = Some(std::time::Instant::now());
        self.results_project_dir = Some(self.config.effective_project_dir());
        self.detail_code_preview = None;
        self.clear_exec_logs();
        self.log_scroll = 0;
        self.log_follow = true;
        self.exec_cancelled = false;
        self.exec_paused = false;
        let registry = self.orchestrator.registry.clone();
        self.orchestrator = Orchestrator::with_registry(self.config.clone(), registry.clone());
        // A task de execução e a TUI compartilham o mesmo canal de controle,
        // para que a pausa e o cancelamento atinjam o container real.
        let control = self.orchestrator.control.clone();
        self.audit_log_path = None;
        self.clear_run_issues();
        self.llm_warning = None;

        self.analysis_phase = AnalysisPhase::Scanning;
        self.analysis_findings = 0;
        self.analysis_wait_secs = 0;
        self.ai_activity = AiActivity::WaitingForEvidence;
        self.ai_decision = None;
        self.ai_timeline.clear();
        self.ai_timeline_scroll = 0;
        self.ai_timeline_max_scroll = 0;
        self.ai_timeline_follow = true;
        self.show_ai_timeline = false;
        self.log_drop_counter.store(0, Ordering::Relaxed);

        let selected: Vec<_> = self
            .tools
            .iter()
            .enumerate()
            .filter(|(_, tool)| tool.selected)
            .map(|(index, tool)| (index, tool.tool.clone(), tool.runner))
            .collect();
        self.config.active_tools = selected
            .iter()
            .map(|(_, tool, _)| tool.name.to_string())
            .collect();
        let config = self.config.clone();
        let target = config.target_url.clone();
        let (sender, receiver) = mpsc::channel(RUN_EVENT_CAPACITY);
        self.run_receiver = Some(receiver);
        let dropped = Arc::clone(&self.log_drop_counter);
        self.run_task = Some(tokio::spawn(async move {
            let mut orchestrator = Orchestrator::with_registry(config, registry);
            // A task precisa do MESMO canal da TUI: cada `Orchestrator::new`
            // criaria o seu, e a pausa da tela nunca chegaria ao container.
            orchestrator.control = control.clone();
            let control_events = control.subscribe();
            for (index, tool, runner) in selected {
                let is_nuclei = runner == RunnerKind::Nuclei;
                if sender.send(RunEvent::ToolStarted(index)).await.is_err() {
                    return;
                }
                if is_nuclei && sender.send(RunEvent::AiDecisionStarted).await.is_err() {
                    return;
                }
                // Aplica o estado pendente (pausa ou cancelamento pedido antes
                // de a ferramenta começar) e reflete cada mudança na tela.
                let control_task = {
                    let sender = sender.clone();
                    let control_events = control_events.clone();
                    tokio::spawn(async move {
                        let mut control_events = control_events;
                        // O estado corrente é aplicado de imediato: uma pausa
                        // pedida antes de a ferramenta começar não pode ser
                        // perdida por esperar a próxima mudança.
                        let mut state = *control_events.borrow_and_update();
                        loop {
                            if sender.send(RunEvent::ToolControl(state)).await.is_err() {
                                return;
                            }
                            if control_events.changed().await.is_err() {
                                return;
                            }
                            state = *control_events.borrow_and_update();
                        }
                    })
                };
                let (trace_tx, mut trace_rx) = mpsc::unbounded_channel::<String>();
                orchestrator.trace_sink = Some(trace_tx);
                let forwarder = tokio::spawn({
                    let sender = sender.clone();
                    let dropped = Arc::clone(&dropped);
                    async move {
                        while let Some(line) = trace_rx.recv().await {
                            // Política de drop: log nunca bloqueia o executor.
                            match sender.try_send(RunEvent::ToolLog(line)) {
                                Ok(()) => {}
                                Err(TrySendError::Full(_)) => {
                                    dropped.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(TrySendError::Closed(_)) => break,
                            }
                        }
                    }
                });
                let decision_forwarder = if is_nuclei {
                    let (decision_tx, mut decision_rx) = mpsc::unbounded_channel();
                    orchestrator.decision_sink = Some(decision_tx);
                    Some(tokio::spawn({
                        let sender = sender.clone();
                        async move {
                            if let Some(decision) = decision_rx.recv().await {
                                let _ = sender.send(RunEvent::AiDecisionFinished(decision)).await;
                            }
                        }
                    }))
                } else {
                    None
                };
                let execution = orchestrator.execute_tool(&tool, &target).await;
                orchestrator.trace_sink = None;
                orchestrator.decision_sink = None;
                control_task.abort();
                let _ = forwarder.await;
                if let Some(forwarder) = decision_forwarder {
                    let _ = forwarder.await;
                }
                if sender
                    .send(RunEvent::ToolFinished {
                        index,
                        execution: Box::new(execution),
                    })
                    .await
                    .is_err()
                {
                    return;
                }
                // Regra automática de interrupção (REQ05): decide entre
                // ferramentas para não descartar a evidência recém-coletada.
                if let Some(reason) = orchestrator.interrupt_after_findings(tool.name.as_str()) {
                    orchestrator.record_interruption(reason);
                    break;
                }
                if orchestrator.is_cancelled() {
                    break;
                }
            }
            orchestrator.build_findings();

            // A auditoria de código entra antes da correlação, como no headless,
            // senão os achados do fonte não participariam da deduplicação.
            let audit = orchestrator.audit_code();
            if audit.files_scanned > 0 {
                let _ = sender
                    .send(RunEvent::AuditFinished {
                        files_scanned: audit.files_scanned,
                        findings: audit.findings.len(),
                        limitation: audit.limitation.clone(),
                    })
                    .await;
            }
            orchestrator.correlate_and_enrich_findings().await;
            for line in orchestrator.enrichment.lines_pt_br() {
                let _ = sender.send(RunEvent::EnrichmentSummary(line)).await;
            }
            // Quantos achados o pipeline produziu de fato: e este evento, e nao
            // uma contagem de quadros, que move a tela de Análise.
            let findings = orchestrator.findings.len();
            if sender
                .send(RunEvent::FindingsBuilt { count: findings })
                .await
                .is_err()
            {
                return;
            }
            if let Some(reason) = orchestrator.interruption() {
                // Execução interrompida: a auditoria do que já foi coletado vem
                // primeiro, e a IA não é chamada — o operador pediu para parar.
                orchestrator.last_log = reason.message;
                let audit_log = orchestrator
                    .persist_scan_log()
                    .map_err(|error| error.to_string());
                let _ = sender
                    .send(RunEvent::Completed {
                        orchestrator: Box::new(orchestrator),
                        audit_log,
                    })
                    .await;
                return;
            }
            let heartbeat = tokio::spawn({
                let sender = sender.clone();
                async move {
                    let _ = sender
                        .send(RunEvent::AnalysisProgress { elapsed_secs: 0 })
                        .await;
                    let mut elapsed_secs = 0u64;
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        elapsed_secs += 2;
                        if sender
                            .send(RunEvent::AnalysisProgress { elapsed_secs })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            });
            orchestrator.analyze_findings().await;

            let (code_tx, mut code_rx) = tokio::sync::mpsc::unbounded_channel();
            let forwarder = sender.clone();
            tokio::spawn(async move {
                while let Some(event) = code_rx.recv().await {
                    if forwarder.send(RunEvent::CodeAgent(event)).await.is_err() {
                        break;
                    }
                }
            });
            // A fase do agente de código roda depois da análise de logs, como no
            // headless: os achados precisam existir e estar classificados. O
            // heartbeat continua vivo para a TUI não parecer travada.
            orchestrator.analyze_code(Some(&code_tx)).await;
            drop(code_tx);
            heartbeat.abort();
            let audit_log = orchestrator
                .persist_scan_log()
                .map_err(|error| error.to_string());
            let _ = sender
                .send(RunEvent::Completed {
                    orchestrator: Box::new(orchestrator),
                    audit_log,
                })
                .await;
        }));
    }

    pub fn push_code_agent(&mut self, event: crate::code_agent::progress::CodeAgentEvent) {
        use crate::code_agent::progress::CodeAgentEvent as Event;
        match &event {
            Event::Started {
                total_findings,
                project_dir,
            } => {
                self.code_agent_current = None;
                self.push_exec_log(format!(
                    "[ia/codigo] explorando {project_dir} · {total_findings} achado(s)"
                ));
            }
            Event::ToolInvoked {
                finding_index,
                tool,
                arguments,
                ..
            } => {
                self.code_agent_current = Some(format!("{tool}({arguments})"));
                self.push_exec_log(format!(
                    "[ia/codigo] achado #{} → {tool}({arguments})",
                    finding_index + 1
                ));
                self.push_ai_timeline(
                    AiTimelineOrigin::Code,
                    format!("ferramenta {tool} no achado #{}", finding_index + 1),
                );
            }
            Event::ToolCompleted(record) => {
                self.code_agent_current = None;
                self.push_exec_log(format!(
                    "[ia/codigo] {} {} · {}",
                    record.tool, record.outcome, record.summary
                ));
                self.push_ai_timeline(
                    AiTimelineOrigin::Code,
                    format!("{} {} · {}", record.tool, record.outcome, record.summary),
                );
            }
            Event::FindingFinished {
                finding_index,
                located,
                tool_calls,
            } => {
                let desfecho = if *located {
                    "localizado"
                } else {
                    "localização não determinada"
                };
                self.push_exec_log(format!(
                    "[ia/codigo] achado #{} {desfecho} em {tool_calls} chamada(s)",
                    finding_index + 1
                ));
                self.push_ai_timeline(
                    AiTimelineOrigin::Code,
                    format!(
                        "achado #{} concluído ({})",
                        finding_index + 1,
                        if *located {
                            "localizado"
                        } else {
                            "não localizado"
                        }
                    ),
                );
            }
            Event::Finished {
                located,
                total,
                unavailable_reason,
            } => {
                self.code_agent_current = None;
                match unavailable_reason {
                    Some(reason) => {
                        self.push_exec_log(format!("[ia/codigo] fase indisponível: {reason}"))
                    }
                    None => self.push_exec_log(format!(
                        "[ia/codigo] {located}/{total} achado(s) localizado(s)"
                    )),
                }
            }
        }

        if self.code_agent_trail.len() >= CODE_TRAIL_LIMIT {
            let excess = self.code_agent_trail.len() + 1 - CODE_TRAIL_LIMIT;
            self.code_agent_trail.drain(..excess);
        }
        self.code_agent_trail.push(event);
    }

    /// Registra uma ação da IA no painel ao vivo, com o horário local do evento.
    /// Saídas de ferramentas de varredura e enriquecimento CVE/NVD não entram aqui.
    pub fn push_ai_timeline(&mut self, origin: AiTimelineOrigin, text: impl Into<String>) {
        self.ai_timeline.push(AiTimelineEntry {
            time: chrono::Local::now().format("%H:%M:%S").to_string(),
            origin,
            text: text.into(),
        });
        let overflow = self.ai_timeline.len().saturating_sub(AI_TIMELINE_LIMIT);
        if overflow == 0 {
            return;
        }
        self.ai_timeline.drain(..overflow);
        if !self.ai_timeline_follow {
            self.ai_timeline_scroll = self.ai_timeline_scroll.saturating_sub(overflow);
        }
    }

    pub fn code_agent_rows(
        &self,
        width: usize,
        height: usize,
    ) -> Vec<ratatui::text::Line<'static>> {
        use crate::code_agent::progress::CodeAgentEvent as Event;
        use ratatui::style::{Color, Modifier, Style};
        use ratatui::text::{Line, Span};

        let label = |text: String| Span::styled(text, Style::default().fg(Color::DarkGray));
        let tool = |text: String| Span::styled(text, Style::default().fg(Color::Cyan));
        let ok = |text: String| Span::styled(text, Style::default().fg(Color::Green));
        let bad = |text: String| Span::styled(text, Style::default().fg(Color::Red));

        let mut rows = Vec::new();
        let trail = &self.code_agent_trail;
        let inicio = trail.len().saturating_sub(height);
        for event in &trail[inicio..] {
            match event {
                Event::Started { total_findings, .. } => rows.push(Line::from(vec![
                    label("  fase  ".into()),
                    Span::styled(
                        format!("explorando código · {total_findings} achado(s)"),
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                ])),
                Event::ToolInvoked {
                    finding_index,
                    tool: name,
                    arguments,
                    ..
                } => rows.push(Line::from(vec![
                    label(format!("  #{}    ", finding_index + 1)),
                    tool(name.clone()),
                    Span::styled(
                        crate::tui::chrome::truncate_width(arguments, width.saturating_sub(14)),
                        Style::default().fg(Color::Gray),
                    ),
                ])),
                Event::ToolCompleted(record) => {
                    let color = match record.outcome.as_str() {
                        "ok" => ok,
                        _ => bad,
                    };
                    rows.push(Line::from(vec![
                        label("        ↳ ".into()),
                        color(record.outcome.clone()),
                        Span::styled(
                            crate::tui::chrome::truncate_width(
                                &record.summary,
                                width.saturating_sub(18),
                            ),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]));
                }
                Event::FindingFinished {
                    finding_index,
                    located,
                    tool_calls,
                } => {
                    let (text, style) = if *located {
                        ("localizado".to_string(), Style::default().fg(Color::Green))
                    } else {
                        (
                            "sem localização".to_string(),
                            Style::default().fg(Color::DarkGray),
                        )
                    };
                    rows.push(Line::from(vec![
                        label(format!("  #{}    ", finding_index + 1)),
                        Span::styled(text, style),
                        label(format!(" · {tool_calls} chamada(s)")),
                    ]));
                }
                Event::Finished {
                    located,
                    total,
                    unavailable_reason,
                } => match unavailable_reason {
                    Some(reason) => rows.push(Line::from(vec![
                        label("  fase  ".into()),
                        bad(crate::tui::chrome::truncate_width(
                            reason,
                            width.saturating_sub(10),
                        )),
                    ])),
                    None => rows.push(Line::from(vec![
                        label("  fase  ".into()),
                        Span::styled(
                            format!("{located}/{total} localizado(s)"),
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        ),
                    ])),
                },
            }
        }
        rows
    }

    pub fn advance_execution(&mut self) {
        if self.exec_cancelled || self.orchestrator.is_cancelled() {
            self.exec_paused = false;
            self.step = AppStep::ToolSelect;
            self.focus = FocusTarget::ToolList;
        }
    }

    /// O relatório usa os achados na ordem do pipeline; a ordenação por
    /// severidade é uma escolha de leitura da tela (REQ15) e não altera o
    /// contrato do relatório.
    pub fn export_md(&self) -> String {
        crate::report::ReportGenerator::compile_report_with_enrichment(
            &self.config,
            &self.orchestrator.findings,
            &self.orchestrator.decision_history,
            &self.orchestrator.enrichment,
            Some(&self.config.effective_project_dir()),
            &self.orchestrator.last_log,
            &self.failed_executions(),
        )
    }

    /// Execuções que terminaram em erro, para a seção de falhas do relatório.
    pub fn failed_executions(&self) -> Vec<SecurityTool> {
        self.orchestrator
            .execution_history
            .iter()
            .filter(|execution| execution.execution_error.is_some())
            .cloned()
            .collect()
    }

    /// Grupos por propósito, já divididos nas duas colunas da tela.
    ///
    /// É a única fonte da divisão: o desenho usa os títulos como seções e a
    /// navegação usa a mesma ordem para a tabulação e para as setas de coluna.
    pub fn settings_column_groups(&self) -> [Vec<(&'static str, Vec<SettingsField>)>; 2] {
        let remote = self.settings_connection_is_remote();
        let mut responde = vec![
            SettingsField::Provider,
            SettingsField::BaseUrl,
            SettingsField::Model,
        ];
        if remote {
            responde.push(SettingsField::ApiKey);
        }
        let mut limites = Vec::new();
        if remote {
            limites.push(SettingsField::RemoteConsent);
        }
        limites.extend([SettingsField::Timeout, SettingsField::Retries]);
        let mut reserva = vec![SettingsField::FallbackEnabled];
        if self.settings_fallback_enabled {
            reserva.extend([SettingsField::FallbackBaseUrl, SettingsField::FallbackModel]);
        }
        // Junto de "quem responde" porque decide o escopo de leitura do agente,
        // não o transporte.
        let analisar = vec![SettingsField::ProjectDir];
        [
            vec![("Quem responde", responde), ("O que analisar", analisar)],
            vec![
                ("Segurança e limites", limites),
                ("Alternativa local", reserva),
            ],
        ]
    }

    /// Ordem de tabulação: concatenação das colunas; as setas usam o eixo da coluna.
    pub fn settings_columns(&self) -> [Vec<SettingsField>; 2] {
        let [left, right] = self.settings_column_groups();
        let flatten = |groups: Vec<(&'static str, Vec<SettingsField>)>| -> Vec<SettingsField> {
            groups.into_iter().flat_map(|(_, fields)| fields).collect()
        };
        [flatten(left), flatten(right)]
    }

    pub fn visible_settings_fields(&self) -> Vec<SettingsField> {
        let [primary, reliability] = self.settings_columns();
        primary.into_iter().chain(reliability).collect()
    }

    /// Uma linha que responde "o que acontece se eu salvar" no estado do
    /// rascunho. O modelo só entra quando cabe junto com o resto: em 80
    /// colunas a segurança (envio remoto, nada sai da máquina) vale mais que
    /// o nome.
    ///
    /// Não chama `settings_candidate`: validar abre o diretório do projeto, e
    /// o desenho de um quadro não pode tocar o disco.
    pub fn settings_summary(&self, max_width: usize) -> String {
        let parts = self.settings_summary_parts();
        let model = self.settings_effective_model();
        if !model.trim().is_empty() {
            let mut with_model = parts.clone();
            with_model.insert(1, model);
            let candidate = with_model.join(" · ");
            if candidate.width() <= max_width {
                return candidate;
            }
        }
        let mut line = String::new();
        for part in parts {
            let candidate = if line.is_empty() {
                part
            } else {
                format!("{line} · {part}")
            };
            if !line.is_empty() && candidate.width() > max_width {
                break;
            }
            line = candidate;
        }
        line
    }

    fn settings_summary_parts(&self) -> Vec<String> {
        if self.settings_effective_base_url().trim().is_empty() {
            return vec![
                "IA desligada: a análise usa as regras do SmartSec, sem modelo".to_string(),
            ];
        }
        let mut parts = vec![format!("IA: {}", self.settings_provider().label())];
        parts.extend(
            self.settings_draft_problems()
                .into_iter()
                .map(str::to_string),
        );
        if self.settings_connection_is_remote() {
            parts.push(
                if self.config.llm.credential_from_env && !self.settings_api_key_touched {
                    "chave da sessão (SMARTSEC_API_KEY)".to_string()
                } else {
                    match (
                        self.settings_api_key_touched,
                        self.settings_input_api_key.trim().is_empty(),
                    ) {
                        (true, false) => "chave nova digitada".to_string(),
                        (false, false) => "chave salva".to_string(),
                        _ => "sem chave".to_string(),
                    }
                },
            );
            parts.push(if self.settings_remote_consent {
                "envio remoto permitido".to_string()
            } else {
                "envio remoto bloqueado".to_string()
            });
        } else {
            parts.push("nada sai da máquina".to_string());
        }
        if self.settings_fallback_enabled {
            parts.push("reserva local ligada".to_string());
        }
        parts
    }

    /// Problemas que se leem do próprio rascunho, sem validação no disco.
    fn settings_draft_problems(&self) -> Vec<&'static str> {
        let mut problems = Vec::new();
        let timeout = self.settings_input_timeout.trim().parse::<u64>();
        if !matches!(timeout, Ok(value) if (1..=MAX_TIMEOUT_SECS).contains(&value)) {
            problems.push("tempo limite inválido");
        }
        let retries = self.settings_input_retries.trim().parse::<u8>();
        if !matches!(retries, Ok(value) if value <= MAX_RETRIES) {
            problems.push("tentativas inválidas");
        }
        let model = self.settings_effective_model();
        if model.trim().is_empty() || model.chars().any(char::is_whitespace) {
            problems.push("modelo inválido");
        }
        problems
    }

    pub fn focused_settings_field(&self) -> Option<SettingsField> {
        match self.focus {
            FocusTarget::SettingsField(field) => Some(field),
            _ => None,
        }
    }

    /// Compara contra `config` e não contra `settings_candidate`: validar o
    /// candidato abriria o diretório do projeto a cada quadro.
    pub fn settings_field_changed(&self, field: SettingsField) -> bool {
        match field {
            SettingsField::Provider => {
                LlmProviderKind::all_labels()[self.settings_provider_idx]
                    != self.config.llm.provider.label()
            }
            SettingsField::BaseUrl => {
                self.settings_effective_base_url() != self.config.llm.base_url
            }
            SettingsField::Model => self.settings_effective_model() != self.config.llm.model,
            SettingsField::ApiKey => {
                self.settings_api_key_touched
                    && self.settings_input_api_key != self.config.llm.api_key
            }
            SettingsField::Timeout => {
                self.settings_input_timeout.trim().parse::<u64>().ok()
                    != Some(self.config.llm.timeout_secs)
            }
            SettingsField::Retries => {
                self.settings_input_retries.trim().parse::<u8>().ok()
                    != Some(self.config.llm.max_retries)
            }
            SettingsField::RemoteConsent => {
                self.settings_remote_consent != self.config.llm.remote_consent
            }
            SettingsField::FallbackEnabled => {
                self.settings_fallback_enabled != self.config.llm.fallback_enabled
            }
            SettingsField::FallbackBaseUrl => {
                self.settings_input_fallback_base_url.trim() != self.config.llm.fallback_base_url
            }
            SettingsField::FallbackModel => {
                self.settings_input_fallback_model.trim() != self.config.llm.fallback_model
            }
            SettingsField::ProjectDir => {
                self.settings_input_project_dir.trim() != self.settings_saved_project_dir().trim()
            }
        }
    }

    /// Quantos campos visíveis divergem do que está gravado.
    pub fn settings_dirty_count(&self) -> usize {
        self.visible_settings_fields()
            .into_iter()
            .filter(|field| self.settings_field_changed(*field))
            .count()
    }

    pub(crate) fn settings_effective_base_url(&self) -> String {
        let draft = self.settings_input_base_url.trim();
        if draft.is_empty() {
            self.settings_provider().default_base_url().to_string()
        } else {
            draft.to_string()
        }
    }

    fn settings_effective_model(&self) -> String {
        let draft = self.settings_input_model.trim();
        if draft.is_empty() {
            self.settings_provider().default_model().to_string()
        } else {
            draft.to_string()
        }
    }

    fn settings_saved_project_dir(&self) -> String {
        self.config
            .project_dir
            .clone()
            .unwrap_or_else(|| self.config.effective_project_dir().display().to_string())
    }

    pub(crate) fn settings_provider(&self) -> LlmProviderKind {
        LlmProviderKind::from_label(LlmProviderKind::all_labels()[self.settings_provider_idx])
    }

    pub fn settings_connection_is_remote(&self) -> bool {
        let mut llm = self.config.llm.clone();
        llm.provider = self.settings_provider();
        llm.base_url = self.settings_input_base_url.trim().to_string();
        llm.is_remote()
    }

    /// Registra (ou limpa) o aviso de configuracao da abertura.
    pub fn set_config_warning(&mut self, warning: Option<String>) {
        self.config_warning = warning.filter(|text| !text.trim().is_empty());
    }

    /// O aviso mais urgente entre erro de salvamento e problema de abertura.
    pub fn settings_status_error(&self) -> Option<&str> {
        self.settings_error
            .as_deref()
            .or(self.config_warning.as_deref())
    }

    /// Relê a chave ao abrir Configurar IA; o cofre pode ter sido desbloqueado.
    pub(crate) fn reload_api_key_from_keyring(&mut self) {
        if !self.config.llm.api_key.trim().is_empty() || !self.config.llm.is_remote() {
            return;
        }
        match crate::config::persistence::api_key_status() {
            crate::config::persistence::ApiKeyStatus::Available(key) => {
                self.config.llm.api_key = key;
                self.config.llm.credential_error = None;
            }
            crate::config::persistence::ApiKeyStatus::Missing => {
                self.config.llm.credential_error = None;
            }
            crate::config::persistence::ApiKeyStatus::Locked(reason)
            | crate::config::persistence::ApiKeyStatus::Unavailable(reason) => {
                self.config.llm.credential_error = Some(reason);
            }
        }
        let problems = self.config.validation_problems();
        self.set_config_warning(if problems.is_empty() {
            None
        } else {
            Some(problems.join(" · "))
        });
    }

    pub fn apply_settings(&mut self) -> Result<(), String> {
        let candidate = self.settings_candidate()?;
        candidate.save()?;
        self.commit_settings(candidate);
        Ok(())
    }

    /// Monta a configuração a partir do rascunho **sem** gravar nada.
    ///
    /// `save` toca o arquivo do usuário e o keyring: o assistente precisa montar
    /// e validar o candidato antes de decidir se ele será persistido.
    pub fn settings_candidate(&self) -> Result<Configuration, String> {
        let provider = self.settings_provider();
        let timeout = self
            .settings_input_timeout
            .trim()
            .parse::<u64>()
            .map_err(|_| {
                "Tempo limite inválido: informe um número inteiro entre 1 e 45 segundos."
                    .to_string()
            })?;
        let retries = self
            .settings_input_retries
            .trim()
            .parse::<u8>()
            .map_err(|_| {
                "Tentativas inválidas: informe um número inteiro entre 0 e 3.".to_string()
            })?;
        let mut candidate = self.config.clone();
        candidate.llm.provider = provider;
        candidate.llm.base_url = self.settings_effective_base_url();
        candidate.llm.api_key = self.settings_input_api_key.clone();
        candidate.llm.credential_from_env =
            self.config.llm.credential_from_env && !self.settings_api_key_touched;
        candidate.llm.model = self.settings_effective_model();
        candidate.llm.timeout_secs = timeout;
        candidate.llm.max_retries = retries;
        candidate.llm.remote_consent = self.settings_remote_consent;
        candidate.llm.fallback_enabled = self.settings_fallback_enabled;
        candidate.llm.fallback_base_url = self.settings_input_fallback_base_url.trim().to_string();
        candidate.llm.fallback_model = self.settings_input_fallback_model.trim().to_string();
        candidate.llm.validate()?;
        // O diretório do projeto é validado pelo mesmo sandbox que o agente vai
        // usar: aceitar na tela um caminho que a fase rejeitaria entregaria ao
        // operador a impressão de que a análise de código está configurada.
        let project = self.settings_input_project_dir.trim().to_string();
        let project_path = if project.is_empty() {
            PathBuf::from(".")
        } else {
            PathBuf::from(&project)
        };
        crate::code_agent::workspace::Workspace::open(&project_path).map_err(|error| {
            format!(
                "Diretório do projeto inválido: {error}; escolha uma pasta existente e legível."
            )
        })?;
        candidate.project_dir = Some(project);
        Ok(candidate)
    }

    /// Aplica uma configuração já validada e persistida.
    ///
    /// Separado de [`Self::apply_settings`] para o efeito no estado ser
    /// verificável sem tocar o disco do usuário nem o keyring.
    pub(crate) fn commit_settings(&mut self, candidate: Configuration) {
        self.config = candidate;
        self.reset_settings_draft();
        self.show_settings = false;
        // Uma configuracao valida foi salva: o aviso de abertura perdeu o
        // objeto e sai, para a proxima execucao comecar limpa. Se o `save`
        // falhasse, ele nao chegaria aqui e manter o aviso seria o correto.
        self.config_warning = None;
    }

    pub fn reset_settings_draft(&mut self) {
        self.settings_provider_idx = self.config.llm.provider.index();
        self.settings_input_base_url = self.config.llm.base_url.clone();
        self.settings_input_api_key = self.config.llm.api_key.clone();
        self.settings_input_model = self.config.llm.model.clone();
        self.settings_input_timeout = self.config.llm.timeout_secs.to_string();
        self.settings_input_retries = self.config.llm.max_retries.to_string();
        self.settings_remote_consent = self.config.llm.remote_consent;
        self.settings_fallback_enabled = self.config.llm.fallback_enabled;
        self.settings_input_fallback_base_url = self.config.llm.fallback_base_url.clone();
        self.settings_input_fallback_model = self.config.llm.fallback_model.clone();
        self.settings_input_project_dir = self.settings_saved_project_dir();
        self.settings_api_key_touched = false;
        self.settings_error = None;
        self.settings_scroll = 0;
        self.settings_editing = None;
        if !self
            .visible_settings_fields()
            .contains(&self.settings_field)
        {
            self.settings_field = SettingsField::Provider;
        }
    }

    /// Cancela a execução pelo canal de controle compartilhado, na varredura e
    /// na análise: a task não é abortada às cegas — isso impediria a limpeza e a
    /// auditoria —, e o cancelamento na Análise evita prender o operador na
    /// espera do modelo.
    pub fn cancel_run(&mut self) {
        if !matches!(self.step, AppStep::Execution | AppStep::Analysis) || self.exec_cancelled {
            return;
        }
        self.exec_cancelled = true;
        self.exec_paused = false;
        self.orchestrator.cancel_execution();
        // A ferramenta em execucao e marcada como cancelada, e nao como falha:
        // o operador pediu para parar, e a distincao importa no relatorio e na
        // auditoria tanto quanto importa na tela.
        if let Some(tool) = self
            .tools
            .iter_mut()
            .find(|tool| matches!(tool.status, ToolStatus::Running | ToolStatus::Paused))
        {
            let name = tool.tool.name.clone();
            tool.status = ToolStatus::Failed;
            self.push_exec_log(format!("[cancelled] {name} CANCELADA pelo operador"));
        }
        self.push_exec_log("X Cancelamento solicitado; encerrando o container".to_string());
        // A auditoria e gravada agora, e nao quando a task termina: o
        // cancelamento e uma decisao do operador e precisa estar registrada
        // mesmo que o container demore a encerrar.
        self.persist_cancelled_run();
        self.follow_latest_log();
    }

    /// Pausa a ferramenta em execução (`podman pause` no container real).
    pub fn pause_run(&mut self) {
        if self.step != AppStep::Execution || self.exec_cancelled || self.exec_paused {
            return;
        }
        self.orchestrator.pause_execution();
        self.exec_paused = true;
        if let Some(tool) = self
            .tools
            .iter_mut()
            .find(|tool| tool.status == ToolStatus::Running)
        {
            tool.status = ToolStatus::Paused;
        }
        self.push_exec_log("‖ Pausa solicitada; o container será pausado".to_string());
        self.follow_latest_log();
    }

    /// Retoma a ferramenta pausada (`podman unpause` no container real).
    pub fn resume_run(&mut self) {
        if self.step != AppStep::Execution || self.exec_cancelled || !self.exec_paused {
            return;
        }
        self.orchestrator.resume_execution();
        self.exec_paused = false;
        if let Some(tool) = self
            .tools
            .iter_mut()
            .find(|tool| tool.status == ToolStatus::Paused)
        {
            tool.status = ToolStatus::Running;
        }
        self.push_exec_log("‖ Retomada solicitada; o container será retomado".to_string());
        self.follow_latest_log();
    }

    /// Encerra a execução antes de sair da TUI, sem deixar container órfão.
    pub async fn shutdown_run(&mut self) {
        if self.run_task.is_none() {
            return;
        }
        if !self.exec_cancelled {
            self.orchestrator.cancel_execution();
        }
        if let Some(task) = self.run_task.take() {
            let completed = tokio::time::timeout(std::time::Duration::from_secs(30), async {
                let _ = task.await;
            })
            .await
            .is_ok();
            if !completed {
                // O executor cooperativo não respondeu: o `abort` é o último
                // recurso, e o guard `ContainerCleanup` ainda remove o
                // container parcial no encerramento da task.
                self.run_error = Some(
                    "A execução não respondeu ao cancelamento e foi interrompida; \
                     confirme com `podman ps -a` que não restou container."
                        .to_string(),
                );
            }
        }
        self.run_receiver = None;
        self.persist_cancelled_run();
    }

    /// Persiste a execução sintética de cancelamento para auditoria: nenhum
    /// scanner roda, o registro é fabricado do estado da tela só para o log dizer
    /// qual ferramenta estava em execução; o registro real vem do executor.
    fn persist_cancelled_run(&mut self) {
        self.orchestrator.record_interruption(
            crate::orchestrator::control::InterruptionReason::user_cancelled(),
        );
        if let Some(tool) = self.tools.iter().find(|tool| {
            matches!(
                tool.status,
                ToolStatus::Running | ToolStatus::Paused | ToolStatus::Failed
            )
        }) {
            let already_recorded = self
                .orchestrator
                .execution_history
                .iter()
                .any(|execution| execution.status == "cancelled");
            if !already_recorded {
                let mut execution = SecurityTool::new(
                    &tool.tool.name,
                    &format!("{} {}", tool.tool.name, self.config.target_url),
                );
                execution.executed_at =
                    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                execution.status = "cancelled".to_string();
                execution.execution_error = Some("Execução cancelada pelo usuário".to_string());
                self.orchestrator.execution_history.push(execution);
            }
        }
        if self.orchestrator.last_log.is_empty() {
            self.orchestrator.last_log = "Execução cancelada pelo usuário".to_string();
        }
        match self.orchestrator.persist_scan_log() {
            Ok(path) => self.audit_log_path = Some(path),
            Err(error) => self.record_run_issue(
                RunIssueScope::Audit,
                format!("Execução cancelada; falha ao salvar auditoria: {error}"),
            ),
        }
    }

    pub fn sync_agent_from_orchestrator(&mut self) {
        self.agent.last_analysis = self.orchestrator.last_log.clone();
    }

    /// Carrega o histórico de execuções gravado em disco; a leitura não altera
    /// nenhum artefato, e registros ilegíveis ficam em
    /// [`ScanHistory::unreadable`](crate::orchestrator::scan_logger::ScanHistory)
    /// e são exibidos em vez de sumir.
    pub fn load_history(&mut self) {
        match crate::orchestrator::scan_logger::list_scan_logs_from_dir(&self.history_dir) {
            Ok(history) => {
                self.history = history;
                self.history_error = None;
            }
            Err(error) => {
                self.history = crate::orchestrator::scan_logger::ScanHistory::default();
                self.history_error = Some(format!("{error:#}"));
            }
        }
        self.history_cursor = self
            .history_cursor
            .min(self.history.records.len().saturating_sub(1));
        self.splash_recent_cursor = self
            .splash_recent_cursor
            .min(self.recent_scan_indices().len().saturating_sub(1));
        self.history_scroll = 0;
        self.history_refresh_pending = false;
    }

    /// Índices das execuções que valem a pena mostrar no início.
    ///
    /// A suíte grava logs de teste com alvo `[REDACTED]`; eles não são
    /// execuções reais e não podem esconder o histórico útil.
    pub fn recent_scan_indices(&self) -> Vec<usize> {
        self.history
            .records
            .iter()
            .enumerate()
            .filter(|(_, record)| record.target_url != "[REDACTED]" && record.findings_count > 0)
            .map(|(index, _)| index)
            .take(3)
            .collect()
    }

    pub fn request_history_refresh(&mut self) {
        self.history_refresh_pending = true;
    }

    pub fn refresh_history_if_pending(&mut self) {
        if self.history_refresh_pending {
            self.load_history();
        }
    }

    /// Abre os resultados de um registro já listado no histórico.
    pub fn replay_history_record(&mut self, index: usize) -> anyhow::Result<()> {
        let record =
            self.history.records.get(index).cloned().ok_or_else(|| {
                anyhow::anyhow!("A execução selecionada não está mais disponível.")
            })?;
        let metadata =
            crate::orchestrator::scan_logger::load_scan_log_from_file(&record.file_path)?;
        self.load_replayed_scan(metadata)?;
        self.audit_log_path = Some(record.file_path.clone());
        self.history_cursor = index;
        self.history_detail = None;
        self.history_error = None;
        Ok(())
    }

    /// Abre o histórico a partir da tela atual, preservando a tela de retorno.
    pub fn open_history(&mut self) {
        self.load_history();
        self.history_return_step = self.step;
        self.history_detail = None;
        self.history_detail_scroll = 0;
        self.history_detail_max_scroll = 0;
        self.step = AppStep::History;
        self.focus = FocusTarget::HistoryList;
    }

    /// Abre o detalhe da execução selecionada, somente leitura.
    pub fn open_history_record(&mut self, index: usize) {
        let Some(record) = self.history.records.get(index).cloned() else {
            self.history_error =
                Some("A execução selecionada não está mais disponível.".to_string());
            return;
        };
        match crate::orchestrator::scan_logger::load_scan_log_from_file(&record.file_path) {
            Ok(metadata) => {
                self.history_error = None;
                self.history_cursor = index;
                self.history_detail = Some(metadata);
                self.history_detail_scroll = 0;
                self.history_detail_max_scroll = 0;
                self.focus = FocusTarget::HistoryDetail;
            }
            Err(error) => {
                self.history_detail = None;
                self.history_error = Some(format!(
                    "Não foi possível abrir {}: {error:#}",
                    record.scan_id
                ));
                self.focus = FocusTarget::HistoryList;
            }
        }
    }

    /// Motivo pelo qual um achado ficou sem origem no código.
    ///
    /// O texto vem do relatório da fase (indexado pela posição do achado) e é
    /// sanitizado: o diagnóstico pode carregar detalhe do transporte.
    pub fn code_reason_for_index(&self, index: usize) -> Option<String> {
        self.orchestrator
            .last_code_report
            .as_ref()?
            .findings
            .iter()
            .find(|item| item.finding_index == index)
            .and_then(|item| item.reason.clone())
            .map(|reason| crate::utils::redaction::sanitize_diagnostic(&reason))
    }

    /// Motivo registrado para o achado atualmente aberto no painel de detalhe.
    pub fn code_reason_fallback(&self) -> Option<String> {
        self.code_reason_for_index(self.result_detail_vuln?)
    }

    /// Diretório do projeto analisado pela fase de código, para exibição.
    pub fn project_dir_label(&self) -> String {
        crate::utils::redaction::sanitize_text(
            &self.config.effective_project_dir().display().to_string(),
        )
    }
}

/// Seleção inicial da ferramenta: lista explícita em `config.active_tools`
/// manda; lista vazia deixa tudo marcado (a pré-seleção só age na tela).
fn selected_from_active_tools(active_tools: &[String], name: &str) -> bool {
    active_tools.is_empty()
        || active_tools
            .iter()
            .any(|selected| selected.trim().eq_ignore_ascii_case(name.trim()))
}

/// Ordem de leitura dos achados: a severidade do scanner é autoritativa
/// (TCC_SPEC.md, seção 7) e a tela apenas a ordena para destacar os críticos.
fn restore_rag_example(result: &mut crate::cyberrag::service::ExplanationResult) {
    let Some(example) = result.example.as_mut() else {
        return;
    };
    let Some(entry) = crate::cyberrag::corpus::Corpus::shared().get(&example.id) else {
        result.example = None;
        return;
    };
    let language = example.linguagem.clone();
    if let Some(header) = example.header.clone() {
        if let Some(guide) = entry
            .cabecalhos
            .iter()
            .find(|guide| guide.cabecalho.eq_ignore_ascii_case(&header))
        {
            *example = crate::cyberrag::service::header_example(
                entry.id.clone(),
                &header,
                guide,
                language.as_deref(),
            );
            return;
        }
    }
    let code = entry
        .exemplos
        .iter()
        .find(|candidate| Some(candidate.linguagem.as_str()) == language.as_deref())
        .or_else(|| entry.exemplos.first());
    example.titulo = entry.titulo.clone();
    example.padrao_seguro = entry.padrao_seguro.clone();
    example.linguagem = code.map(|candidate| candidate.linguagem.clone());
    example.vulneravel = code.map(|candidate| candidate.vulneravel.trim().to_string());
    example.corrigido = code.map(|candidate| candidate.corrigido.trim().to_string());
}

fn format_elapsed(total_secs: u64) -> String {
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    if hours > 0 {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
    }
}

fn severity_rank(severity: crate::domain::Severity) -> u8 {
    match severity {
        crate::domain::Severity::Critical => 0,
        crate::domain::Severity::High => 1,
        crate::domain::Severity::Medium => 2,
        crate::domain::Severity::Low => 3,
        crate::domain::Severity::Info => 4,
    }
}

/// Resumo legível de uma decisão do Nuclei para o painel da IA: quem decidiu,
/// o motivo e quantos argumentos foram registrados no `DecisionRecord`.
fn decision_summary(record: &DecisionRecord) -> String {
    let author = match record.source {
        DecisionSource::Ai => "a IA decidiu",
        DecisionSource::Fallback => "a política local decidiu",
    };
    format!(
        "plano do Nuclei definido: {author} · motivo: {} · {} argumento(s)",
        record.justification,
        record.parameters.len()
    )
}

/// Conta as linhas visuais de entradas que saíram do log, usando a mesma
/// quebra do `Paragraph` aplicada na renderização. Sem isso, o ajuste do
/// offset no descarte misturaria unidades lógicas e visuais.
fn visual_line_count(lines: &[String], width: u16) -> usize {
    if lines.is_empty() || width == 0 {
        return 0;
    }
    let text = Text::from(
        lines
            .iter()
            .map(|line| Line::from(line.as_str()))
            .collect::<Vec<_>>(),
    );
    Paragraph::new(text)
        .wrap(Wrap { trim: false })
        .line_count(width)
}

/// Linhas visuais de uma entrada do log, com a mesma quebra do `Paragraph`.
/// É a medida memoizada por linha em `AppState::log_rows`.
fn log_line_rows(line: &str, width: u16) -> u32 {
    if width == 0 {
        return 0;
    }
    Paragraph::new(Line::from(line))
        .wrap(Wrap { trim: false })
        .line_count(width) as u32
}

fn compact_operational_log(line: &str) -> String {
    let Some(json_start) = line.find('{') else {
        return line.chars().take(600).collect();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&line[json_start..]) else {
        return line.chars().take(600).collect();
    };
    let Some(template_id) = json.get("template-id").and_then(|value| value.as_str()) else {
        return line.chars().take(600).collect();
    };
    let matcher = json
        .get("matcher-name")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let title = crate::orchestrator::nuclei_parser::localized_nuclei_title(template_id, matcher);
    let severity = crate::domain::Severity::from_label(
        json.pointer("/info/severity")
            .and_then(|value| value.as_str())
            .unwrap_or("info"),
    )
    .label_pt_br();
    let endpoint = json
        .get("matched-at")
        .or_else(|| json.get("url"))
        .and_then(|value| value.as_str())
        .map(crate::utils::redaction::sanitize_url)
        .unwrap_or_else(|| "endpoint não informado".to_string());
    let timestamp = &line[..json_start];
    format!("{timestamp}achado · {severity} · {title} · {endpoint}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vulnerability::FindingSource;
    use crate::domain::Severity;

    fn app() -> AppState {
        AppState::new(Configuration::default()).expect("configuração de teste válida")
    }

    /// Mesmo canal limitado que `init_execution` cria para o executor real.
    fn run_channel() -> (mpsc::Sender<RunEvent>, mpsc::Receiver<RunEvent>) {
        mpsc::channel(RUN_EVENT_CAPACITY)
    }

    async fn feed(app: &mut AppState, sender: &mpsc::Sender<RunEvent>, event: RunEvent) {
        sender.send(event).await.expect("canal aberto");
        app.process_run_events().await;
    }

    fn finding(severity: Severity, title: &str) -> Vulnerability {
        Vulnerability {
            title: title.to_string(),
            severity,
            description: "Descrição".to_string(),
            tool: "Nmap".to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: FindingSource::Real,
            target: "http://target.local".to_string(),
            evidence: "porta 22 aberta".to_string(),
            detected_at: "2026-09-04T14:00:00Z".to_string(),
            ..Default::default()
        }
    }

    fn orchestrator_with(findings: Vec<Vulnerability>, agent_history: Vec<&str>) -> Orchestrator {
        let mut orchestrator = Orchestrator::new(Configuration::default()).expect("orquestrador");
        orchestrator.findings = findings;
        orchestrator
            .agent
            .execution_history
            .extend(agent_history.into_iter().map(str::to_string));
        orchestrator.last_log = "Análise concluída: 2 achados".to_string();
        orchestrator
    }

    fn failed_execution(tool: &str, error: &str) -> SecurityTool {
        let mut execution = SecurityTool::new(tool, &format!("{tool} http://target.local"));
        execution.status = "failed".to_string();
        execution.duration_ms = 1_500;
        execution.execution_error = Some(error.to_string());
        execution
    }

    fn succeeded_execution(tool: &str) -> SecurityTool {
        let mut execution = SecurityTool::new(tool, &format!("{tool} http://target.local"));
        execution.status = "succeeded".to_string();
        execution.duration_ms = 2_500;
        execution
    }

    #[test]
    fn compacts_nuclei_jsonl_for_the_live_log() {
        let line = r#"[12:00:00] {"template-id":"headers","info":{"name":"Cabeçalhos ausentes","severity":"info"},"matched-at":"http://target.local/path?token=secret","request":"segredo","response":"segredo"}"#;

        let compact = compact_operational_log(line);

        assert!(
            compact.contains("achado · INFORMATIVA · Achado identificado pelo Nuclei — headers")
        );
        assert!(compact.contains("http://target.local/path"));
        assert!(!compact.contains("request"));
        assert!(!compact.contains("response"));
        assert!(!compact.contains("secret"));
    }

    /// Sequência ponta a ponta do pipeline real: início, log, fim, achados,
    /// análise e conclusão. Nenhuma contagem de ticks participa.
    #[tokio::test]
    async fn the_real_event_sequence_reaches_the_results_screen() {
        let mut app = app();
        app.step = AppStep::Execution;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);

        let producer = tokio::spawn(async move {
            for event in [
                RunEvent::ToolStarted(0),
                RunEvent::ToolLog("[12:00:01] $ podman create --name smartsec-nmap".to_string()),
                RunEvent::ToolFinished {
                    index: 0,
                    execution: Box::new(succeeded_execution("Nmap")),
                },
                RunEvent::FindingsBuilt { count: 2 },
                RunEvent::AnalysisProgress { elapsed_secs: 0 },
            ] {
                sender.send(event).await.expect("canal aberto");
            }
            sender
                .send(RunEvent::Completed {
                    orchestrator: Box::new(orchestrator_with(
                        vec![
                            finding(Severity::Info, "Versão exposta"),
                            finding(Severity::Critical, "Shell remota aberta"),
                        ],
                        Vec::new(),
                    )),
                    audit_log: Ok(PathBuf::from("/tmp/scan.json")),
                })
                .await
                .expect("canal aberto");
        });
        producer.await.expect("produtor de eventos");

        app.step_tick().await;
        app.step_tick().await;

        assert_eq!(
            app.step,
            AppStep::Results,
            "a análise concluída abre os resultados"
        );
        assert_eq!(app.focus, FocusTarget::ResultsList);
        assert_eq!(app.analysis_phase, AnalysisPhase::Complete);
        assert_eq!(app.tools[0].status, ToolStatus::Done);
        assert_eq!(app.analysis_findings, 2);
        assert_eq!(app.audit_log_path, Some(PathBuf::from("/tmp/scan.json")));
        assert!(app
            .exec_logs
            .iter()
            .any(|line| line.contains("podman create")));
        assert!(app
            .exec_logs
            .iter()
            .any(|line| line.contains("[Nmap] OK em 2.5s")));
        assert!(!app.run_issues.is_empty() || app.run_error.is_none());
    }

    /// A tela só muda quando o pipeline emite o evento correspondente, quantos
    /// quadros passem.
    #[tokio::test]
    async fn the_analysis_transition_waits_for_the_pipeline_and_not_for_ticks() {
        let mut app = app();
        app.step = AppStep::Execution;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);

        for _ in 0..200 {
            app.step_tick().await;
        }
        assert_eq!(
            app.step,
            AppStep::Execution,
            "sem evento do pipeline a TUI não avança de tela"
        );
        assert_eq!(app.analysis_phase, AnalysisPhase::Scanning);

        feed(&mut app, &sender, RunEvent::FindingsBuilt { count: 3 }).await;
        assert_eq!(app.step, AppStep::Analysis);
        assert_eq!(app.analysis_phase, AnalysisPhase::Correlating);
        assert_eq!(app.analysis_findings, 3);

        feed(
            &mut app,
            &sender,
            RunEvent::AnalysisProgress { elapsed_secs: 2 },
        )
        .await;
        assert_eq!(
            app.analysis_phase,
            AnalysisPhase::Generating,
            "a fase da IA começa quando a chamada começa"
        );
        assert_eq!(app.analysis_wait_secs, 2);

        feed(
            &mut app,
            &sender,
            RunEvent::Completed {
                orchestrator: Box::new(orchestrator_with(
                    vec![finding(Severity::High, "Serviço administrativo")],
                    Vec::new(),
                )),
                audit_log: Ok(PathBuf::from("/tmp/scan.json")),
            },
        )
        .await;
        assert_eq!(
            app.step,
            AppStep::Results,
            "a análise terminou de verdade: sem espera de 30 ticks"
        );
        assert_eq!(app.analysis_phase, AnalysisPhase::Complete);
        assert_eq!(app.vulnerabilities().len(), 1);
    }

    /// Toda ocorrência é preservada: ferramenta, auditoria e IA.
    #[tokio::test]
    async fn tool_audit_and_ai_failures_are_all_reported() {
        let mut app = app();
        app.step = AppStep::Execution;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);

        feed(
            &mut app,
            &sender,
            RunEvent::ToolFinished {
                index: 0,
                execution: Box::new(failed_execution("Nmap", "imagem do container ausente")),
            },
        )
        .await;
        feed(
            &mut app,
            &sender,
            RunEvent::Completed {
                orchestrator: Box::new(orchestrator_with(
                    vec![finding(Severity::Critical, "Shell remota aberta")],
                    vec![
                        "A LLM principal falhou: conexão recusada",
                        "Usando o llama.cpp local configurado como alternativa",
                    ],
                )),
                audit_log: Err("sem permissão de escrita".to_string()),
            },
        )
        .await;

        let scopes: Vec<RunIssueScope> = app.run_issues.iter().map(|issue| issue.scope).collect();
        assert_eq!(
            scopes,
            vec![
                RunIssueScope::Tool,
                RunIssueScope::Ai,
                RunIssueScope::Ai,
                RunIssueScope::Audit
            ],
            "nenhuma origem pode ser omitida"
        );
        assert_eq!(app.tools[0].status, ToolStatus::Failed);
        assert_eq!(
            app.run_error.as_deref(),
            Some("imagem do container ausente"),
            "o status resumido aponta a primeira falha de execução"
        );
        assert!(
            app.llm_warning
                .is_some_and(|warning| warning.contains("A LLM principal falhou")),
            "o aviso de IA resume a causa raiz registrada pelo agente"
        );

        assert!(app
            .run_issues
            .iter()
            .any(|issue| issue.detail.contains("sem permissão de escrita")));
    }

    #[tokio::test]
    async fn analysis_progress_feeds_the_wait_indicator() {
        let mut app = app();
        app.step = AppStep::Execution;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);

        feed(
            &mut app,
            &sender,
            RunEvent::AnalysisProgress { elapsed_secs: 0 },
        )
        .await;
        assert_eq!(app.analysis_wait_secs, 0);
        assert!(app
            .exec_logs()
            .last()
            .is_some_and(|line| line == "[ia] análise em andamento… (0s)"));

        feed(
            &mut app,
            &sender,
            RunEvent::AnalysisProgress { elapsed_secs: 2 },
        )
        .await;
        assert_eq!(app.analysis_wait_secs, 2);
        assert_eq!(app.exec_logs().len(), 1, "sem spam a cada heartbeat");

        feed(
            &mut app,
            &sender,
            RunEvent::AnalysisProgress { elapsed_secs: 10 },
        )
        .await;
        assert_eq!(app.analysis_wait_secs, 10);
        assert!(app
            .exec_logs()
            .last()
            .is_some_and(|line| line == "[ia] análise em andamento… (10s)"));
    }

    #[tokio::test]
    async fn ai_events_expose_the_real_pipeline_stage() {
        let mut app = app();
        app.step = AppStep::Execution;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);

        feed(&mut app, &sender, RunEvent::AiDecisionStarted).await;
        assert_eq!(app.ai_activity, AiActivity::PlanningNuclei);

        let decision = crate::orchestrator::decision::decide_nuclei_plan(
            "http://target.local",
            None,
            None,
            "modelo-local",
        );
        feed(
            &mut app,
            &sender,
            RunEvent::AiDecisionFinished(decision.clone()),
        )
        .await;
        assert_eq!(app.ai_activity, AiActivity::PlanReady);
        assert_eq!(app.ai_decision.as_ref(), Some(&decision));

        feed(
            &mut app,
            &sender,
            RunEvent::AnalysisProgress { elapsed_secs: 2 },
        )
        .await;
        assert_eq!(app.ai_activity, AiActivity::GeneratingGuidance);
    }

    /// A timeline da IA recebe só a atuação da IA, na ordem dos eventos, com a
    /// origem de cada etapa e o horário local de cada ação.
    #[tokio::test]
    async fn ai_timeline_records_the_ai_events_in_order_with_the_right_origin() {
        use crate::code_agent::agent::ToolCallRecord;
        use crate::code_agent::progress::CodeAgentEvent;

        let mut app = app();
        app.step = AppStep::Execution;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);

        feed(&mut app, &sender, RunEvent::AiDecisionStarted).await;
        let decision = crate::orchestrator::decision::decide_nuclei_plan(
            "http://target.local",
            None,
            None,
            "modelo-local",
        );
        feed(
            &mut app,
            &sender,
            RunEvent::AiDecisionFinished(decision.clone()),
        )
        .await;
        feed(
            &mut app,
            &sender,
            RunEvent::AnalysisProgress { elapsed_secs: 10 },
        )
        .await;
        feed(
            &mut app,
            &sender,
            RunEvent::CodeAgent(CodeAgentEvent::ToolInvoked {
                finding_index: 0,
                iteration: 0,
                tool: "read_file".to_string(),
                arguments: r#"{"path":"src/app.py"}"#.to_string(),
            }),
        )
        .await;
        feed(
            &mut app,
            &sender,
            RunEvent::CodeAgent(CodeAgentEvent::ToolCompleted(ToolCallRecord {
                finding_index: 0,
                iteration: 0,
                tool: "read_file".to_string(),
                arguments: r#"{"path":"src/app.py"}"#.to_string(),
                outcome: "ok".to_string(),
                summary: "4 | raise ValueError".to_string(),
            })),
        )
        .await;
        feed(
            &mut app,
            &sender,
            RunEvent::CodeAgent(CodeAgentEvent::FindingFinished {
                finding_index: 0,
                located: true,
                tool_calls: 1,
            }),
        )
        .await;
        feed(
            &mut app,
            &sender,
            RunEvent::Completed {
                orchestrator: Box::new(orchestrator_with(
                    Vec::new(),
                    vec!["A LLM principal falhou; usando o modelo local"],
                )),
                audit_log: Ok(PathBuf::from("/tmp/scan.json")),
            },
        )
        .await;

        let origins: Vec<AiTimelineOrigin> =
            app.ai_timeline.iter().map(|entry| entry.origin).collect();
        assert_eq!(
            origins,
            vec![
                AiTimelineOrigin::Planning,
                AiTimelineOrigin::Planning,
                AiTimelineOrigin::Ai,
                AiTimelineOrigin::Code,
                AiTimelineOrigin::Code,
                AiTimelineOrigin::Code,
                AiTimelineOrigin::Ai,
            ],
            "cada evento entra com a origem da etapa que o produziu"
        );

        let texts: Vec<&str> = app
            .ai_timeline
            .iter()
            .map(|entry| entry.text.as_str())
            .collect();
        assert_eq!(texts[0], "planejando o uso do Nuclei…");
        assert!(
            texts[1].contains("plano do Nuclei definido"),
            "{}",
            texts[1]
        );
        assert!(texts[1].contains(&decision.justification), "{}", texts[1]);
        assert!(
            texts[1].contains(&format!("{} argumento(s)", decision.parameters.len())),
            "{}",
            texts[1]
        );
        assert_eq!(texts[2], "análise em andamento (10s)");
        assert_eq!(texts[3], "ferramenta read_file no achado #1");
        assert_eq!(texts[4], "read_file ok · 4 | raise ValueError");
        assert_eq!(texts[5], "achado #1 concluído (localizado)");
        assert_eq!(texts[6], "A LLM principal falhou; usando o modelo local");

        assert!(
            app.ai_timeline.iter().all(|entry| {
                let bytes = entry.time.as_bytes();
                entry.time.len() == 8 && bytes[2] == b':' && bytes[5] == b':'
            }),
            "todo evento carrega o horário local no formato HH:MM:SS"
        );
    }

    #[test]
    fn elapsed_uses_mm_ss_and_hh_mm_ss() {
        assert_eq!(format_elapsed(0), "00:00");
        assert_eq!(format_elapsed(65), "01:05");
        assert_eq!(format_elapsed(3661), "01:01:01");
    }

    #[test]
    fn replay_loads_findings_and_opens_the_results_screen() {
        use serde_json::json;

        let finding = Vulnerability {
            title: "Cabeçalho ausente".to_string(),
            severity: crate::domain::Severity::High,
            description: "descrição".to_string(),
            tool: "Nuclei".to_string(),
            target: "http://alvo.local".to_string(),
            evidence: "evidência".to_string(),
            detected_at: "2026-10-22T12:00:00Z".to_string(),
            ..Default::default()
        };
        let metadata: crate::orchestrator::scan_logger::ScanMetadata =
            serde_json::from_value(json!({
                "scan_id": "scan_123",
                "target_url": "http://alvo.local",
                "started_at": "2026-10-22T12:00:00Z",
                "completed_at": "2026-10-22T12:01:00Z",
                "execution_type": "Assistido",
                "llm_provider": "OpenAI",
                "tools_executed": [],
                "findings_count": 1,
                "critical_count": 0,
                "high_count": 1,
                "medium_count": 0,
                "low_count": 0,
                "findings": [serde_json::to_value(&finding).unwrap()],
                "agent_analysis": "resumo da IA",
                "rag_explanations": [serde_json::to_value(rag_result(true)).unwrap()]
            }))
            .expect("log de replay válido");

        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        app.load_replayed_scan(metadata).expect("replay válido");

        assert_eq!(app.step, AppStep::Results);
        assert_eq!(app.orchestrator.findings.len(), 1);
        assert_eq!(app.config.target_url, "http://alvo.local");
        assert_eq!(app.agent.last_analysis, "resumo da IA");
        assert_eq!(app.rag_results.len(), 1);
        assert!(app
            .rag_results
            .values()
            .next()
            .is_some_and(|r| r.approved()));
    }

    #[test]
    fn ai_timeline_keeps_the_end_by_default_and_respects_manual_scroll() {
        let mut app = app();
        for index in 0..AI_TIMELINE_LIMIT {
            app.push_ai_timeline(AiTimelineOrigin::Ai, format!("evento {index}"));
        }
        assert!(app.ai_timeline_follow, "por padrão o painel segue o fim");
        assert_eq!(app.ai_timeline.len(), AI_TIMELINE_LIMIT);

        app.ai_timeline_follow = false;
        app.ai_timeline_scroll = 7;
        for _ in 0..3 {
            app.push_ai_timeline(AiTimelineOrigin::Ai, "mais um evento");
        }
        assert_eq!(
            app.ai_timeline.len(),
            AI_TIMELINE_LIMIT,
            "retenção limitada"
        );
        assert_eq!(
            app.ai_timeline_scroll, 4,
            "o descarte do topo desconta o offset manual"
        );
        assert!(!app.ai_timeline_follow);
    }

    fn rag_result(approved: bool) -> crate::cyberrag::service::ExplanationResult {
        crate::cyberrag::service::ExplanationResult {
            finding_index: 0,
            text: if approved {
                "Explicação".to_string()
            } else {
                String::new()
            },
            conceito: "injecao_sql".to_string(),
            example: None,
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

    #[tokio::test]
    async fn a_rag_explanation_updates_the_state_and_the_structured_log() {
        let mut app = app();
        app.orchestrator.findings = vec![finding(Severity::High, "Achado")];
        let (sender, receiver) = run_channel();
        app.rag_receiver = Some(receiver);
        app.rag_pending = Some(0);
        sender
            .try_send(RunEvent::RagExplanationFinished {
                finding_index: 0,
                result: Box::new(rag_result(true)),
            })
            .expect("canal aberto");

        app.process_rag_events();

        assert_eq!(app.rag_pending, None);
        assert!(app
            .rag_results
            .get(&0)
            .is_some_and(|stored| stored.approved()));
        assert!(app.exec_logs().iter().any(|line| line.starts_with("[rag]")));
        let metadata = app.orchestrator.scan_metadata();
        assert_eq!(metadata.rag_explanations_count, 1);
        assert!(
            metadata.rag_ontology_verdict.contains("aprovada"),
            "{}",
            metadata.rag_ontology_verdict
        );
    }

    #[tokio::test]
    async fn run_events_update_progress_findings_and_audit_path() {
        let mut app = app();
        app.step = AppStep::Execution;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);

        feed(&mut app, &sender, RunEvent::ToolStarted(0)).await;
        assert_eq!(app.tools[0].status, ToolStatus::Running);
        assert!(app.exec_logs().is_empty());
        assert_eq!(
            app.finished_tools(),
            (0, app.tools.iter().filter(|tool| tool.selected).count()),
            "o progresso geral só conta ferramentas em estado terminal"
        );

        feed(
            &mut app,
            &sender,
            RunEvent::ToolLog("[12:00:01] $ podman create --name smartsec-test".to_string()),
        )
        .await;
        assert!(app.exec_logs()[0].contains("$ podman create"));
        assert!(app.exec_logs()[0].starts_with("[Nmap]"));

        feed(
            &mut app,
            &sender,
            RunEvent::ToolFinished {
                index: 0,
                execution: Box::new(succeeded_execution("Nmap")),
            },
        )
        .await;
        let mut orchestrator =
            Orchestrator::new(Configuration::default()).expect("configuração de teste válida");
        orchestrator.findings.push(Vulnerability {
            title: "Achado real".to_string(),
            severity: Severity::Info,
            description: "Descrição".to_string(),
            tool: "Nmap".to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: FindingSource::Real,
            target: "http://target.local".to_string(),
            evidence: "porta aberta".to_string(),
            detected_at: "2026-09-04T14:00:00Z".to_string(),
            origins: Vec::new(),
            enrichment: None,
            severity_conflict: None,
            ..Default::default()
        });
        orchestrator.last_log = "Análise real".to_string();
        let audit_path = PathBuf::from("/tmp/scan.json");
        feed(
            &mut app,
            &sender,
            RunEvent::Completed {
                orchestrator: Box::new(orchestrator_with(
                    vec![finding(Severity::Critical, "Achado real")],
                    Vec::new(),
                )),
                audit_log: Ok(audit_path.clone()),
            },
        )
        .await;

        assert_eq!(app.tools[0].status, ToolStatus::Done);
        assert_eq!(app.orchestrator.findings.len(), 1);
        assert_eq!(app.audit_log_path.as_ref(), Some(&audit_path));
        assert_eq!(app.step, AppStep::Results);
        assert_eq!(app.ai_activity, AiActivity::Complete);
        assert_eq!(app.run_error, None);
    }

    /// A lista da TUI põe os críticos no topo sem alterar a severidade do
    /// scanner (REQ15) e sem mexer na ordem do relatório.
    #[test]
    fn critical_findings_come_first_without_touching_severities() {
        let mut app = app();
        app.orchestrator.findings = vec![
            finding(Severity::Info, "Versão exposta"),
            finding(Severity::Medium, "Cabeçalho ausente"),
            finding(Severity::Critical, "Shell remota aberta"),
            finding(Severity::High, "Painel administrativo"),
        ];

        let ordered = app.vulnerabilities();
        let titles: Vec<&str> = ordered.iter().map(|item| item.title.as_str()).collect();

        assert_eq!(
            titles,
            vec![
                "Shell remota aberta",
                "Painel administrativo",
                "Cabeçalho ausente",
                "Versão exposta"
            ]
        );
        assert_eq!(
            app.orchestrator.findings[0].severity,
            Severity::Info,
            "o pipeline mantém a ordem original dos achados"
        );
        assert!(app.export_md().contains("Versão exposta"));
    }

    /// A ordem exibida é memoizada, então precisa acompanhar troca real de
    /// severidade sem continuar servindo a lista antiga.
    #[test]
    fn the_display_order_cache_follows_real_changes_in_the_findings() {
        let mut app = app();
        let titles = |app: &AppState| -> Vec<String> {
            app.vulnerabilities()
                .iter()
                .map(|item| item.title.clone())
                .collect()
        };

        app.orchestrator.findings = vec![
            finding(Severity::Info, "Primeiro"),
            finding(Severity::Critical, "Segundo"),
        ];
        assert_eq!(titles(&app), vec!["Segundo", "Primeiro"]);

        // Mesmo número de achados com severidades trocadas: a ordem muda.
        app.orchestrator.findings = vec![
            finding(Severity::Critical, "Terceiro"),
            finding(Severity::Info, "Quarto"),
        ];
        assert_eq!(titles(&app), vec!["Terceiro", "Quarto"]);

        // Só a severidade do último mudou: o empate preserva a ordem do pipeline.
        app.orchestrator.findings[1].severity = Severity::Critical;
        assert_eq!(titles(&app), vec!["Terceiro", "Quarto"]);

        // Troca de posições com severidades iguais: a ordem acompanha o vetor.
        app.orchestrator.findings.swap(0, 1);
        assert_eq!(titles(&app), vec!["Quarto", "Terceiro"]);

        // O achado é emprestado, não copiado: o texto exibido é o atual.
        app.orchestrator.findings[0].title = "Quarto revisado".to_string();
        assert_eq!(titles(&app), vec!["Quarto revisado", "Terceiro"]);
    }

    /// Testa o caminho real do `Paragraph` para provar que a contagem memoizada
    /// por linha é igual à quebra do texto completo.
    fn render_log_area(app: &mut AppState, width: u16, height: u16) {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("terminal de teste");
        terminal
            .draw(|frame| crate::tui::render(app, frame))
            .expect("render da execução");
    }

    fn long_log_lines(count: usize) -> Vec<String> {
        (0..count)
            .map(|index| format!("L{index}-INICIO{}{index}FIM", "x".repeat(200)))
            .collect()
    }

    #[test]
    fn the_memoized_log_rows_match_the_paragraph_wrap() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        for line in long_log_lines(5_010) {
            app.push_exec_log(line);
        }

        render_log_area(&mut app, 80, 24);

        assert_eq!(app.exec_logs().len(), 5_000, "limite de retenção");
        let esperado = Paragraph::new(Text::from(
            app.exec_logs()
                .iter()
                .map(|line| Line::from(line.as_str()))
                .collect::<Vec<_>>(),
        ))
        .wrap(Wrap { trim: false })
        .line_count(app.log_width);
        assert_eq!(
            app.log_total_lines, esperado,
            "o total memoizado precisa ser igual ao do Paragraph"
        );

        let estreito = app.log_total_lines;
        render_log_area(&mut app, 120, 24);
        assert!(
            app.log_total_lines < estreito,
            "outra largura invalida a medida: {} não é menor que {estreito}",
            app.log_total_lines
        );
    }

    /// A janela precisa pintar o mesmo buffer que o texto completo, inclusive
    /// quando o offset cai no meio de uma linha quebrada.
    #[test]
    fn the_log_window_paints_the_same_buffer_as_the_full_text() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = app();
        app.step = AppStep::Execution;
        app.set_exec_logs(long_log_lines(120));

        let width = 60u16;
        let height = 16u16;
        let render_with = |lines: &[String], scroll: u16| {
            let backend = TestBackend::new(width, height);
            let mut terminal = Terminal::new(backend).expect("terminal de teste");
            terminal
                .draw(|frame| {
                    frame.render_widget(
                        Paragraph::new(Text::from(
                            lines
                                .iter()
                                .map(|line| Line::from(line.as_str()))
                                .collect::<Vec<_>>(),
                        ))
                        .wrap(Wrap { trim: false })
                        .scroll((scroll, 0)),
                        frame.area(),
                    );
                })
                .expect("render");
            terminal.backend().buffer().clone()
        };

        app.sync_log_rows(width);
        let total = app.log_total_lines;
        for first_row in [0usize, 1, 7, 42, total / 2, total - 1] {
            let (start, end, offset) = app.log_window(first_row, height as usize);
            let completo = render_with(app.exec_logs(), first_row as u16);
            let janela = render_with(&app.exec_logs()[start..end], offset);
            assert_eq!(
                completo, janela,
                "janela diferente do texto completo na linha {first_row} \
                 (início {start}, fim {end}, offset {offset})"
            );
        }
    }

    #[tokio::test]
    async fn disconnected_worker_surfaces_an_error_instead_of_hanging() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.tools[0].status = ToolStatus::Running;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);
        app.run_task = Some(tokio::spawn(std::future::pending()));
        drop(sender);

        app.process_run_events().await;

        assert_eq!(app.step, AppStep::Results);
        assert_eq!(app.tools[0].status, ToolStatus::Failed);
        assert!(app.run_error.is_some());
        assert!(app
            .run_issues
            .iter()
            .any(|issue| issue.scope == RunIssueScope::Executor));
        assert!(app.run_task.is_none(), "o JoinHandle é liberado sem await");
    }

    #[test]
    fn cancel_run_stops_the_pipeline_and_keeps_the_audit() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.tools[0].status = ToolStatus::Running;
        app.audit_log_path = None;

        app.cancel_run();

        assert!(app.exec_cancelled);
        assert!(app.orchestrator.control.is_cancelled());
        // O canal nao e descartado: o cancelamento e cooperativo, e o trace da
        // limpeza do container ainda chega pelo executor. O que impede um evento
        // tardio de reabrir a tela e a flag `exec_cancelled`, conferida acima e
        // respeitada por `advance_auto`.
        assert!(
            app.exec_cancelled,
            "o cancelamento precisa barrar o modo automatico"
        );
        assert!(app
            .exec_logs()
            .iter()
            .any(|line| line.contains("CANCELADA")));
        assert_eq!(
            app.orchestrator
                .execution_history
                .last()
                .map(|execution| execution.status.as_str()),
            Some("cancelled")
        );
        if let Some(path) = app.audit_log_path.clone() {
            let _ = std::fs::remove_file(path);
        }
    }

    /// O cancelamento precisa ser estável: no modo automático a execução não
    /// recomeça sozinha, e o reinício depende de uma ação do usuário.
    #[test]
    fn a_cancelled_run_does_not_restart_itself_in_automatic_mode() {
        let mut app = app();
        app.set_mode(crate::config::execution_type::ExecutionType::Auto);
        app.step = AppStep::Execution;
        app.tools[0].status = ToolStatus::Running;

        app.cancel_run();
        app.tick();

        assert_eq!(
            app.step,
            AppStep::ToolSelect,
            "o cancelamento leva à seleção e a execução não volta sozinha"
        );
        assert!(app.exec_cancelled);
        if let Some(path) = app.audit_log_path.clone() {
            let _ = std::fs::remove_file(path);
        }
    }

    #[tokio::test]
    async fn shutdown_run_aborts_the_executor_without_blocking() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.tools[0].status = ToolStatus::Running;
        app.run_task = Some(tokio::spawn(std::future::pending()));

        app.shutdown_run().await;

        assert!(app.run_task.is_none());
        assert!(app.run_receiver.is_none());
        assert!(app.orchestrator.control.is_cancelled());
        if let Some(path) = app.audit_log_path.clone() {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Sob saturação o log é descartado e contabilizado, nunca bloqueado: a
    /// teclado, o auto-follow e a renderização seguem reagindo.
    #[tokio::test]
    async fn log_pressure_drops_instead_of_blocking_and_is_reported() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        app.log_follow = true;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);
        app.log_drop_counter = Arc::new(AtomicU64::new(0));

        let mut delivered = 0usize;
        let mut dropped = 0u64;
        for index in 0..(RUN_EVENT_CAPACITY * 4) {
            match sender.try_send(RunEvent::ToolLog(format!("linha {index}"))) {
                Ok(()) => delivered += 1,
                Err(TrySendError::Full(_)) => dropped += 1,
                Err(TrySendError::Closed(_)) => panic!("canal fechado"),
            }
        }
        assert_eq!(delivered, RUN_EVENT_CAPACITY);
        assert!(dropped > 0);
        app.log_drop_counter.store(dropped, Ordering::Relaxed);

        app.step_tick().await;

        assert_eq!(app.exec_logs().len(), RUN_EVENT_CAPACITY);
        assert_eq!(app.dropped_log_lines(), dropped);
        assert_eq!(
            app.log_scroll,
            app.log_max_scroll(),
            "auto-follow preservado"
        );
        assert!(app.log_follow);
    }

    #[tokio::test]
    async fn new_log_lines_respect_manual_scroll_and_resume_following() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        app.log_visible_height = 10;
        app.log_total_lines = 100;
        app.log_follow = false;
        app.log_scroll = 5;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);

        feed(
            &mut app,
            &sender,
            RunEvent::ToolLog("nova linha".to_string()),
        )
        .await;
        assert_eq!(
            app.log_scroll, 5,
            "novas mensagens não podem puxar a tela após o usuário subir"
        );
        assert!(!app.log_follow);

        app.log_follow = true;
        feed(
            &mut app,
            &sender,
            RunEvent::ToolLog("outra linha".to_string()),
        )
        .await;
        assert_eq!(app.log_scroll, app.log_max_scroll());
        assert_eq!(app.log_scroll, 90);
    }

    #[tokio::test]
    async fn draining_old_entries_shifts_the_manual_scroll_by_visual_rows() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        app.log_visible_height = 10;
        app.log_width = 10;
        app.log_total_lines = 200;
        app.set_exec_logs(vec!["x".repeat(25); 5000]);
        app.log_follow = false;
        app.log_scroll = 100;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);

        feed(
            &mut app,
            &sender,
            RunEvent::ToolLog("nova linha".to_string()),
        )
        .await;

        assert_eq!(app.exec_logs().len(), 5000);
        assert_eq!(
            app.log_scroll, 97,
            "o offset deve andar pelas linhas visuais removidas, não por entradas"
        );
        assert_eq!(app.log_total_lines, 197);
        assert!(!app.log_follow);
    }

    #[test]
    fn cancel_run_uses_the_control_channel_instead_of_aborting_the_task() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        app.step = AppStep::Execution;
        app.tools[0].status = ToolStatus::Running;

        app.cancel_run();

        assert!(app.exec_cancelled);
        assert!(
            app.orchestrator.is_cancelled(),
            "o cancelamento precisa chegar ao container pelo canal compartilhado"
        );
        assert!(
            app.run_task.is_none(),
            "não existe task de execução fora da tela de execução"
        );
        let reason = app
            .orchestrator
            .interruption()
            .expect("o cancelamento precisa ser auditável");
        assert_eq!(reason.rule, "cancelado_pelo_usuario");
    }

    #[test]
    fn pause_and_resume_travel_through_the_shared_control_channel() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        app.step = AppStep::Execution;
        app.tools[0].status = ToolStatus::Running;

        app.pause_run();
        assert!(app.orchestrator.control.is_paused());
        assert_eq!(app.tools[0].status, ToolStatus::Paused);

        // Pausar de novo não muda o pedido.
        app.pause_run();
        assert!(app.orchestrator.control.is_paused());

        app.resume_run();
        assert!(!app.orchestrator.control.is_paused());
        assert_eq!(app.tools[0].status, ToolStatus::Running);

        // O cancelamento encerra a linha: a retomada posterior é ignorada.
        app.cancel_run();
        app.resume_run();
        assert!(app.orchestrator.control.is_cancelled());
    }

    #[test]
    fn run_control_events_drive_the_visible_tool_status() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        app.step = AppStep::Execution;
        app.tools[0].status = ToolStatus::Running;

        // O executor confirma a pausa de fato aplicada no container.
        app.apply_run_control(crate::orchestrator::control::RunControl::Paused);
        assert!(app.exec_paused);
        assert_eq!(app.tools[0].status, ToolStatus::Paused);

        app.apply_run_control(crate::orchestrator::control::RunControl::Running);
        assert!(!app.exec_paused);
        assert_eq!(app.tools[0].status, ToolStatus::Running);
    }

    #[test]
    fn the_cancelled_run_is_recorded_for_audit_without_creating_findings() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        app.step = AppStep::Execution;
        app.tools[0].status = ToolStatus::Running;

        app.persist_cancelled_run();

        let cancelled: Vec<_> = app
            .orchestrator
            .execution_history
            .iter()
            .filter(|execution| execution.status == "cancelled")
            .collect();
        assert_eq!(cancelled.len(), 1, "um registro sintético por cancelamento");
        assert!(app.orchestrator.findings.is_empty());
        assert!(
            app.audit_log_path.is_some(),
            "a auditoria precisa ser gravada"
        );
        let log = std::fs::read_to_string(app.audit_log_path.as_ref().unwrap()).unwrap();
        assert!(log.contains("cancelado_pelo_usuario"), "{log}");
    }

    #[test]
    fn log_max_scroll_saturates_at_u16_range() {
        let mut app = app();
        app.log_total_lines = usize::MAX;
        app.log_visible_height = 1;

        assert_eq!(app.log_max_scroll(), u16::MAX as usize);
    }

    /// Rascunho recém-aberto é cópia do gravado: nada pendente e sem aviso.
    #[test]
    fn a_fresh_settings_draft_has_no_pending_changes() {
        let app = app();

        assert_eq!(app.settings_dirty_count(), 0);
        for field in app.visible_settings_fields() {
            assert!(
                !app.settings_field_changed(field),
                "{field:?} recém-aberto não pode contar como alterado"
            );
        }
    }

    /// Cada campo editado entra na conta do aviso, inclusive o interruptor e o
    /// diretório do projeto, que não são texto.
    #[test]
    fn editing_a_field_marks_it_as_pending_until_it_is_saved() {
        let mut app = app();
        app.settings_input_timeout = "7".to_string();
        app.settings_fallback_enabled = true;
        app.settings_input_project_dir = "/tmp".to_string();

        assert!(app.settings_field_changed(SettingsField::Timeout));
        assert!(app.settings_field_changed(SettingsField::FallbackEnabled));
        assert!(app.settings_field_changed(SettingsField::ProjectDir));
        assert!(!app.settings_field_changed(SettingsField::BaseUrl));
        assert_eq!(app.settings_dirty_count(), 3);
    }

    /// A chave de API só conta como alterada depois que o operador digita: o
    /// valor em rascunho é o mesmo segredo e não pode aparecer como pendência.
    #[test]
    fn the_api_key_only_counts_as_pending_after_being_typed() {
        let mut app = app();
        app.settings_provider_idx = 1;
        app.settings_input_base_url = "https://api.openai.com/v1".to_string();
        app.settings_input_api_key = "chave-antiga".to_string();
        app.config.llm.api_key = "chave-antiga".to_string();

        assert!(!app.settings_field_changed(SettingsField::ApiKey));

        app.settings_api_key_touched = true;
        assert!(!app.settings_field_changed(SettingsField::ApiKey));

        app.settings_input_api_key = "chave-nova".to_string();
        assert!(app.settings_field_changed(SettingsField::ApiKey));
    }

    /// Depois de aplicar a configuração, o aviso de pendências não pode
    /// sobreviver: ele descreveria um estado que não existe mais.
    #[test]
    fn applying_the_settings_clears_the_pending_change_count() {
        let mut app = app();
        app.settings_input_retries = "3".to_string();
        assert_eq!(app.settings_dirty_count(), 1);

        app.commit_settings(app.settings_candidate().expect("candidato válido"));

        assert_eq!(app.settings_dirty_count(), 0);
    }

    fn temp_profile_project(label: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "smartsec-preselecao-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        for (relative, contents) in files {
            let path = root.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(path, contents).unwrap();
        }
        root
    }

    fn app_with_project(root: &std::path::Path, active_tools: Vec<String>) -> AppState {
        let config = Configuration {
            project_dir: Some(root.display().to_string()),
            active_tools,
            ..Configuration::default()
        };
        AppState::new(config).expect("configuração de teste válida")
    }

    fn selected_of(app: &AppState, name: &str) -> bool {
        app.tools
            .iter()
            .find(|tool| tool.tool.name == name)
            .unwrap_or_else(|| panic!("{name} deveria estar no catálogo"))
            .selected
    }

    fn recommendation_of(app: &AppState, name: &str) -> Option<&'static str> {
        app.tools
            .iter()
            .find(|tool| tool.tool.name == name)
            .unwrap_or_else(|| panic!("{name} deveria estar no catálogo"))
            .recommendation
    }

    /// A recomendação marca as ferramentas e guarda o motivo de cada uma; o
    /// perfil do projeto fica resumido para a tela.
    #[test]
    fn the_profile_recommendation_marks_tools_and_explains_them() {
        let root = temp_profile_project(
            "nosql",
            &[(
                "package.json",
                r#"{"dependencies":{"mongoose":"^8.0.0","redis":"^4.6.0"}}"#,
            )],
        );
        let mut app = app_with_project(&root, Vec::new());

        assert!(app.tool_preselection.is_none());
        app.apply_tool_preselection();

        assert!(!selected_of(&app, "SQLMap"), "projeto NoSQL sem SQL");
        assert_eq!(
            recommendation_of(&app, "SQLMap"),
            Some(crate::project_profile::NO_SQL_NOSQL_REASON)
        );
        assert!(selected_of(&app, "Nmap"));
        assert_eq!(
            recommendation_of(&app, "Nmap"),
            Some(crate::project_profile::NMAP_REASON)
        );
        assert!(!selected_of(&app, "TruffleHog"), "sem .git no fixture");
        assert!(app.project_profile_summary.is_some());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A assinatura impede reaplicar a recomendação: o ajuste manual do
    /// usuário não é sobrescrito na volta à tela.
    #[test]
    fn the_recommendation_is_not_reapplied_over_a_manual_toggle() {
        let root = temp_profile_project(
            "ajuste",
            &[("package.json", r#"{"dependencies":{"mongoose":"^8.0.0"}}"#)],
        );
        let mut app = app_with_project(&root, Vec::new());

        app.apply_tool_preselection();
        assert!(!selected_of(&app, "SQLMap"));

        app.tools
            .iter_mut()
            .find(|tool| tool.tool.name == "SQLMap")
            .unwrap()
            .selected = true;
        app.apply_tool_preselection();

        assert!(
            selected_of(&app, "SQLMap"),
            "toggle manual do usuário sempre vence"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Trocar o projeto recalculou o perfil: a recomendação acompanha.
    #[test]
    fn changing_the_project_recomputes_the_recommendation() {
        let nosql = temp_profile_project(
            "troca-nosql",
            &[("package.json", r#"{"dependencies":{"mongoose":"^8.0.0"}}"#)],
        );
        let sqlite = temp_profile_project("troca-sqlite", &[("app.py", "import sqlite3\n")]);
        let mut app = app_with_project(&nosql, Vec::new());

        app.apply_tool_preselection();
        assert!(!selected_of(&app, "SQLMap"));

        app.config.project_dir = Some(sqlite.display().to_string());
        app.apply_tool_preselection();

        assert!(selected_of(&app, "SQLMap"));
        assert_eq!(
            recommendation_of(&app, "SQLMap"),
            Some(crate::project_profile::SQL_REASON)
        );

        let _ = std::fs::remove_dir_all(&nosql);
        let _ = std::fs::remove_dir_all(&sqlite);
    }

    /// Lista explícita em `config.active_tools` é do usuário: manda na seleção
    /// inicial e desliga a recomendação do perfil.
    #[test]
    fn explicit_active_tools_win_over_the_recommendation() {
        let root = temp_profile_project(
            "lista",
            &[("package.json", r#"{"dependencies":{"mongoose":"^8.0.0"}}"#)],
        );
        let mut app = app_with_project(&root, vec!["Nmap".to_string(), "Nikto".to_string()]);

        assert!(selected_of(&app, "Nmap"));
        assert!(selected_of(&app, "Nikto"));
        assert!(!selected_of(&app, "SQLMap"));

        app.apply_tool_preselection();

        assert!(
            selected_of(&app, "Nikto"),
            "a lista explícita continua valendo"
        );
        assert!(!selected_of(&app, "SQLMap"));
        assert!(app.tools.iter().all(|tool| tool.recommendation.is_none()));
        assert!(app.project_profile_summary.is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Projeto inacessível: sem perfil, nada é desmarcado por dúvida.
    #[test]
    fn an_unreadable_project_keeps_every_tool_selected() {
        let missing = std::env::temp_dir().join(format!(
            "smartsec-preselecao-inexistente-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&missing);
        let mut app = app_with_project(&missing, Vec::new());

        app.apply_tool_preselection();

        assert!(
            app.tools.iter().all(|tool| tool.selected),
            "sem perfil vale o comportamento de hoje: tudo marcado"
        );
        assert!(app.tools.iter().all(|tool| tool.recommendation.is_none()));
        assert!(app.project_profile_summary.is_none());
    }
}
