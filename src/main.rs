//! SmartSec - Security Analysis Platform
//!
//! Entry point: `CommandLineInterface::main`.
//!
//! Supports interactive TUI mode and structured `scan`/`tool` commands.

mod ai;
mod code_agent;
mod config;
mod domain;
mod llm;
mod orchestrator;
mod report;
mod tools;
mod tui;
mod utils;

use crate::config::execution_type::ExecutionType;
use crate::domain::vulnerability::Vulnerability;
use crate::domain::Severity;
use crate::orchestrator::Orchestrator;
use crate::tools::registry::{RegisteredTool, ToolRegistry};
use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;

/// Contrato de saída do modo headless (TCC_SPEC.md, seção 10).
const EXIT_SUCCESS: i32 = 0;
const EXIT_CRITICAL: i32 = 1;
const EXIT_ERROR: i32 = 2;

/// CommandLineInterface (per class diagram).
///
/// Responsible for parsing arguments, initializing configuration, and
/// displaying the TUI. The actual analysis work is delegated to the
/// [`orchestrator::Orchestrator`].
pub struct CommandLineInterface {
    pub arguments: Vec<String>,
}

#[derive(Debug)]
struct Cli {
    command: Option<CliCommand>,
}

#[derive(Debug)]
enum CliCommand {
    Scan(ScanArgs),
    Tool(ToolArgs),
    History(HistoryArgs),
    Show(ShowArgs),
}

#[derive(Debug)]
struct ScanArgs {
    target: String,
    options: ExecutionArgs,
}

#[derive(Debug)]
struct ToolArgs {
    tool: String,
    target: String,
    options: ExecutionArgs,
}

/// Argumentos de `history`: listagem das execuções com limite configurável.
#[derive(Debug)]
struct HistoryArgs {
    limit: usize,
}

/// Argumentos de `show`: abertura de uma execução pelo `scan_id`.
#[derive(Debug)]
struct ShowArgs {
    scan_id: String,
}

#[derive(Debug, Clone, Default)]
struct ExecutionArgs {
    config: Option<std::path::PathBuf>,
    tools: Option<String>,
    llm: Option<String>,
    model: Option<String>,
    output: Option<String>,
    output_dir: Option<String>,
}

impl Cli {
    fn parse(arguments: &[String]) -> Result<Self> {
        if arguments
            .iter()
            .any(|argument| argument == "--version" || argument == "-V")
        {
            println!("smartsec-rust 0.2.0");
            return Ok(Self { command: None });
        }
        if arguments.is_empty() {
            return Ok(Self { command: None });
        }
        if arguments
            .iter()
            .any(|argument| argument == "--help" || argument == "-h")
        {
            print_help();
            return Ok(Self { command: None });
        }
        let command = arguments[0].as_str();
        match command {
            "history" => {
                let limit = parse_history_limit(&arguments[1..])?;
                return Ok(Self {
                    command: Some(CliCommand::History(HistoryArgs { limit })),
                });
            }
            "show" => {
                let scan_id = arguments
                    .get(1)
                    .ok_or_else(|| anyhow::anyhow!("o scan_id da execução é obrigatório"))?;
                if scan_id.starts_with('-') {
                    anyhow::bail!("o scan_id da execução deve vir antes das opções; use --help para ver as opções");
                }
                if arguments.len() > 2 {
                    anyhow::bail!(
                        "argumento desconhecido: {}; use --help para ver as opções",
                        arguments[2]
                    );
                }
                return Ok(Self {
                    command: Some(CliCommand::Show(ShowArgs {
                        scan_id: scan_id.clone(),
                    })),
                });
            }
            _ => {}
        }
        let (tool, start) = match command {
            "scan" => (None, 1),
            "tool" => {
                let tool = arguments
                    .get(1)
                    .ok_or_else(|| anyhow::anyhow!("a ferramenta é obrigatória"))?;
                (Some(tool.clone()), 2)
            }
            other => anyhow::bail!("comando desconhecido: {other}; use --help para ver as opções"),
        };
        let (target, options) = parse_execution_args(&arguments[start..])?;
        let target = target.ok_or_else(|| anyhow::anyhow!("o argumento --target é obrigatório"))?;
        Ok(Self {
            command: Some(if let Some(tool) = tool {
                CliCommand::Tool(ToolArgs {
                    tool,
                    target,
                    options,
                })
            } else {
                CliCommand::Scan(ScanArgs { target, options })
            }),
        })
    }
}

fn parse_execution_args(arguments: &[String]) -> Result<(Option<String>, ExecutionArgs)> {
    let mut target = None;
    let mut options = ExecutionArgs::default();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        let value = |index: &mut usize, name: &str| -> Result<String> {
            *index += 1;
            arguments
                .get(*index)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("o argumento {name} exige um valor"))
        };
        match argument.as_str() {
            "--target" | "-t" => target = Some(value(&mut index, "--target")?),
            "--config" => options.config = Some(value(&mut index, "--config")?.into()),
            "--tools" => options.tools = Some(value(&mut index, "--tools")?),
            "--llm" => options.llm = Some(value(&mut index, "--llm")?),
            "--model" => options.model = Some(value(&mut index, "--model")?),
            "--output" | "-o" => options.output = Some(value(&mut index, "--output")?),
            "--output-dir" => options.output_dir = Some(value(&mut index, "--output-dir")?),
            other => {
                anyhow::bail!("argumento desconhecido: {other}; use --help para ver as opções")
            }
        }
        index += 1;
    }
    Ok((target, options))
}

/// Interpreta o limite de `history` (`--limit`, `-n` ou `--limite`).
///
/// Valores ausentes assumem o padrão; valores inválidos ou zero são recusados
/// com mensagem acionável, pois um limite vazio esconderia execuções.
fn parse_history_limit(arguments: &[String]) -> Result<usize> {
    const DEFAULT_LIMIT: usize = 20;
    let mut limit = DEFAULT_LIMIT;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if !matches!(argument, "--limit" | "-n" | "--limite") {
            anyhow::bail!("argumento desconhecido: {argument}; use --help para ver as opções");
        }
        index += 1;
        let value = arguments
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("o argumento {argument} exige um valor"))?;
        limit = value.parse::<usize>().map_err(|_| {
            anyhow::anyhow!("o limite deve ser um número inteiro maior que zero: {value}")
        })?;
        if limit == 0 {
            anyhow::bail!("o limite deve ser maior que zero");
        }
        index += 1;
    }
    Ok(limit)
}

fn print_help() {
    println!("SmartSec - Plataforma de análise de segurança");
    println!("Uso: smartsec <scan|tool> --target <ALVO> [OPÇÕES]");
    println!("     smartsec history [--limit <N>]");
    println!("     smartsec show <SCAN_ID>");
    println!("\nComandos:\n  scan              Executa uma varredura não interativa.\n  tool <FERRAMENTA> Executa manualmente uma ferramenta.\n  history           Lista as execuções recentes do histórico.\n  show <SCAN_ID>    Mostra o detalhe de uma execução pelo identificador.");
    println!("\nOpções:\n  -t, --target <ALVO>  IP, domínio ou URL\n      --config <ARQUIVO>  Configuração TOML\n      --tools <LISTA>  Ferramentas reais separadas por vírgulas\n      --llm <PROVEDOR>  ollama, openai, nvidia-nim ou custom\n      --model <MODELO>  Modelo da IA\n  -o, --output <ARQUIVO>  Relatório Markdown (padrão: smartsec-report.md)\n      --output-dir <DIRETORIO>  Diretório de saída do relatório\n  -n, --limit <N>        Quantidade de execuções exibidas por 'history' (padrão: 20)\n  -h, --help\n  -V, --version");
    println!("\nCódigos de saída:\n  0  nenhuma vulnerabilidade crítica\n  1  vulnerabilidade crítica encontrada\n  2  erro de configuração, de execução ou de consulta ao histórico");
}

impl CommandLineInterface {
    pub fn new(arguments: Vec<String>) -> Self {
        Self { arguments }
    }

    pub async fn run(self) -> Result<i32> {
        let cli = Cli::parse(&self.arguments)?;
        if self
            .arguments
            .iter()
            .any(|argument| matches!(argument.as_str(), "--help" | "-h" | "--version" | "-V"))
        {
            return Ok(EXIT_SUCCESS);
        }
        match cli.command {
            Some(CliCommand::Scan(args)) => {
                let config = build_config(&args.options, args.target, None, true)?;
                Self::run_headless(config).await
            }
            Some(CliCommand::Tool(args)) => {
                let config = build_config(&args.options, args.target, Some(args.tool), true)?;
                Self::run_headless(config).await
            }
            Some(CliCommand::History(args)) => Ok(Self::print_history(args.limit)),
            Some(CliCommand::Show(args)) => Ok(Self::print_scan_detail(&args.scan_id)),
            None => {
                let config = config::Configuration::load(&[])?;
                Self::display_tui(config).await?;
                Ok(EXIT_SUCCESS)
            }
        }
    }

    async fn display_tui(initial_config: config::Configuration) -> Result<()> {
        let mut app = tui::state::AppState::new(initial_config)?;

        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let result = Self::tui_loop(&mut terminal, &mut app).await;

        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        result
    }

    async fn tui_loop(
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
        app: &mut tui::state::AppState,
    ) -> Result<()> {
        loop {
            terminal.draw(|f| tui::render(app, f))?;

            let should_quit = tui::event::handle_events(app)?;
            if should_quit || app.should_quit {
                app.shutdown_run().await;
                return Ok(());
            }

            app.tick();
            app.step_tick().await;

            if app.should_quit {
                app.shutdown_run().await;
                return Ok(());
            }
        }
    }

    /// Lista as execuções gravadas no histórico, da mais recente para a mais antiga.
    ///
    /// A listagem é somente leitura: nenhum artefato original é alterado. Cada
    /// registro ilegível é informado ao usuário em vez de sumir em silêncio.
    fn print_history(limit: usize) -> i32 {
        use crate::orchestrator::scan_logger;

        let history = match scan_logger::list_scan_logs_from_dir(&scan_logger::scans_dir()) {
            Ok(history) => history,
            Err(error) => {
                eprintln!("Erro: {error:#}");
                return EXIT_ERROR;
            }
        };

        println!("═══════════════════════════════════════════════════════════");
        println!("  SmartSec — Histórico de execuções");
        println!("═══════════════════════════════════════════════════════════");

        if !history.directory_exists {
            println!("  Nenhuma execução registrada ainda.");
            println!(
                "  Diretório do histórico: {}",
                scan_logger::scans_dir().display()
            );
            println!("  Execute uma varredura para criar o primeiro registro.");
            return EXIT_SUCCESS;
        }

        if history.records.is_empty() {
            println!("  O histórico está vazio: nenhuma execução foi registrada.");
        } else {
            let shown = history.records.len().min(limit);
            println!(
                "  {} de {} execuções (limite {limit})",
                shown,
                history.records.len()
            );
            println!();
            for record in &history.records[..shown] {
                println!("  {}", record.scan_id);
                println!("    alvo         {}", record.target_url);
                println!("    concluída em {}", record.completed_at);
                println!(
                    "    execução     {} · {}",
                    record.execution_type,
                    record.severity_counts.label()
                );
            }
            if shown < history.records.len() {
                println!();
                println!("  {shown} execuções ocultas pelo limite; use --limit <N> para ver mais.");
            }
        }

        if let Some(warning) = history.unreadable_warning() {
            println!();
            println!("  ATENÇÃO: {warning}");
            for record in &history.unreadable {
                println!("    - {}: {}", record.file_name, record.reason);
            }
        }

        println!();
        println!("  Detalhe de uma execução: smartsec show <SCAN_ID>");
        println!("═══════════════════════════════════════════════════════════");
        EXIT_SUCCESS
    }

    /// Mostra o detalhe de uma execução a partir do `scan_id` informado.
    ///
    /// O `scan_id` é validado contra o padrão `scan_<nanos>` e resolvido dentro
    /// de `scans_dir()`; um identificador inexistente ou fora do padrão é um erro
    /// de consulta e retorna `EXIT_ERROR` (código 2), sem expor outros arquivos.
    fn print_scan_detail(scan_id: &str) -> i32 {
        use crate::orchestrator::scan_logger;

        let metadata = match scan_logger::load_scan_log_by_id(scan_id) {
            Ok(metadata) => metadata,
            Err(error) => {
                eprintln!("Erro: {error:#}");
                return EXIT_ERROR;
            }
        };
        let counts = scan_logger::ScanSeverityCounts::from_metadata(&metadata);

        println!("═══════════════════════════════════════════════════════════");
        println!("  SmartSec — Execução {scan_id}");
        println!("═══════════════════════════════════════════════════════════");
        println!("  alvo         {}", metadata.target_url);
        println!("  iniciada em  {}", metadata.started_at);
        println!("  concluída em {}", metadata.completed_at);
        println!(
            "  modo         {} · provedor {}",
            metadata.execution_type, metadata.llm_provider
        );
        println!("  achados      {}", counts.label());
        println!("  registros    {}", metadata.tools_executed.len());

        println!();
        println!("  Ferramentas executadas:");
        if metadata.tools_executed.is_empty() {
            println!("    (nenhuma ferramenta registrada)");
        }
        for execution in &metadata.tools_executed {
            println!(
                "    {:<12} {:<10} {} ms",
                execution.tool_name, execution.status, execution.duration_ms
            );
            if let Some(error) = &execution.execution_error {
                println!("      erro: {error}");
            }
        }

        println!();
        println!("  Achados:");
        if metadata.findings.is_empty() {
            println!("    (nenhum achado registrado)");
        }
        for finding in &metadata.findings {
            let title = finding
                .get("title")
                .and_then(|value| value.as_str())
                .unwrap_or("(achado sem título)");
            let severity = Severity::from_label(
                finding
                    .get("severity")
                    .and_then(|value| value.as_str())
                    .unwrap_or("Info"),
            )
            .label_pt_br();
            let tool = finding
                .get("tool")
                .and_then(|value| value.as_str())
                .unwrap_or("-");
            println!("    {severity:<12} {title} [{tool}]");
        }

        println!();
        println!("  Análise da IA:");
        if metadata.agent_analysis.trim().is_empty() {
            println!("    (sem análise registrada)");
        } else {
            for line in metadata.agent_analysis.lines() {
                println!("    │ {line}");
            }
        }

        if !metadata.decisions.is_empty() {
            println!();
            println!("  Decisões ({})", metadata.decisions.len());
            for decision in &metadata.decisions {
                println!(
                    "    [{}] {} — {}",
                    match decision.source {
                        crate::orchestrator::decision::DecisionSource::Ai => "IA",
                        crate::orchestrator::decision::DecisionSource::Fallback => "fallback",
                    },
                    decision.model,
                    decision.justification
                );
            }
        }

        println!("═══════════════════════════════════════════════════════════");
        EXIT_SUCCESS
    }

    pub async fn run_headless(config: config::Configuration) -> Result<i32> {
        config.validate_target().map_err(anyhow::Error::msg)?;

        println!("═══════════════════════════════════════════════════════════");
        println!("  SmartSec — Análise sem interface");
        println!("═══════════════════════════════════════════════════════════");
        println!("  Alvo:   {}", config.target_url);
        println!("  Modo:   {}", config.execution_type);
        println!("  Dados:  REAL");
        println!("  LLM:    {:?} ({})", config.llm.provider, config.llm.model);
        println!("  Scanners: Podman sem privilégios de root");
        println!();

        let mut orchestrator = Orchestrator::new(config.clone())?;
        let all_tools = orchestrator.registry.tools().to_vec();
        let selected = selected_tools(&all_tools, &config.active_tools);

        println!("[1/3] Executando ferramentas de segurança...");
        let (trace_tx, mut trace_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        orchestrator.trace_sink = Some(trace_tx);
        let trace_printer = tokio::spawn(async move {
            while let Some(line) = trace_rx.recv().await {
                println!("  │ {line}");
            }
        });
        let total = selected.len();
        for (i, tool) in selected.iter().enumerate() {
            if orchestrator.cancelled {
                println!("  X Cancelado.");
                return Ok(EXIT_ERROR);
            }
            if orchestrator.paused {
                loop {
                    if !orchestrator.paused || orchestrator.cancelled {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
            println!("  [{:>2}/{:>2}] {:<12} ", i + 1, total, tool.manifest.name);
            let exec = orchestrator
                .execute_tool(&tool.manifest, &config.target_url)
                .await;
            if let Some(error) = &exec.execution_error {
                println!("  FALHA ({error})");
            } else {
                println!(
                    "  OK ({}, {} bytes de saída)",
                    exec.executed_at,
                    exec.output.len()
                );
            }
        }
        orchestrator.trace_sink = None;
        let _ = trace_printer.await;
        println!();

        orchestrator.build_findings();
        let scan_failure = orchestrator
            .execution_history
            .iter()
            .find_map(|execution| execution.execution_error.as_deref())
            .map(str::to_owned);
        let analysis = orchestrator
            .agent
            .analyze_logs(&orchestrator.findings)
            .await;
        orchestrator.last_log = analysis.clone();

        println!(
            "[2/3] Análise da IA ({} achados):",
            orchestrator.findings.len()
        );
        for line in analysis.lines() {
            println!("  │ {}", line);
        }
        println!();

        let report = crate::report::ReportGenerator::compile_report(
            &config,
            &orchestrator.findings,
            &orchestrator.decision_history,
        );
        let crit = orchestrator
            .findings
            .iter()
            .filter(|v| v.severity == Severity::Critical)
            .count();
        let high = orchestrator
            .findings
            .iter()
            .filter(|v| v.severity == Severity::High)
            .count();
        let med = orchestrator
            .findings
            .iter()
            .filter(|v| v.severity == Severity::Medium)
            .count();
        let low = orchestrator
            .findings
            .iter()
            .filter(|v| v.severity == Severity::Low)
            .count();
        let info = orchestrator
            .findings
            .iter()
            .filter(|v| v.severity == Severity::Info)
            .count();

        println!("[3/3] Resumo");
        println!("───────────────────────────────────────────────────────────");
        println!("  Total de achados: {}", orchestrator.findings.len());
        println!(
            "  CRÍTICAS: {}   ALTAS: {}   MÉDIAS: {}   BAIXAS: {}   INFORMATIVAS: {}",
            crit, high, med, low, info
        );
        println!();
        println!("  Próximo passo: {}", orchestrator.determine_next_step());
        println!("  Contêiner: {}", orchestrator.container_id());
        println!();
        let report_path = resolve_report_path(&config)?;
        let log_result = orchestrator.persist_scan_log();
        let report_result = crate::report::ReportGenerator::export_to_markdown(
            &report,
            &report_path.to_string_lossy(),
        );
        let log_path = log_result?;
        report_result?;
        println!("═══════════════════════════════════════════════════════════");
        println!("  OK Relatório exportado: {}", report_path.display());
        println!("  OK Log estruturado: {}", log_path.display());
        // O scan_id carrega nanos e não é adivinhável: sem esta linha o histórico
        // seria inútil para quem executou o scan em modo headless.
        let scan_id = log_path.file_stem().map_or_else(
            || "desconhecido".to_string(),
            |stem| stem.to_string_lossy().into_owned(),
        );
        println!("  OK ID da execução: {scan_id}");
        println!("     consulte depois com: smartsec show {scan_id}");
        let exit_code = headless_exit_code(&orchestrator.findings, scan_failure.as_deref());
        if let Some(failure) = scan_failure {
            println!("  FALHA Varredura concluída com erros: {failure}");
            println!("═══════════════════════════════════════════════════════════");
            return Ok(exit_code);
        }
        println!("  OK Análise concluída.");
        println!("═══════════════════════════════════════════════════════════");
        Ok(exit_code)
    }
}

/// Código de saída consolidado do modo headless (TCC_SPEC.md, seção 10).
///
/// A falha de execução tem precedência sobre o achado crítico: uma varredura
/// incompleta precisa ser investigada antes de o resultado ser considerado.
pub fn headless_exit_code(findings: &[Vulnerability], scan_failure: Option<&str>) -> i32 {
    if scan_failure.is_some() {
        return EXIT_ERROR;
    }
    if findings
        .iter()
        .any(|finding| finding.severity == Severity::Critical)
    {
        return EXIT_CRITICAL;
    }
    EXIT_SUCCESS
}

/// Resolve o caminho do relatório e cria o diretório de saída quando definido.
fn resolve_report_path(config: &config::Configuration) -> Result<std::path::PathBuf> {
    let file = config
        .output_file
        .as_deref()
        .unwrap_or("smartsec-report.md");
    let path = match config.output_dir.as_deref().filter(|dir| !dir.is_empty()) {
        Some(dir) => {
            let file_name = std::path::Path::new(file)
                .file_name()
                .map(std::ffi::OsStr::to_os_string)
                .unwrap_or_else(|| "smartsec-report.md".into());
            let directory = std::path::PathBuf::from(dir);
            std::fs::create_dir_all(&directory).map_err(|error| {
                anyhow::anyhow!(
                    "não foi possível criar o diretório de saída '{}': {error}",
                    directory.display()
                )
            })?;
            directory.join(file_name)
        }
        None => std::path::PathBuf::from(file),
    };
    Ok(path)
}

fn build_config(
    options: &ExecutionArgs,
    target: String,
    manual_tool: Option<String>,
    auto: bool,
) -> Result<config::Configuration> {
    let mut config = match &options.config {
        Some(path) => config::Configuration::load_from_path(path)?,
        None => config::Configuration::load_unvalidated(),
    };
    config.target_url = target;
    config.execution_type = if auto {
        ExecutionType::Auto
    } else {
        ExecutionType::Assisted
    };
    let registry = ToolRegistry::with_configured(&config.tools)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if options.tools.is_none() && manual_tool.is_none() {
        config
            .active_tools
            .retain(|selected| registry.find(selected).is_some());
    }
    if let Some(tools) = &options.tools {
        config.active_tools = tools
            .split(',')
            .map(str::trim)
            .filter(|tool| !tool.is_empty())
            .map(str::to_owned)
            .collect();
        if config.active_tools.is_empty() {
            anyhow::bail!("a lista de ferramentas não pode estar vazia");
        }
    }
    if let Some(tool) = manual_tool {
        config.active_tools = vec![tool];
    }
    validate_tools(&registry, &config.active_tools)?;
    if let Some(provider) = &options.llm {
        let kind = parse_provider(provider)?;
        config.llm.provider = kind;
        config.llm.base_url = kind.default_base_url().to_owned();
        if options.model.is_none() {
            config.llm.model = kind.default_model().to_owned();
        }
    }
    if let Some(model) = &options.model {
        if model.trim().is_empty() {
            anyhow::bail!("o modelo da IA não pode ser vazio");
        }
        config.llm.model = model.clone();
    }
    if let Some(output) = &options.output {
        if output.trim().is_empty() {
            anyhow::bail!("o arquivo de saída não pode ser vazio");
        }
        config.output_file = Some(output.clone());
    }
    if let Some(dir) = &options.output_dir {
        if dir.trim().is_empty() {
            anyhow::bail!("o diretório de saída não pode ser vazio");
        }
        config.output_dir = Some(dir.clone());
    }
    config.validate_target().map_err(anyhow::Error::msg)?;
    config.llm.validate().map_err(anyhow::Error::msg)?;
    Ok(config)
}

fn validate_tools(registry: &ToolRegistry, active_tools: &[String]) -> Result<()> {
    for selected in active_tools {
        if registry.find(selected).is_none() {
            anyhow::bail!("ferramenta desconhecida: {selected}");
        }
    }
    Ok(())
}

fn parse_provider(provider: &str) -> Result<config::llm_config::LlmProviderKind> {
    match provider.to_ascii_lowercase().as_str() {
        "ollama" => Ok(config::llm_config::LlmProviderKind::Ollama),
        "openai" => Ok(config::llm_config::LlmProviderKind::OpenAI),
        "nvidia-nim" | "nvidia_nim" => Ok(config::llm_config::LlmProviderKind::NvidiaNim),
        "custom" | "personalizado" => Ok(config::llm_config::LlmProviderKind::Custom),
        _ => anyhow::bail!("provedor de IA desconhecido: {provider}"),
    }
}

fn selected_tools<'a>(
    tools: &'a [RegisteredTool],
    active_tools: &[String],
) -> Vec<&'a RegisteredTool> {
    tools
        .iter()
        .filter(|tool| {
            active_tools.is_empty()
                || active_tools
                    .iter()
                    .any(|active| active.eq_ignore_ascii_case(&tool.manifest.name))
        })
        .collect()
}

#[tokio::main]
async fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let cli = CommandLineInterface::new(arguments);
    match cli.run().await {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("Erro: {error:#}");
            std::process::exit(EXIT_ERROR);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vulnerability::FindingSource;

    fn vulnerability(severity: Severity) -> Vulnerability {
        Vulnerability {
            title: "Achado de teste".to_string(),
            severity,
            description: "Descrição".to_string(),
            tool: "Nmap".to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: FindingSource::Real,
            target: "http://test.local".to_string(),
            evidence: "evidência".to_string(),
            detected_at: "2026-09-24T12:00:00Z".to_string(),
        }
    }

    #[test]
    fn classifies_headless_exit_codes() {
        assert_eq!(headless_exit_code(&[], None), EXIT_SUCCESS);
        assert_eq!(
            headless_exit_code(&[vulnerability(Severity::Critical)], None),
            EXIT_CRITICAL
        );
        assert_eq!(
            headless_exit_code(&[vulnerability(Severity::Info)], None),
            EXIT_SUCCESS
        );
        assert_eq!(
            headless_exit_code(&[], Some("falha do scanner")),
            EXIT_ERROR
        );
        assert_eq!(
            headless_exit_code(
                &[vulnerability(Severity::Critical)],
                Some("falha do scanner")
            ),
            EXIT_ERROR,
            "falha de execução tem precedência sobre o achado crítico"
        );
    }

    #[test]
    fn output_dir_overrides_the_report_destination() {
        let dir = std::env::temp_dir().join(format!("smartsec-output-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = config::Configuration {
            output_dir: Some(dir.to_string_lossy().into_owned()),
            output_file: Some("relatorio.md".to_string()),
            ..config::Configuration::default()
        };

        let path = resolve_report_path(&config).unwrap();

        assert_eq!(path, dir.join("relatorio.md"));
        assert!(dir.is_dir(), "o diretório de saída deve ser criado");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_flags_configure_the_report_destination() {
        let path =
            std::env::temp_dir().join(format!("smartsec-output-flags-{}.toml", std::process::id()));
        std::fs::write(
            &path,
            "target_url = \"http://config.local\"\nactive_tools = [\"Nmap\"]\n\
             [llm]\nprovider = \"Ollama\"\nbase_url = \"http://localhost:11434/v1\"\nmodel = \"llama3.2:1b\"\n",
        )
        .unwrap();
        let options = ExecutionArgs {
            config: Some(path.clone()),
            tools: None,
            llm: None,
            model: None,
            output: Some("personalizado.md".to_owned()),
            output_dir: Some("saida".to_owned()),
        };

        let configured = build_config(&options, "192.0.2.10".to_owned(), None, true).unwrap();

        assert_eq!(configured.output_file.as_deref(), Some("personalizado.md"));
        assert_eq!(configured.output_dir.as_deref(), Some("saida"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn parses_scan_target_and_options() {
        let cli = Cli::parse(&[
            "scan".to_owned(),
            "--target".to_owned(),
            "192.0.2.10".to_owned(),
            "--tools".to_owned(),
            "Nmap,Nuclei".to_owned(),
            "--llm".to_owned(),
            "ollama".to_owned(),
            "--model".to_owned(),
            "llama3.1:8b".to_owned(),
        ])
        .unwrap();
        let Some(CliCommand::Scan(args)) = cli.command else {
            panic!("o comando scan deveria ser reconhecido");
        };
        assert_eq!(args.target, "192.0.2.10");
        assert_eq!(args.options.tools.as_deref(), Some("Nmap,Nuclei"));
        assert_eq!(args.options.llm.as_deref(), Some("ollama"));
    }

    #[test]
    fn cli_values_have_precedence_over_configuration() {
        let path =
            std::env::temp_dir().join(format!("smartsec-precedence-{}.toml", std::process::id()));
        std::fs::write(
            &path,
            "target_url = \"http://config.local\"\nactive_tools = [\"Nuclei\"]\nexecution_type = \"Assisted\"\n\n[llm]\nprovider = \"Ollama\"\nbase_url = \"http://localhost:11434/v1\"\nmodel = \"llama3.2:1b\"\n",
        )
        .unwrap();
        let options = ExecutionArgs {
            config: Some(path.clone()),
            tools: Some("Nmap".to_owned()),
            llm: None,
            model: None,
            ..ExecutionArgs::default()
        };
        let configured = build_config(&options, "192.0.2.10".to_owned(), None, true).unwrap();
        assert_eq!(configured.target_url, "192.0.2.10");
        assert_eq!(configured.active_tools, vec!["Nmap"]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn accepts_a_tool_registered_by_configuration() {
        let path = std::env::temp_dir().join(format!(
            "smartsec-configured-tool-{}.toml",
            std::process::id()
        ));
        std::fs::write(
            &path,
            "target_url = \"http://config.local\"\nactive_tools = [\"ZAP\"]\n\n[llm]\nprovider = \"Ollama\"\n\n[[tools]]\nname = \"ZAP\"\ndescription = \"Scanner de servidores web\"\ncategory = \"DAST\"\nimage = \"example/zap:1\"\nversion = \"1.0\"\nrunner = \"generic\"\nparser = \"generic-text\"\ncommand_template = [\"zap\", \"-host\", \"{target}\"]\noutput_format = \"text\"\n",
        )
        .unwrap();
        let options = ExecutionArgs {
            config: Some(path.clone()),
            tools: Some("ZAP".to_owned()),
            llm: None,
            model: None,
            ..ExecutionArgs::default()
        };

        let configured = build_config(&options, "192.0.2.10".to_owned(), None, true).unwrap();

        assert_eq!(configured.active_tools, vec!["ZAP"]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rejects_invalid_target_and_tool() {
        let options = ExecutionArgs {
            config: None,
            tools: Some("Inexistente".to_owned()),
            llm: None,
            model: None,
            ..ExecutionArgs::default()
        };
        assert!(build_config(&options, "não é um alvo".to_owned(), None, true).is_err());
        assert!(build_config(
            &ExecutionArgs {
                tools: Some("Inexistente".to_owned()),
                ..options
            },
            "192.0.2.10".to_owned(),
            None,
            true
        )
        .is_err());
    }

    #[test]
    fn rejects_removed_demo_mode() {
        assert!(Cli::parse(&[
            "scan".to_owned(),
            "--target".to_owned(),
            "192.0.2.10".to_owned(),
            "--demo".to_owned(),
        ])
        .is_err());
    }
}
