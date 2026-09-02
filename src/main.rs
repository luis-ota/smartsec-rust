//! SmartSec - Security Analysis Platform
//!
//! Entry point: `CommandLineInterface::main`.
//!
//! Supports interactive TUI mode and structured `scan`/`tool` commands.

mod ai;
mod config;
mod domain;
mod llm;
mod orchestrator;
mod report;
mod tools;
mod tui;
mod utils;

use crate::config::execution_type::ExecutionType;
use crate::domain::security_tool::ToolInfo;
use crate::domain::Severity;
use crate::orchestrator::Orchestrator;
use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;

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

#[derive(Debug, Clone, Default)]
struct ExecutionArgs {
    config: Option<std::path::PathBuf>,
    tools: Option<String>,
    llm: Option<String>,
    model: Option<String>,
    real_nuclei: bool,
    demo: bool,
}

impl Cli {
    fn parse(arguments: &[String]) -> Result<Self> {
        if arguments.iter().any(|argument| argument == "--version" || argument == "-V") {
            println!("smartsec-rust 0.2.0");
            return Ok(Self { command: None });
        }
        if arguments.is_empty() {
            return Ok(Self { command: None });
        }
        if arguments.iter().any(|argument| argument == "--help" || argument == "-h") {
            print_help();
            return Ok(Self { command: None });
        }
        let command = arguments[0].as_str();
        let (tool, start) = match command {
            "scan" => (None, 1),
            "tool" => {
                let tool = arguments.get(1).ok_or_else(|| anyhow::anyhow!("a ferramenta é obrigatória"))?;
                (Some(tool.clone()), 2)
            }
            other => anyhow::bail!("comando desconhecido: {other}; use --help para ver as opções"),
        };
        let (target, options) = parse_execution_args(&arguments[start..])?;
        let target = target.ok_or_else(|| anyhow::anyhow!("o argumento --target é obrigatório"))?;
        Ok(Self {
            command: Some(if let Some(tool) = tool {
                CliCommand::Tool(ToolArgs { tool, target, options })
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
            arguments.get(*index).cloned().ok_or_else(|| anyhow::anyhow!("o argumento {name} exige um valor"))
        };
        match argument.as_str() {
            "--target" | "-t" => target = Some(value(&mut index, "--target")?),
            "--config" => options.config = Some(value(&mut index, "--config")?.into()),
            "--tools" => options.tools = Some(value(&mut index, "--tools")?),
            "--llm" => options.llm = Some(value(&mut index, "--llm")?),
            "--model" => options.model = Some(value(&mut index, "--model")?),
            "--real-nuclei" => options.real_nuclei = true,
            "--demo" => options.demo = true,
            other => anyhow::bail!("argumento desconhecido: {other}; use --help para ver as opções"),
        }
        index += 1;
    }
    Ok((target, options))
}

fn print_help() {
    println!("SmartSec - Plataforma de análise de segurança");
    println!("Uso: smartsec <scan|tool> --target <ALVO> [OPÇÕES]");
    println!("\nComandos:\n  scan              Executa uma varredura não interativa.\n  tool <FERRAMENTA> Executa manualmente uma ferramenta.");
    println!("\nOpções:\n  -t, --target <ALVO>  IP, domínio ou URL\n      --config <ARQUIVO>  Configuração TOML\n      --tools <LISTA>  Ferramentas separadas por vírgulas\n      --llm <PROVEDOR>  mock, ollama, openai, nvidia-nim ou custom\n      --model <MODELO>  Modelo da IA\n      --real-nuclei  Executa Nuclei via Podman\n  -h, --help\n  -V, --version");
}

impl CommandLineInterface {
    pub fn new(arguments: Vec<String>) -> Self {
        Self { arguments }
    }

    pub async fn run(self) -> Result<()> {
        let cli = Cli::parse(&self.arguments)?;
        if self.arguments.iter().any(|argument| {
            matches!(argument.as_str(), "--help" | "-h" | "--version" | "-V")
        }) {
            return Ok(());
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
            None => {
                let config = config::Configuration::load(&[])?;
                Self::display_tui(config).await
            }
        }
    }

    fn print_help() {
        println!("SmartSec - Security Analysis Platform");
        println!();
        println!("USO:");
        println!("  smartsec [OPCOES]");
        println!();
        println!("OPCOES:");
        println!("  -u, --url <URL>               Define a URL/alvo para o scan");
        println!("  -a, --auto                    Executa em modo automatizado (headless)");
        println!("  -d, --demo                    Executa em modo demonstrativo (dados simulados)");
        println!("  -p, --provider <NOME>         Provedor de IA (mock, ollama, openai)");
        println!("  -o, --output <ARQUIVO>        Salva o relatorio Markdown no caminho especificado");
        println!("  -h, --help                    Exibe esta ajuda");
        println!("  -v, --version                 Exibe a versao");
        println!();
        println!("EXEMPLOS:");
        println!("  smartsec");
        println!("  smartsec --auto --url http://target.local");
        println!("  smartsec --auto --url http://target.local --demo -o relatorio.md");
    }

    async fn display_tui(initial_config: config::Configuration) -> Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let mut app = tui::state::AppState::new(initial_config);
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
                return Ok(());
            }

            app.tick();
            app.step_tick().await;

            if app.should_quit {
                return Ok(());
            }
        }
    }

    pub async fn run_headless(config: config::Configuration) -> Result<()> {
        config.validate_target().map_err(anyhow::Error::msg)?;

        println!("═══════════════════════════════════════════════════════════");
        println!("  SmartSec — Headless Analysis");
        println!("═══════════════════════════════════════════════════════════");
        println!("  Target: {}", config.target_url);
        println!("  Mode:   {}", config.execution_type);
        if config.demo_mode {
            println!("  Dados:  DEMO (findings simulados; nenhum scanner real)");
        } else {
            println!("  Dados:  REAL");
        }
        println!("  LLM:    {:?} ({})", config.llm.provider, config.llm.model);
        println!(
            "  Nuclei: {}",
            if config.use_real_nuclei {
                "REAL execution"
            } else {
                "emulated execution"
            }
        );
        println!();

        let mut orchestrator = Orchestrator::new(config.clone());
        let all_tools = ToolInfo::all();
        let selected = selected_tools(&all_tools, &config.active_tools);

        println!("[1/3] Running security tools...");
        let total = selected.len();
        for (i, tool) in selected.iter().enumerate() {
            if orchestrator.cancelled {
                println!("  X Cancelled.");
                return Ok(());
            }
            if orchestrator.paused {
                loop {
                    if !orchestrator.paused || orchestrator.cancelled {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
            print!("  [{:>2}/{:>2}] {:<12} ", i + 1, total, tool.name);
            use std::io::Write;
            let _ = std::io::stdout().flush();
            let exec = orchestrator.execute_tool(tool, &config.target_url).await;
            if let Some(error) = &exec.execution_error {
                println!("FALHA ({error})");
            } else {
                println!(
                    "OK ({}, {} bytes output)",
                    exec.executed_at,
                    exec.output.len()
                );
            }
        }
        println!();

        orchestrator.build_findings();
        if let Some(failure) = orchestrator
            .execution_history
            .iter()
            .find_map(|execution| execution.execution_error.as_deref())
        {
            anyhow::bail!("A varredura não foi concluída: {failure}");
        }
        let analysis = orchestrator
            .agent
            .analyze_logs(&orchestrator.findings)
            .await;
        orchestrator.last_log = analysis.clone();

        println!(
            "[2/3] AI analysis ({} findings):",
            orchestrator.findings.len()
        );
        for line in analysis.lines() {
            println!("  │ {}", line);
        }
        println!();

        let report =
            crate::report::ReportGenerator::compile_report(&config, &orchestrator.findings);
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

        println!("[3/3] Summary");
        println!("───────────────────────────────────────────────────────────");
        println!("  Total findings: {}", orchestrator.findings.len());
        println!(
            "  CRITICAL: {}   HIGH: {}   MEDIUM: {}   LOW: {}",
            crit, high, med, low
        );
        println!();
        println!("  Next step: {}", orchestrator.determine_next_step());
        println!("  Container: {}", orchestrator.container_id());
        println!();
        println!("═══════════════════════════════════════════════════════════");
        println!("  OK Relatorio exportado: smartsec-report.md");
        if let Ok(log_path) = orchestrator.persist_scan_log() {
            println!("  OK Log estruturado: {}", log_path.display());
        }
        println!("  OK Analise concluida.");
        println!("═══════════════════════════════════════════════════════════");

        let output_file = config.output_file.as_deref().unwrap_or("smartsec-report.md");
        crate::report::ReportGenerator::export_to_markdown(&report, output_file)?;
        Ok(())
    }
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
    config.execution_type = if auto { ExecutionType::Auto } else { ExecutionType::Assisted };
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
    validate_tools(&config.active_tools)?;
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
    if options.real_nuclei {
        config.use_real_nuclei = true;
    }
    config.demo_mode = options.demo;
    config.validate_target().map_err(anyhow::Error::msg)?;
    config.llm.validate().map_err(anyhow::Error::msg)?;
    Ok(config)
}

fn validate_tools(active_tools: &[String]) -> Result<()> {
    let catalog = ToolInfo::all();
    for selected in active_tools {
        if !catalog.iter().any(|tool| tool.name.eq_ignore_ascii_case(selected)) {
            anyhow::bail!("ferramenta desconhecida: {selected}");
        }
    }
    Ok(())
}

fn parse_provider(provider: &str) -> Result<config::llm_config::LlmProviderKind> {
    match provider.to_ascii_lowercase().as_str() {
        "mock" | "integrado" => Ok(config::llm_config::LlmProviderKind::Mock),
        "ollama" => Ok(config::llm_config::LlmProviderKind::Ollama),
        "openai" => Ok(config::llm_config::LlmProviderKind::OpenAI),
        "nvidia-nim" | "nvidia_nim" => Ok(config::llm_config::LlmProviderKind::NvidiaNim),
        "custom" | "personalizado" => Ok(config::llm_config::LlmProviderKind::Custom),
        _ => anyhow::bail!("provedor de IA desconhecido: {provider}"),
    }
}

fn selected_tools<'a>(tools: &'a [ToolInfo], active_tools: &[String]) -> Vec<&'a ToolInfo> {
    tools
        .iter()
        .filter(|tool| {
            active_tools.is_empty()
                || active_tools
                    .iter()
                    .any(|active| active.eq_ignore_ascii_case(tool.name))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scan_target_and_options() {
        let cli = Cli::parse(&[
            "scan".to_owned(),
            "--target".to_owned(), "192.0.2.10".to_owned(),
            "--tools".to_owned(), "Nmap,Nuclei".to_owned(),
            "--llm".to_owned(), "ollama".to_owned(),
            "--model".to_owned(), "llama3.1:8b".to_owned(),
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
        let options = ExecutionArgs {
            config: None,
            tools: Some("Nmap".to_owned()),
            llm: None,
            model: None,
            real_nuclei: false,
            demo: false,
        };
        let configured = build_config(&options, "192.0.2.10".to_owned(), None, true).unwrap();
        assert_eq!(configured.active_tools, vec!["Nmap"]);
    }

    #[test]
    fn rejects_invalid_target_and_tool() {
        let options = ExecutionArgs {
            config: None,
            tools: Some("Inexistente".to_owned()),
            llm: None,
            model: None,
            real_nuclei: false,
            demo: false,
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
    fn demo_requires_explicit_cli_flag() {
        let mut config = config::Configuration::default();
        config.demo_mode = ["--demo".to_owned()].iter().any(|arg| arg == "--demo");
        assert!(config.demo_mode);
        assert!(!config::Configuration::default().demo_mode);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let cli = CommandLineInterface::new(arguments);
    cli.run().await
}
