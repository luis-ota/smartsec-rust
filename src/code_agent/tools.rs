//! Ferramentas locais read-only expostas ao agente de código por tool calling.
//!
//! O registro nunca escreve no diretório analisado e só executa comandos com
//! opt-in explícito via allowlist, sem shell e com timeout.

use crate::code_agent::workspace::{SearchHit, Workspace, WorkspaceError, TRUNCATION_MARKER};
use crate::code_agent::CodeAgentLimits;
use crate::utils::redaction::sanitize_text;
use serde_json::{json, Value};
use std::fmt;
use std::process::Stdio;
use std::time::Duration;

const LIST_DIR: &str = "list_dir";
const READ_FILE: &str = "read_file";
const SEARCH_CODE: &str = "search_code";
const RUN_COMMAND: &str = "run_command";

/// Descrição de uma ferramenta no formato aceito por provedores com tool
/// calling (schema estilo OpenAI).
#[derive(Debug, Clone, PartialEq)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

/// Resultado de uma chamada de ferramenta.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCallResult {
    pub tool: String,
    pub output: String,
    pub truncated: bool,
}

/// Falhas previsíveis ao despachar uma chamada de ferramenta.
#[derive(Debug)]
pub enum ToolError {
    UnknownTool(String),
    InvalidArguments(String),
    Denied(String),
    Failed(String),
}

impl fmt::Display for ToolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTool(message)
            | Self::InvalidArguments(message)
            | Self::Denied(message)
            | Self::Failed(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ToolError {}

/// Registro das ferramentas locais disponíveis para o agente de código.
pub struct LocalToolRegistry {
    workspace: Workspace,
    limits: CodeAgentLimits,
    command_allowlist: Vec<String>,
}

impl LocalToolRegistry {
    pub fn new(
        workspace: Workspace,
        limits: CodeAgentLimits,
        command_allowlist: Vec<String>,
    ) -> Self {
        let workspace = workspace.with_max_file_bytes(limits.max_file_bytes);
        Self {
            workspace,
            limits,
            command_allowlist,
        }
    }

    pub fn workspace(&self) -> &Workspace {
        &self.workspace
    }

    pub fn limits(&self) -> CodeAgentLimits {
        self.limits
    }

    /// Especificações das ferramentas `list_dir`, `read_file`, `search_code` e
    /// `run_command`.
    pub fn specs(&self) -> Vec<ToolSpec> {
        vec![
            ToolSpec {
                name: LIST_DIR.to_owned(),
                description: "Lista arquivos e diretórios de um caminho dentro do projeto analisado; diretórios aparecem com o sufixo \"/\".".to_owned(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Caminho relativo à raiz do projeto; use \".\" para a raiz."
                        }
                    },
                    "required": ["path"]
                }),
            },
            ToolSpec {
                name: READ_FILE.to_owned(),
                description: format!(
                    "Lê um arquivo de texto do projeto com numeração de linha, limitado a {} bytes.",
                    self.limits.max_file_bytes
                ),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Caminho relativo à raiz do projeto."
                        }
                    },
                    "required": ["path"]
                }),
            },
            ToolSpec {
                name: SEARCH_CODE.to_owned(),
                description: format!(
                    "Busca textual (sem diferenciar maiúsculas) no projeto, ignorando diretórios de build, arquivos binários e arquivos maiores que {} bytes; devolve no máximo {} resultados.",
                    self.limits.max_file_bytes, self.limits.max_search_results
                ),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "term": {
                            "type": "string",
                            "description": "Texto procurado."
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "Limite opcional de resultados, limitado pelo teto configurado."
                        }
                    },
                    "required": ["term"]
                }),
            },
            ToolSpec {
                name: RUN_COMMAND.to_owned(),
                description: format!(
                    "Executa um programa da allowlist explícita, sem shell, no diretório raiz do projeto, com timeout de {}s. Desabilitado quando a allowlist está vazia.",
                    self.limits.command_timeout_secs
                ),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "program": {
                            "type": "string",
                            "description": "Executável permitido pela allowlist (primeiro argumento)."
                        },
                        "args": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Argumentos repassados diretamente, sem interpretação de shell."
                        }
                    },
                    "required": ["program"]
                }),
            },
        ]
    }

    /// Executa uma ferramenta pelo nome com os argumentos informados.
    pub async fn call(&self, name: &str, arguments: &Value) -> Result<ToolCallResult, ToolError> {
        match name {
            LIST_DIR => self.call_list_dir(arguments),
            READ_FILE => self.call_read_file(arguments),
            SEARCH_CODE => self.call_search_code(arguments),
            RUN_COMMAND => self.call_run_command(arguments).await,
            other => Err(ToolError::UnknownTool(format!(
                "ferramenta desconhecida: \"{other}\"; consulte specs() para ver as ferramentas disponíveis"
            ))),
        }
    }

    fn call_list_dir(&self, arguments: &Value) -> Result<ToolCallResult, ToolError> {
        let path = required_string(LIST_DIR, arguments, "path")?;
        let entries = self
            .workspace
            .list_dir(path)
            .map_err(|error| workspace_failure(LIST_DIR, error))?;
        let output = if entries.is_empty() {
            format!("o diretório \"{path}\" está vazio")
        } else {
            entries.join("\n")
        };
        Ok(ToolCallResult {
            tool: LIST_DIR.to_owned(),
            output: sanitize_text(&output),
            truncated: false,
        })
    }

    fn call_read_file(&self, arguments: &Value) -> Result<ToolCallResult, ToolError> {
        let path = required_string(READ_FILE, arguments, "path")?;
        let text = self
            .workspace
            .read_text(path, self.limits.max_file_bytes)
            .map_err(|error| workspace_failure(READ_FILE, error))?;
        let truncated = text.contains(TRUNCATION_MARKER);
        Ok(ToolCallResult {
            tool: READ_FILE.to_owned(),
            output: number_lines(&text),
            truncated,
        })
    }

    fn call_search_code(&self, arguments: &Value) -> Result<ToolCallResult, ToolError> {
        let term = required_string(SEARCH_CODE, arguments, "term")?;
        let requested = match arguments.get("max_results") {
            None | Some(Value::Null) => self.limits.max_search_results,
            Some(value) => value.as_u64().ok_or_else(|| {
                ToolError::InvalidArguments(format!(
                    "a ferramenta \"{SEARCH_CODE}\" exige que \"max_results\" seja um inteiro"
                ))
            })? as usize,
        };
        let max_results = requested.clamp(1, self.limits.max_search_results);
        let hits = self
            .workspace
            .search(term, max_results)
            .map_err(|error| workspace_failure(SEARCH_CODE, error))?;
        let output = if hits.is_empty() {
            format!("nenhum resultado para \"{term}\"")
        } else {
            hits.iter().map(format_hit).collect::<Vec<_>>().join("\n")
        };
        Ok(ToolCallResult {
            tool: SEARCH_CODE.to_owned(),
            output: sanitize_text(&output),
            truncated: hits.len() >= max_results,
        })
    }

    async fn call_run_command(&self, arguments: &Value) -> Result<ToolCallResult, ToolError> {
        let program = required_string(RUN_COMMAND, arguments, "program")?.to_owned();
        let args = parse_args(arguments)?;
        if !self
            .command_allowlist
            .iter()
            .any(|allowed| allowed == &program)
        {
            return Err(ToolError::Denied(format!(
                "o programa \"{}\" não está na allowlist de comandos ({}); habilite-o explicitamente antes de executar",
                sanitize_text(&program),
                allowlist_description(&self.command_allowlist)
            )));
        }
        self.execute_command(&program, &args).await
    }

    async fn execute_command(
        &self,
        program: &str,
        args: &[String],
    ) -> Result<ToolCallResult, ToolError> {
        let mut command = tokio::process::Command::new(program);
        command
            .args(args)
            .current_dir(self.workspace.root())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let child = command.spawn().map_err(|error| {
            ToolError::Failed(format!(
                "não foi possível executar \"{}\": {error}",
                sanitize_text(program)
            ))
        })?;
        let timeout = Duration::from_secs(self.limits.command_timeout_secs);
        let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                return Err(ToolError::Failed(format!(
                    "falha ao aguardar \"{}\": {error}",
                    sanitize_text(program)
                )))
            }
            Err(_) => {
                return Err(ToolError::Failed(format!(
                    "o comando \"{}\" excedeu o timeout de {}s e foi interrompido",
                    sanitize_text(program),
                    self.limits.command_timeout_secs
                )))
            }
        };
        let mut command_line = sanitize_text(program);
        if !args.is_empty() {
            command_line = format!("{command_line} {}", sanitize_text(&args.join(" ")));
        }
        let status = output
            .status
            .code()
            .map_or_else(|| "encerrado por sinal".to_owned(), |code| code.to_string());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!(
            "comando: {command_line}\nstatus: {status}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            stdout.trim_end(),
            stderr.trim_end()
        );
        let (output, truncated) =
            limit_bytes(&sanitize_text(&combined), self.limits.max_file_bytes);
        Ok(ToolCallResult {
            tool: RUN_COMMAND.to_owned(),
            output,
            truncated,
        })
    }
}

fn required_string<'a>(tool: &str, arguments: &'a Value, key: &str) -> Result<&'a str, ToolError> {
    match arguments.get(key).and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(ToolError::InvalidArguments(format!(
            "a ferramenta \"{tool}\" exige o argumento de texto \"{key}\""
        ))),
    }
}

fn parse_args(arguments: &Value) -> Result<Vec<String>, ToolError> {
    match arguments.get("args") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str().map(str::to_owned).ok_or_else(|| {
                    ToolError::InvalidArguments(format!(
                        "a ferramenta \"{RUN_COMMAND}\" exige que \"args\" seja uma lista de textos"
                    ))
                })
            })
            .collect(),
        Some(_) => Err(ToolError::InvalidArguments(format!(
            "a ferramenta \"{RUN_COMMAND}\" exige que \"args\" seja uma lista de textos"
        ))),
    }
}

fn allowlist_description(allowlist: &[String]) -> String {
    if allowlist.is_empty() {
        "allowlist vazia".to_owned()
    } else {
        format!("allowlist atual: {}", allowlist.join(", "))
    }
}

fn workspace_failure(tool: &str, error: WorkspaceError) -> ToolError {
    ToolError::Failed(format!("[{tool}] {error}"))
}

fn format_hit(hit: &SearchHit) -> String {
    format!("{}:{}: {}", hit.path, hit.line, hit.text)
}

fn number_lines(text: &str) -> String {
    text.lines()
        .enumerate()
        .map(|(index, line)| format!("{:>5} | {line}", index + 1))
        .collect::<Vec<_>>()
        .join("\n")
}

fn limit_bytes(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_owned(), false);
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (
        format!(
            "{}\n[... saída truncada: exibidos {end} de {} bytes]",
            &text[..end],
            text.len()
        ),
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/codebase")
    }

    fn fixture_workspace() -> Workspace {
        Workspace::open(&fixture_root()).unwrap()
    }

    fn registry(command_allowlist: Vec<String>) -> LocalToolRegistry {
        LocalToolRegistry::new(
            fixture_workspace(),
            CodeAgentLimits::default(),
            command_allowlist,
        )
    }

    fn temp_workspace(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("smartsec-code-agent-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn specs_describe_all_local_tools() {
        let specs = registry(Vec::new()).specs();
        let names: Vec<&str> = specs.iter().map(|spec| spec.name.as_str()).collect();
        assert_eq!(names, vec![LIST_DIR, READ_FILE, SEARCH_CODE, RUN_COMMAND]);
        for spec in &specs {
            assert_eq!(spec.parameters["type"], "object");
            assert!(spec.parameters["properties"].is_object());
            assert!(!spec.parameters["required"].as_array().unwrap().is_empty());
            assert!(!spec.description.trim().is_empty());
        }
    }

    #[tokio::test]
    async fn read_file_numbers_lines() {
        let result = registry(Vec::new())
            .call(READ_FILE, &json!({"path": "src/app.py"}))
            .await
            .unwrap();

        assert_eq!(result.tool, READ_FILE);
        assert!(!result.truncated);
        let mut lines = result.output.lines();
        assert_eq!(lines.next().unwrap(), "    1 | def login(user):");
        assert!(result.output.contains("    4 | "));
    }

    #[tokio::test]
    async fn read_file_flags_truncation() {
        let limits = CodeAgentLimits {
            max_file_bytes: 24,
            ..CodeAgentLimits::default()
        };
        let registry = LocalToolRegistry::new(fixture_workspace(), limits, Vec::new());

        let result = registry
            .call(READ_FILE, &json!({"path": "src/app.py"}))
            .await
            .unwrap();

        assert!(result.truncated);
        assert!(result.output.contains(TRUNCATION_MARKER));
    }

    #[tokio::test]
    async fn list_dir_returns_sorted_entries() {
        let result = registry(Vec::new())
            .call(LIST_DIR, &json!({"path": "src"}))
            .await
            .unwrap();

        assert_eq!(result.output, "app.py\nbinary.bin\nconfig.py\nnested/");
        assert!(!result.truncated);
    }

    #[tokio::test]
    async fn search_code_returns_hits_and_respects_limit() {
        let registry = registry(Vec::new());

        let result = registry
            .call(SEARCH_CODE, &json!({"term": "login"}))
            .await
            .unwrap();
        assert_eq!(result.output.lines().count(), 5);
        assert_eq!(
            result.output.lines().next().unwrap(),
            "src/app.py:1: def login(user):"
        );
        assert!(!result.truncated);

        let limited = registry
            .call(SEARCH_CODE, &json!({"term": "login", "max_results": 2}))
            .await
            .unwrap();
        assert_eq!(limited.output.lines().count(), 2);
        assert!(limited.truncated);
    }

    #[tokio::test]
    async fn masks_example_secret_in_tool_output() {
        let registry = registry(Vec::new());

        let read = registry
            .call(READ_FILE, &json!({"path": "src/config.py"}))
            .await
            .unwrap();
        assert!(read.output.contains("[REDACTED]"));
        assert!(!read.output.contains("valor-de-exemplo"));
    }

    #[tokio::test]
    async fn rejects_unknown_tool_and_invalid_arguments() {
        let registry = registry(Vec::new());

        assert!(matches!(
            registry.call("ferramenta_inexistente", &json!({})).await,
            Err(ToolError::UnknownTool(_))
        ));
        assert!(matches!(
            registry.call(READ_FILE, &json!({})).await,
            Err(ToolError::InvalidArguments(_))
        ));
        assert!(matches!(
            registry.call(READ_FILE, &json!({"path": 3})).await,
            Err(ToolError::InvalidArguments(_))
        ));
        assert!(matches!(
            registry
                .call(
                    SEARCH_CODE,
                    &json!({"term": "login", "max_results": "muitos"})
                )
                .await,
            Err(ToolError::InvalidArguments(_))
        ));
    }

    #[tokio::test]
    async fn reports_workspace_errors_as_actionable_failures() {
        let error = registry(Vec::new())
            .call(READ_FILE, &json!({"path": "../Cargo.toml"}))
            .await
            .unwrap_err();

        assert!(matches!(error, ToolError::Failed(_)));
        assert!(error.to_string().contains("fora da raiz do workspace"));
    }

    #[tokio::test]
    async fn run_command_is_denied_without_allowlist() {
        let error = registry(Vec::new())
            .call(RUN_COMMAND, &json!({"program": "echo", "args": ["ola"]}))
            .await
            .unwrap_err();

        assert!(matches!(error, ToolError::Denied(_)));
        assert!(error.to_string().contains("allowlist vazia"));
    }

    #[tokio::test]
    async fn run_command_denies_program_outside_allowlist() {
        let error = registry(vec!["echo".to_owned()])
            .call(
                RUN_COMMAND,
                &json!({"program": "sh", "args": ["-c", "echo ola"]}),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, ToolError::Denied(_)));
        assert!(error.to_string().contains("allowlist atual: echo"));
    }

    #[tokio::test]
    async fn run_command_executes_from_workspace_root_without_shell() {
        let registry = registry(vec!["echo".to_owned(), "pwd".to_owned()]);

        let result = registry
            .call(
                RUN_COMMAND,
                &json!({"program": "echo", "args": ["ola", "mundo"]}),
            )
            .await
            .unwrap();
        assert!(result.output.contains("status: 0"));
        assert!(result.output.contains("ola mundo"));
        assert!(!result.truncated);

        let pwd = registry
            .call(RUN_COMMAND, &json!({"program": "pwd"}))
            .await
            .unwrap();
        assert!(pwd
            .output
            .contains(&registry.workspace().root().display().to_string()));

        let marker = std::env::temp_dir().join(format!(
            "smartsec-code-agent-shell-marker-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&marker);
        let injection = registry
            .call(
                RUN_COMMAND,
                &json!({"program": "echo", "args": [format!("$(touch {})", marker.display())]}),
            )
            .await
            .unwrap();
        assert!(injection.output.contains("$(touch"));
        assert!(
            !marker.exists(),
            "nenhum shell deveria interpretar os argumentos"
        );
    }

    #[tokio::test]
    async fn run_command_masks_secret_in_output() {
        let result = registry(vec!["echo".to_owned()])
            .call(
                RUN_COMMAND,
                &json!({"program": "echo", "args": ["EXEMPLO_SECRET=valor-de-exemplo"]}),
            )
            .await
            .unwrap();

        assert!(result.output.contains("[REDACTED]"));
        assert!(!result.output.contains("valor-de-exemplo"));
    }

    #[tokio::test]
    async fn run_command_timeout_interrupts_the_process() {
        let root = temp_workspace("timeout");
        let marker = root.join("marcador.txt");
        let workspace = Workspace::open(&root).unwrap();
        let limits = CodeAgentLimits {
            command_timeout_secs: 1,
            ..CodeAgentLimits::default()
        };
        let registry = LocalToolRegistry::new(workspace, limits, vec!["sh".to_owned()]);

        let started = std::time::Instant::now();
        let error = registry
            .call(
                RUN_COMMAND,
                &json!({
                    "program": "sh",
                    "args": ["-c", format!("sleep 2; touch {}", marker.display())]
                }),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, ToolError::Failed(_)));
        assert!(error.to_string().contains("timeout"));
        assert!(started.elapsed() < Duration::from_secs(3));

        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(
            !marker.exists(),
            "o processo deveria ter sido interrompido no timeout"
        );

        let _ = fs::remove_dir_all(&root);
    }
}
