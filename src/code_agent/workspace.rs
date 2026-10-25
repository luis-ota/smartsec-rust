//! Sandbox de leitura restrito ao diretório do projeto analisado.
//!
//! Toda resolução de caminho canonicaliza o alvo e exige que ele permaneça
//! dentro da raiz do workspace, bloqueando `..`, caminhos absolutos fora da
//! raiz e symlinks que escapem. O sandbox nunca escreve no diretório analisado.

use crate::code_agent::DEFAULT_MAX_FILE_BYTES;
use crate::utils::redaction::sanitize_text;
use std::fmt;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// Marcador acrescentado quando um arquivo é lido parcialmente.
pub const TRUNCATION_MARKER: &str = "[... truncado:";

const SKIPPED_DIRECTORIES: &[&str] = &[
    ".git",
    ".ai",
    ".claude",
    ".svn",
    ".hg",
    "target",
    "node_modules",
    "dist",
    "build",
];
const BINARY_SAMPLE_BYTES: usize = 8 * 1024;

/// Extensões de código e configuração que a busca deve entregar primeiro.
const CODE_EXTENSIONS: &[&str] = &[
    "rs",
    "py",
    "js",
    "jsx",
    "ts",
    "tsx",
    "go",
    "java",
    "kt",
    "rb",
    "php",
    "c",
    "h",
    "cc",
    "cpp",
    "hpp",
    "cs",
    "swift",
    "sh",
    "bash",
    "sql",
    "html",
    "css",
    "scss",
    "vue",
    "svelte",
    "toml",
    "yaml",
    "yml",
    "json",
    "ini",
    "conf",
    "cfg",
    "env",
    "properties",
    "dockerfile",
    "tf",
];

/// Ocorrência de um termo em um arquivo do workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    /// Caminho relativo à raiz do workspace.
    pub path: String,
    /// Número da linha, começando em 1.
    pub line: usize,
    /// Conteúdo da linha, já sanitizado.
    pub text: String,
}

/// Falhas previsíveis do sandbox de workspace.
#[derive(Debug)]
pub enum WorkspaceError {
    NotFound { requested: String },
    OutsideRoot { requested: String },
    NotAFile { requested: String },
    NotADirectory { requested: String },
    Io { requested: String, message: String },
}

impl fmt::Display for WorkspaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { requested } => {
                write!(formatter, "caminho não encontrado no workspace: \"{requested}\"")
            }
            Self::OutsideRoot { requested } => write!(
                formatter,
                "caminho fora da raiz do workspace: \"{requested}\"; use caminhos relativos, sem \"..\" e sem symlink para fora"
            ),
            Self::NotAFile { requested } => {
                write!(formatter, "\"{requested}\" não é um arquivo regular")
            }
            Self::NotADirectory { requested } => {
                write!(formatter, "\"{requested}\" não é um diretório")
            }
            Self::Io { requested, message } => {
                write!(formatter, "falha de E/S ao acessar \"{requested}\": {message}")
            }
        }
    }
}

impl std::error::Error for WorkspaceError {}

/// Diretório do projeto analisado, acessível apenas para leitura.
#[derive(Debug, Clone)]
pub struct Workspace {
    root: PathBuf,
    max_file_bytes: usize,
}

impl Workspace {
    /// Abre o workspace na raiz informada, que precisa existir e ser diretório.
    pub fn open(root: &Path) -> Result<Self, WorkspaceError> {
        let requested = root.display().to_string();
        let canonical = root
            .canonicalize()
            .map_err(|error| map_io(&requested, error))?;
        if !canonical.is_dir() {
            return Err(WorkspaceError::NotADirectory { requested });
        }
        Ok(Self {
            root: canonical,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
        })
    }

    /// Ajusta o limite de tamanho usado pela busca recursiva.
    pub fn with_max_file_bytes(mut self, max_file_bytes: usize) -> Self {
        self.max_file_bytes = max_file_bytes;
        self
    }

    /// Raiz canônica do workspace.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve um caminho relativo (ou absoluto dentro da raiz) para um caminho
    /// canônico dentro do workspace.
    pub fn resolve(&self, requested: &str) -> Result<PathBuf, WorkspaceError> {
        let requested_path = Path::new(requested);
        if requested_path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(WorkspaceError::OutsideRoot {
                requested: requested.to_owned(),
            });
        }
        let candidate = if requested_path.is_absolute() {
            requested_path.to_path_buf()
        } else {
            self.root.join(requested_path)
        };
        let canonical = candidate
            .canonicalize()
            .map_err(|error| map_io(requested, error))?;
        if !canonical.starts_with(&self.root) {
            return Err(WorkspaceError::OutsideRoot {
                requested: requested.to_owned(),
            });
        }
        Ok(canonical)
    }

    /// Lê um arquivo de texto, truncando em `max_bytes` com marcador explícito.
    ///
    /// `None` cai no teto configurado no workspace: um chamador que não passa
    /// limite não deve conseguir ler um arquivo inteiro sem querer.
    pub fn read_text(
        &self,
        requested: &str,
        max_bytes: Option<usize>,
    ) -> Result<String, WorkspaceError> {
        Ok(sanitize_text(&self.read_text_raw(requested, max_bytes)?))
    }

    /// Leitura crua para a prévia local da TUI.
    ///
    /// Mantém a política de caminho/tamanho de `read_text`, mas sem a
    /// sanitização conservadora que apagaria linhas inteiras de código.
    pub(crate) fn read_text_raw(
        &self,
        requested: &str,
        max_bytes: Option<usize>,
    ) -> Result<String, WorkspaceError> {
        let max_bytes = max_bytes
            .filter(|value| *value > 0)
            .unwrap_or(self.max_file_bytes);
        let path = self.resolve(requested)?;
        let metadata = std::fs::metadata(&path).map_err(|error| map_io(requested, error))?;
        if !metadata.is_file() {
            return Err(WorkspaceError::NotAFile {
                requested: requested.to_owned(),
            });
        }
        let file = std::fs::File::open(&path).map_err(|error| map_io(requested, error))?;
        let mut buffer = Vec::new();
        file.take(max_bytes.saturating_add(1) as u64)
            .read_to_end(&mut buffer)
            .map_err(|error| map_io(requested, error))?;
        let (text, _) = truncate_bytes(&buffer, max_bytes, metadata.len());
        Ok(text)
    }

    /// Lista as entradas de um diretório em ordem determinística, marcando
    /// subdiretórios com o sufixo `/`.
    pub fn list_dir(&self, requested: &str) -> Result<Vec<String>, WorkspaceError> {
        let path = self.resolve(requested)?;
        if !path.is_dir() {
            return Err(WorkspaceError::NotADirectory {
                requested: requested.to_owned(),
            });
        }
        let entries = std::fs::read_dir(&path).map_err(|error| map_io(requested, error))?;
        let mut names = Vec::new();
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let display = if file_type.is_dir() {
                format!("{name}/")
            } else {
                name
            };
            names.push(sanitize_text(&display));
        }
        names.sort();
        Ok(names)
    }

    /// Busca textual recursiva no workspace, pulando diretórios de build,
    /// arquivos binários e arquivos maiores que o limite configurado.
    pub fn search(&self, term: &str, max_results: usize) -> Result<Vec<SearchHit>, WorkspaceError> {
        self.search_any(&[term], max_results)
    }

    /// Busca por qualquer um dos termos em uma única passagem pelo workspace.
    ///
    /// Uma passagem só é necessária porque o localizador de portas testa vários
    /// formatos (`EXPOSE 3000`, `containerPort: 3000`, `listen(3000)`); repetir
    /// `search` por formato releria o projeto inteiro.
    pub fn search_any(
        &self,
        terms: &[&str],
        max_results: usize,
    ) -> Result<Vec<SearchHit>, WorkspaceError> {
        let needles: Vec<String> = terms
            .iter()
            .map(|term| term.to_ascii_lowercase())
            .filter(|term| !term.is_empty())
            .collect();
        let mut hits = Vec::new();
        if needles.is_empty() || max_results == 0 {
            return Ok(hits);
        }
        self.search_directory(&self.root, &needles, max_results, &mut hits);
        Ok(hits)
    }

    fn search_directory(
        &self,
        directory: &Path,
        needles: &[String],
        max_results: usize,
        hits: &mut Vec<SearchHit>,
    ) {
        if hits.len() >= max_results {
            return;
        }
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        let mut paths = Vec::new();
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if SKIPPED_DIRECTORIES.contains(&name.as_str()) {
                    continue;
                }
            } else if !file_type.is_file() {
                continue;
            }
            let path = entry.path();
            paths.push((search_rank(&path, file_type.is_dir()), path));
        }
        paths.sort();
        for (_, path) in paths {
            if hits.len() >= max_results {
                return;
            }
            if path.is_dir() {
                self.search_directory(&path, needles, max_results, hits);
            } else {
                self.search_file(&path, needles, max_results, hits);
            }
        }
    }

    /// Índice leve da árvore do projeto, sem LLM.
    ///
    /// Devolve diretórios e arquivos de entrada/configuração em ordem
    /// determinística, podando diretórios de build e ocultos. É o que permite ao
    /// modelo começar pela estrutura em vez de gastar chamadas de `list_dir`
    /// repetidas na raiz.
    pub fn overview(&self, max_entries: usize, max_depth: usize) -> String {
        let mut lines = Vec::new();
        self.overview_directory(&self.root, 0, max_depth, max_entries, &mut lines);
        if lines.is_empty() {
            "(projeto vazio)".to_string()
        } else {
            lines.join("\n")
        }
    }

    fn overview_directory(
        &self,
        directory: &Path,
        depth: usize,
        max_depth: usize,
        max_entries: usize,
        lines: &mut Vec<String>,
    ) {
        if lines.len() >= max_entries {
            return;
        }
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        let mut dirs = Vec::new();
        let mut files = Vec::new();
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if file_type.is_dir() {
                if name.starts_with('.') || SKIPPED_DIRECTORIES.contains(&name.as_str()) {
                    continue;
                }
                dirs.push((name, entry.path()));
            } else if file_type.is_file() && is_entrypoint_file(&name) {
                files.push(name);
            }
        }
        dirs.sort_by(|left, right| left.0.cmp(&right.0));
        files.sort();
        for name in files {
            if lines.len() >= max_entries {
                return;
            }
            let relative = directory.strip_prefix(&self.root).unwrap_or(directory);
            lines.push(relative.join(&name).to_string_lossy().replace('\\', "/"));
        }
        if depth >= max_depth {
            return;
        }
        for (_name, path) in dirs {
            if lines.len() >= max_entries {
                return;
            }
            let relative = path.strip_prefix(&self.root).unwrap_or(&path);
            lines.push(format!(
                "{}/",
                relative.to_string_lossy().replace('\\', "/")
            ));
            self.overview_directory(&path, depth + 1, max_depth, max_entries, lines);
        }
    }

    fn search_file(
        &self,
        path: &Path,
        needles: &[String],
        max_results: usize,
        hits: &mut Vec<SearchHit>,
    ) {
        let Ok(metadata) = std::fs::metadata(path) else {
            return;
        };
        if metadata.len() > self.max_file_bytes as u64 {
            return;
        }
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        let sample = &bytes[..bytes.len().min(BINARY_SAMPLE_BYTES)];
        if sample.contains(&0) {
            return;
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return;
        };
        let relative = path
            .strip_prefix(&self.root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let relative = sanitize_text(&relative);
        for (index, line) in text.lines().enumerate() {
            if hits.len() >= max_results {
                return;
            }
            let lower = line.to_ascii_lowercase();
            if needles.iter().any(|needle| lower.contains(needle)) {
                hits.push(SearchHit {
                    path: relative.clone(),
                    line: index + 1,
                    text: sanitize_text(line),
                });
            }
        }
    }
}

/// Prioridade de varredura dentro de um diretório.
///
/// Código e configuração vêm antes dos diretórios e dos arquivos restantes:
/// com o teto de resultados, a busca entrega a origem provável primeiro em vez
/// de gastar o limite em README, imagens e lockfiles.
fn search_rank(path: &Path, is_dir: bool) -> u8 {
    if is_dir {
        return 1;
    }
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if matches!(
        name.as_str(),
        "cargo.lock"
            | "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "go.sum"
            | "poetry.lock"
            | "composer.lock"
            | "pipfile.lock"
    ) {
        return 2;
    }
    if name == "dockerfile" || name == "makefile" {
        return 0;
    }
    match path
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
    {
        Some(extension) if CODE_EXTENSIONS.contains(&extension.as_str()) => 0,
        _ => 2,
    }
}

fn is_entrypoint_file(name: &str) -> bool {
    const NAMES: &[&str] = &[
        "cargo.toml",
        "package.json",
        "pyproject.toml",
        "go.mod",
        "requirements.txt",
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
        "makefile",
        "readme.md",
    ];
    let lower = name.to_ascii_lowercase();
    if NAMES.contains(&lower.as_str()) {
        return true;
    }
    if [
        "main.",
        "lib.",
        "index.",
        "app.",
        "server.",
        "config.",
        "settings.",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
    {
        return true;
    }
    matches!(
        lower.rsplit_once('.').map(|(_, extension)| extension),
        Some("toml" | "yaml" | "yml" | "json" | "ini" | "conf" | "cfg" | "env")
    )
}

fn map_io(requested: &str, error: std::io::Error) -> WorkspaceError {
    if error.kind() == std::io::ErrorKind::NotFound {
        WorkspaceError::NotFound {
            requested: requested.to_owned(),
        }
    } else {
        WorkspaceError::Io {
            requested: requested.to_owned(),
            message: error.to_string(),
        }
    }
}

fn truncate_bytes(buffer: &[u8], max_bytes: usize, total_bytes: u64) -> (String, bool) {
    if buffer.len() <= max_bytes {
        return (String::from_utf8_lossy(buffer).into_owned(), false);
    }
    let prefix = String::from_utf8_lossy(&buffer[..max_bytes]).into_owned();
    let separator = if prefix.is_empty() || prefix.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let marker = format!("{TRUNCATION_MARKER} exibidos {max_bytes} de {total_bytes} bytes]");
    (format!("{prefix}{separator}{marker}"), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/codebase")
    }

    fn fixture_workspace() -> Workspace {
        Workspace::open(&fixture_root()).unwrap()
    }

    fn temp_workspace(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("smartsec-code-agent-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn reads_text_and_truncates_with_clear_marker() {
        let workspace = fixture_workspace();

        let full = workspace.read_text("README.md", Some(4096)).unwrap();
        assert!(full.starts_with("# Codebase de exemplo"));

        let truncated = workspace.read_text("src/app.py", Some(24)).unwrap();
        assert!(truncated.contains(TRUNCATION_MARKER));
        assert!(truncated.contains("exibidos 24 de"));
        assert!(!truncated.contains("return user"));
    }

    #[test]
    fn falls_back_to_the_configured_ceiling_when_no_limit_is_given() {
        let root = temp_workspace("teto-padrao");
        fs::write(root.join("grande.txt"), "conteúdo\n".repeat(64)).unwrap();
        let workspace = Workspace::open(&root).unwrap().with_max_file_bytes(32);

        let read = workspace.read_text("grande.txt", None).unwrap();

        assert!(read.contains(TRUNCATION_MARKER), "{read}");
        assert!(read.contains("exibidos 32 de"), "{read}");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn lists_entries_sorted_with_directory_suffix() {
        let workspace = fixture_workspace();

        assert_eq!(
            workspace.list_dir("src").unwrap(),
            vec!["app.py", "binary.bin", "config.py", "nested/"]
        );
        assert_eq!(
            workspace.list_dir(".").unwrap(),
            vec![
                "README.md",
                "build/",
                "dist/",
                "node_modules/",
                "src/",
                "target/"
            ]
        );
    }

    #[test]
    fn rejects_parent_directory_and_absolute_path_outside_root() {
        let workspace = fixture_workspace();
        let outside = temp_workspace("outside");
        let external = outside.join("fora.txt");
        fs::write(&external, "conteúdo externo").unwrap();

        let error = workspace.resolve("../Cargo.toml").unwrap_err();
        assert!(matches!(error, WorkspaceError::OutsideRoot { .. }));
        assert!(error.to_string().contains("fora da raiz do workspace"));
        assert!(matches!(
            workspace.resolve(&external.display().to_string()),
            Err(WorkspaceError::OutsideRoot { .. })
        ));
        assert!(matches!(
            workspace.read_text("../Cargo.toml", Some(1024)),
            Err(WorkspaceError::OutsideRoot { .. })
        ));

        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn rejects_symlink_that_escapes_root_and_accepts_internal_symlink() {
        let outside = temp_workspace("symlink-outside");
        fs::write(outside.join("segredo.txt"), "conteúdo externo").unwrap();
        let root = temp_workspace("symlink-root");
        fs::write(root.join("dentro.txt"), "conteúdo interno").unwrap();
        symlink(&outside, root.join("escape")).unwrap();
        symlink(outside.join("segredo.txt"), root.join("escape.txt")).unwrap();
        symlink(root.join("dentro.txt"), root.join("link.txt")).unwrap();
        let workspace = Workspace::open(&root).unwrap();

        assert!(matches!(
            workspace.resolve("escape"),
            Err(WorkspaceError::OutsideRoot { .. })
        ));
        assert!(matches!(
            workspace.read_text("escape/segredo.txt", Some(64)),
            Err(WorkspaceError::OutsideRoot { .. })
        ));
        assert!(matches!(
            workspace.read_text("escape.txt", Some(64)),
            Err(WorkspaceError::OutsideRoot { .. })
        ));
        assert_eq!(
            workspace.read_text("link.txt", Some(64)).unwrap(),
            "conteúdo interno"
        );

        let _ = fs::remove_dir_all(&outside);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn search_returns_hits_in_deterministic_order_and_respects_limit() {
        let workspace = fixture_workspace();

        let hits = workspace.search("login", 10).unwrap();
        let locations: Vec<(String, usize)> = hits
            .iter()
            .map(|hit| (hit.path.clone(), hit.line))
            .collect();
        assert_eq!(
            locations,
            vec![
                ("src/app.py".to_owned(), 1),
                ("src/app.py".to_owned(), 4),
                ("src/nested/deep.py".to_owned(), 1),
                ("src/nested/deep.py".to_owned(), 2),
                ("src/nested/deep.py".to_owned(), 3),
            ]
        );
        assert!(hits.iter().all(|hit| hit.text.contains("login")));

        let limited = workspace.search("login", 2).unwrap();
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[1].line, 4);
    }

    #[test]
    fn search_any_matches_every_term_in_a_single_pass() {
        let workspace = fixture_workspace();

        let hits = workspace
            .search_any(&["EXEMPLO_SECRET", "DEBUG"], 10)
            .unwrap();
        let locations: Vec<(String, usize)> = hits
            .iter()
            .map(|hit| (hit.path.clone(), hit.line))
            .collect();
        assert_eq!(
            locations,
            vec![
                ("src/config.py".to_owned(), 2),
                ("src/config.py".to_owned(), 3),
            ]
        );
        assert!(hits
            .iter()
            .all(|hit| !hit.text.contains("valor-de-exemplo")));
    }

    #[test]
    fn search_skips_ignored_directories_binary_and_large_files() {
        let root = temp_workspace("search-skips");
        fs::write(root.join("texto.txt"), "login permitido\n").unwrap();
        fs::write(root.join("binario.bin"), b"login\0binario").unwrap();
        let large = format!("login\n{}\n", "x".repeat(DEFAULT_MAX_FILE_BYTES));
        fs::write(root.join("grande.txt"), large).unwrap();
        for skipped in SKIPPED_DIRECTORIES {
            let directory = root.join(skipped);
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join("ignorado.py"), "login ignorado\n").unwrap();
        }
        let workspace = Workspace::open(&root).unwrap();

        let hits = workspace.search("login", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "texto.txt");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn search_prefers_code_and_configuration_over_documentation() {
        let root = temp_workspace("search-prioridade");
        fs::write(root.join("README.md"), "login documentado\n").unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/app.py"), "login implementado\n").unwrap();
        fs::write(root.join("config.yaml"), "login: configuração\n").unwrap();
        let workspace = Workspace::open(&root).unwrap();

        let hits = workspace.search("login", 2).unwrap();

        assert_eq!(hits.len(), 2, "{hits:?}");
        assert!(
            hits.iter().all(|hit| hit.path != "README.md"),
            "o teto de resultados não pode ser gasto em documentação: {hits:?}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn search_skips_agent_and_tooling_directories_by_default() {
        let root = temp_workspace("search-agentes");
        fs::write(root.join("app.py"), "login permitido\n").unwrap();
        for skipped in [".ai", ".claude"] {
            let directory = root.join(skipped);
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join("instrucoes.py"), "login ignorado\n").unwrap();
        }
        let workspace = Workspace::open(&root).unwrap();

        let hits = workspace.search("login", 10).unwrap();

        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].path, "app.py");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn overview_lists_directories_and_entrypoints_without_build_noise() {
        let workspace = fixture_workspace();

        let overview = workspace.overview(80, 3);

        assert!(overview.contains("src/"), "{overview}");
        assert!(overview.contains("src/app.py"), "{overview}");
        assert!(overview.contains("README.md"), "{overview}");
        for skipped in ["target", "node_modules", "build", "dist"] {
            assert!(
                !overview.contains(skipped),
                "o índice não pode listar {skipped}: {overview}"
            );
        }
    }

    #[test]
    fn sanitizes_example_secret_from_reads_and_search() {
        let workspace = fixture_workspace();

        let text = workspace.read_text("src/config.py", Some(4096)).unwrap();
        assert!(text.contains("[REDACTED]"));
        assert!(!text.contains("valor-de-exemplo"));

        let hits = workspace.search("EXEMPLO_SECRET", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].text.contains("[REDACTED]"));
        assert!(!hits[0].text.contains("valor-de-exemplo"));
    }

    #[test]
    fn open_rejects_missing_path_and_file() {
        let missing = std::env::temp_dir().join(format!(
            "smartsec-inexistente-{}-{}",
            std::process::id(),
            "code-agent"
        ));
        assert!(matches!(
            Workspace::open(&missing),
            Err(WorkspaceError::NotFound { .. })
        ));
        assert!(matches!(
            Workspace::open(&fixture_root().join("README.md")),
            Err(WorkspaceError::NotADirectory { .. })
        ));
    }

    #[test]
    fn read_and_list_reject_wrong_entry_kind() {
        let workspace = fixture_workspace();

        assert!(matches!(
            workspace.read_text("src", Some(64)),
            Err(WorkspaceError::NotAFile { .. })
        ));
        assert!(matches!(
            workspace.list_dir("README.md"),
            Err(WorkspaceError::NotADirectory { .. })
        ));
        assert!(matches!(
            workspace.read_text("nao-existe.txt", Some(64)),
            Err(WorkspaceError::NotFound { .. })
        ));
    }

    #[test]
    fn resolve_accepts_root_and_absolute_path_inside_root() {
        let workspace = fixture_workspace();

        assert_eq!(workspace.resolve(".").unwrap(), workspace.root());
        let absolute = workspace.root().join("src/app.py");
        assert_eq!(
            workspace.resolve(&absolute.display().to_string()).unwrap(),
            absolute
        );
    }
}
