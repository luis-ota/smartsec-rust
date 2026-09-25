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

const SKIPPED_DIRECTORIES: &[&str] = &[".git", "target", "node_modules", "dist", "build"];
const BINARY_SAMPLE_BYTES: usize = 8 * 1024;

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
    pub fn read_text(&self, requested: &str, max_bytes: usize) -> Result<String, WorkspaceError> {
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
        Ok(sanitize_text(&text))
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
        let mut hits = Vec::new();
        let needle = term.to_ascii_lowercase();
        if needle.is_empty() || max_results == 0 {
            return Ok(hits);
        }
        self.search_directory(&self.root, &needle, max_results, &mut hits);
        Ok(hits)
    }

    fn search_directory(
        &self,
        directory: &Path,
        needle: &str,
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
            paths.push(entry.path());
        }
        paths.sort();
        for path in paths {
            if hits.len() >= max_results {
                return;
            }
            if path.is_dir() {
                self.search_directory(&path, needle, max_results, hits);
            } else {
                self.search_file(&path, needle, max_results, hits);
            }
        }
    }

    fn search_file(
        &self,
        path: &Path,
        needle: &str,
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
            if line.to_ascii_lowercase().contains(needle) {
                hits.push(SearchHit {
                    path: relative.clone(),
                    line: index + 1,
                    text: sanitize_text(line),
                });
            }
        }
    }
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

        let full = workspace.read_text("README.md", 4096).unwrap();
        assert!(full.starts_with("# Codebase de exemplo"));

        let truncated = workspace.read_text("src/app.py", 24).unwrap();
        assert!(truncated.contains(TRUNCATION_MARKER));
        assert!(truncated.contains("exibidos 24 de"));
        assert!(!truncated.contains("return user"));
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
            workspace.read_text("../Cargo.toml", 1024),
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
            workspace.read_text("escape/segredo.txt", 64),
            Err(WorkspaceError::OutsideRoot { .. })
        ));
        assert!(matches!(
            workspace.read_text("escape.txt", 64),
            Err(WorkspaceError::OutsideRoot { .. })
        ));
        assert_eq!(
            workspace.read_text("link.txt", 64).unwrap(),
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
    fn sanitizes_example_secret_from_reads_and_search() {
        let workspace = fixture_workspace();

        let text = workspace.read_text("src/config.py", 4096).unwrap();
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
            workspace.read_text("src", 64),
            Err(WorkspaceError::NotAFile { .. })
        ));
        assert!(matches!(
            workspace.list_dir("README.md"),
            Err(WorkspaceError::NotADirectory { .. })
        ));
        assert!(matches!(
            workspace.read_text("nao-existe.txt", 64),
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
