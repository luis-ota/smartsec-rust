//! Prévia local do código ao redor de um achado.
//!
//! A leitura passa pelo mesmo sandbox do agente (`Workspace`), mas usa a versão
//! crua: a sanitização de logs apagaria a linha inteira ao ver `request` ou
//! `password`, e aqui o objetivo é mostrar o código com a sintaxe preservada.

use crate::code_agent::workspace::{Workspace, WorkspaceError};
use crate::utils::redaction::sanitize_code_line;
use std::path::{Path, PathBuf};

pub const PREVIEW_CONTEXT: usize = 1;
pub const PREVIEW_MAX_LINE_CHARS: usize = 400;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodePreview {
    pub finding_index: usize,
    pub file: String,
    pub line: usize,
    pub root: PathBuf,
    pub state: PreviewState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreviewState {
    Ready {
        first: usize,
        lines: Vec<PreviewLine>,
        truncated: bool,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewLine {
    pub number: usize,
    pub text: String,
    pub is_target: bool,
}

impl CodePreview {
    pub fn load(finding_index: usize, root: &Path, file: &str, line: usize) -> Self {
        let state = Self::read(root, file, line);
        Self {
            finding_index,
            file: file.to_string(),
            line,
            root: root.to_path_buf(),
            state,
        }
    }

    fn read(root: &Path, file: &str, line: usize) -> PreviewState {
        if line == 0 {
            return unavailable("linha inválida");
        }
        let workspace = match Workspace::open(root) {
            Ok(workspace) => workspace,
            Err(error) => return unavailable(root_reason(&error)),
        };
        let text =
            match workspace.read_text_raw(file, Some(crate::code_agent::DEFAULT_MAX_FILE_BYTES)) {
                Ok(text) => text,
                Err(error) => return unavailable(file_reason(&error)),
            };
        if text.contains('\0') {
            return unavailable("arquivo binário");
        }
        let all_lines: Vec<&str> = text.lines().collect();
        if all_lines.is_empty() {
            return unavailable("arquivo vazio");
        }
        if line > all_lines.len() {
            return unavailable(format!(
                "linha {line} não existe no arquivo ({} linhas)",
                all_lines.len()
            ));
        }
        let first = line.saturating_sub(PREVIEW_CONTEXT).max(1);
        let last = (line + PREVIEW_CONTEXT).min(all_lines.len());
        let lines = (first..=last)
            .map(|number| PreviewLine {
                number,
                text: truncate_chars(
                    &sanitize_code_line(all_lines[number - 1]),
                    PREVIEW_MAX_LINE_CHARS,
                ),
                is_target: number == line,
            })
            .collect();
        PreviewState::Ready {
            first,
            lines,
            truncated: text.len() >= crate::code_agent::DEFAULT_MAX_FILE_BYTES,
        }
    }
}

fn unavailable(reason: impl Into<String>) -> PreviewState {
    PreviewState::Unavailable {
        reason: reason.into(),
    }
}

fn root_reason(error: &WorkspaceError) -> String {
    match error {
        WorkspaceError::NotFound { .. } | WorkspaceError::NotADirectory { .. } => {
            "projeto analisado indisponível".to_string()
        }
        WorkspaceError::OutsideRoot { .. } => "projeto fora da raiz permitida".to_string(),
        WorkspaceError::NotAFile { .. } | WorkspaceError::Io { .. } => {
            "não foi possível abrir o projeto analisado".to_string()
        }
    }
}

fn file_reason(error: &WorkspaceError) -> String {
    match error {
        WorkspaceError::NotFound { .. } => "arquivo não encontrado no projeto".to_string(),
        WorkspaceError::OutsideRoot { .. } => "arquivo fora do projeto analisado".to_string(),
        WorkspaceError::NotAFile { .. } => "o caminho não é um arquivo regular".to_string(),
        WorkspaceError::NotADirectory { .. } => "o caminho não é um diretório".to_string(),
        WorkspaceError::Io { .. } => "não foi possível ler o arquivo".to_string(),
    }
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut output: String = value.chars().take(max_chars).collect();
    output.push('…');
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn project(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("smartsec-preview-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).unwrap();
        root
    }

    #[test]
    fn loads_a_three_line_window_and_marks_the_target() {
        let root = project("window");
        fs::write(
            root.join("src/app.py"),
            "def login(user):\n    if not user:\n        raise ValueError('falha')\n    return user\n",
        )
        .unwrap();

        let preview = CodePreview::load(0, &root, "src/app.py", 3);

        let PreviewState::Ready { first, lines, .. } = preview.state else {
            panic!("preview deveria estar pronto: {preview:?}");
        };
        assert_eq!(first, 2);
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().any(|line| line.number == 3 && line.is_target));
        assert!(lines
            .iter()
            .any(|line| line.text.contains("raise ValueError")));
    }

    #[test]
    fn missing_file_becomes_an_actionable_reason() {
        let root = project("missing");
        let preview = CodePreview::load(0, &root, "src/nao-existe.py", 1);

        let PreviewState::Unavailable { reason } = preview.state else {
            panic!("preview não deveria carregar");
        };
        assert!(reason.contains("não encontrado"), "{reason}");
    }

    #[test]
    fn traversal_is_refused_by_the_workspace() {
        let root = project("traversal");
        let preview = CodePreview::load(0, &root, "../fora.py", 1);

        let PreviewState::Unavailable { reason } = preview.state else {
            panic!("traversal não deveria carregar");
        };
        assert!(reason.contains("fora"), "{reason}");
    }
}
