//! Prévia local do código ao redor de um achado, com realce de sintaxe.
//!
//! A leitura passa pelo mesmo sandbox do agente (`Workspace`), mas usa a versão
//! crua: a sanitização de logs apagaria a linha inteira ao ver `request` ou
//! `password`, e aqui o objetivo é mostrar o código com a sintaxe preservada.

use crate::code_agent::workspace::{Workspace, WorkspaceError};
use crate::utils::redaction::sanitize_code_line;
use ratatui::style::Color;
use std::path::{Path, PathBuf};
use unicode_width::UnicodeWidthChar;

pub const PREVIEW_CONTEXT: usize = 2;
pub const PREVIEW_MAX_LINES: usize = 24;
pub const PREVIEW_MAX_LINE_CHARS: usize = 400;

const KEYWORD: Color = Color::Rgb(198, 120, 221);
const STRING: Color = Color::Rgb(152, 195, 121);
const COMMENT: Color = Color::Rgb(106, 153, 85);
const NUMBER: Color = Color::Rgb(209, 154, 102);
const FUNCTION: Color = Color::Rgb(97, 175, 239);
const TEXT: Color = Color::Rgb(220, 223, 228);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodePreview {
    pub finding_index: usize,
    pub file: String,
    pub line: usize,
    pub root: PathBuf,
    pub language: CodeLanguage,
    pub state: PreviewState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreviewState {
    Ready {
        first: usize,
        lines: Vec<PreviewLine>,
        total_lines: usize,
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
            language: CodeLanguage::from_path(file),
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
        let total_lines = all_lines.len();
        if line > total_lines {
            return unavailable(format!(
                "linha {line} não existe no arquivo ({total_lines} linhas)"
            ));
        }
        let first = line.saturating_sub(PREVIEW_CONTEXT).max(1);
        let mut last = (line + PREVIEW_CONTEXT).min(total_lines);
        // Duas linhas acima preservam o alvo visível; abaixo, expande até o fim
        // do bloco (linha em branco) para mostrar a função inteira.
        while last < total_lines
            && last - first + 1 < PREVIEW_MAX_LINES
            && !all_lines[last].trim().is_empty()
        {
            last += 1;
        }
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
            total_lines,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeLanguage {
    Python,
    JavaScript,
    Php,
    Java,
    Rust,
    Text,
}

impl CodeLanguage {
    pub fn from_path(path: &str) -> Self {
        let extension = Path::new(path)
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default()
            .to_lowercase();
        match extension.as_str() {
            "py" => Self::Python,
            "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" => Self::JavaScript,
            "php" => Self::Php,
            "java" => Self::Java,
            "rs" => Self::Rust,
            _ => Self::Text,
        }
    }

    pub fn from_label(label: &str) -> Self {
        match label.to_lowercase().as_str() {
            "python" | "py" => Self::Python,
            "javascript" | "js" | "typescript" | "ts" | "tsx" | "jsx" => Self::JavaScript,
            "php" => Self::Php,
            "java" => Self::Java,
            "rust" | "rs" => Self::Rust,
            _ => Self::Text,
        }
    }

    fn is_keyword(self, word: &str) -> bool {
        const COMMON: &[&str] = &[
            "if", "else", "for", "while", "return", "true", "false", "null", "new", "class",
            "import", "from", "export", "async", "await", "this", "try", "except", "finally",
        ];
        const PYTHON: &[&str] = &[
            "def", "elif", "None", "True", "False", "raise", "with", "as", "in", "is", "not",
            "and", "or", "lambda", "pass", "yield",
        ];
        const JS: &[&str] = &[
            "const",
            "let",
            "var",
            "function",
            "undefined",
            "typeof",
            "instanceof",
            "switch",
            "case",
            "break",
            "continue",
            "of",
            "=>",
        ];
        const RUST: &[&str] = &[
            "fn", "let", "mut", "pub", "use", "struct", "enum", "impl", "match", "mod", "crate",
            "self", "Self", "Some", "Ok", "Err", "where", "trait",
        ];
        const PHP: &[&str] = &[
            "echo",
            "function",
            "foreach",
            "isset",
            "empty",
            "namespace",
            "require",
            "include",
        ];
        const JAVA: &[&str] = &[
            "public",
            "private",
            "protected",
            "static",
            "final",
            "void",
            "extends",
            "implements",
            "interface",
            "package",
            "throws",
            "throw",
        ];
        COMMON.contains(&word)
            || match self {
                Self::Python => PYTHON.contains(&word),
                Self::JavaScript => JS.contains(&word),
                Self::Rust => RUST.contains(&word),
                Self::Php => PHP.contains(&word),
                Self::Java => JAVA.contains(&word),
                Self::Text => false,
            }
    }
}

/// Realce simples de uma linha: comentário, string, número, palavra-chave e
/// chamada de função. Não é um parser; cobre a leitura de código na TUI.
/// Quebra uma linha destacada em várias linhas visuais, preservando as cores
/// dos tokens. Evita o `…` em blocos de código: o conteúdo continua legível.
pub fn wrap_highlighted_line(
    tokens: Vec<(String, Color)>,
    width: usize,
) -> Vec<Vec<(String, Color)>> {
    let width = width.max(1);
    let mut lines: Vec<Vec<(String, Color)>> = vec![Vec::new()];
    let mut used = 0usize;
    for (text, color) in tokens {
        let mut remaining = text.as_str();
        while !remaining.is_empty() {
            if used >= width {
                lines.push(Vec::new());
                used = 0;
            }
            let available = width - used;
            let mut piece = String::new();
            let mut piece_width = 0usize;
            for character in remaining.chars() {
                let character_width = character.width().unwrap_or(0);
                if !piece.is_empty() && piece_width + character_width > available {
                    break;
                }
                piece.push(character);
                piece_width += character_width;
                if piece_width >= available {
                    break;
                }
            }
            if piece.is_empty() {
                if let Some(character) = remaining.chars().next() {
                    piece.push(character);
                    piece_width = character.width().unwrap_or(0);
                }
            }
            lines
                .last_mut()
                .expect("sempre há uma linha")
                .push((piece.clone(), color));
            used += piece_width;
            remaining = &remaining[piece.len()..];
            if !remaining.is_empty() {
                lines.push(Vec::new());
                used = 0;
            }
        }
    }
    lines
}

pub fn highlight_line(line: &str, language: CodeLanguage) -> Vec<(String, Color)> {
    let mut spans = Vec::new();
    let mut index = 0;
    while index < line.len() {
        let rest = &line[index..];
        let first = rest.chars().next().expect("resto não vazio");
        let comment = match language {
            CodeLanguage::Python => rest.starts_with('#'),
            CodeLanguage::Text => false,
            _ => rest.starts_with("//") || rest.starts_with("/*"),
        };
        if comment {
            spans.push((rest.to_string(), COMMENT));
            break;
        }
        if first == '"' || first == '\'' || first == '`' {
            let end = rest[1..]
                .find(first)
                .map(|offset| offset + 1 + first.len_utf8())
                .unwrap_or(rest.len());
            spans.push((rest[..end].to_string(), STRING));
            index += end;
            continue;
        }
        if first.is_ascii_digit() {
            let end = rest
                .char_indices()
                .find(|(_, character)| {
                    !(character.is_ascii_alphanumeric() || *character == '.' || *character == '_')
                })
                .map(|(offset, _)| offset)
                .unwrap_or(rest.len());
            spans.push((rest[..end].to_string(), NUMBER));
            index += end;
            continue;
        }
        if first.is_alphanumeric() || first == '_' || first == '$' {
            let end = rest
                .char_indices()
                .find(|(_, character)| {
                    !(character.is_alphanumeric() || *character == '_' || *character == '$')
                })
                .map(|(offset, _)| offset)
                .unwrap_or(rest.len());
            let word = &rest[..end];
            let after = rest[end..].trim_start();
            let color = if language.is_keyword(word) {
                KEYWORD
            } else if after.starts_with('(') {
                FUNCTION
            } else {
                TEXT
            };
            spans.push((word.to_string(), color));
            index += end;
            continue;
        }
        spans.push((first.to_string(), TEXT));
        index += first.len_utf8();
    }
    if spans.is_empty() {
        spans.push((String::new(), TEXT));
    }
    spans
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
    fn loads_a_window_and_marks_the_target() {
        let root = project("window");
        fs::write(
            root.join("src/app.py"),
            "def login(user):\n    if not user:\n        raise ValueError('falha')\n    return user\n",
        )
        .unwrap();

        let preview = CodePreview::load(0, &root, "src/app.py", 3);

        let PreviewState::Ready {
            first,
            lines,
            total_lines,
            ..
        } = preview.state
        else {
            panic!("preview deveria estar pronto: {preview:?}");
        };
        assert_eq!(first, 1);
        assert_eq!(total_lines, 4);
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

    #[test]
    fn long_code_lines_wrap_without_losing_content() {
        let original =
            "const resultado = funcaoMuitoLonga(argumentoUm, argumentoDois, argumentoTres);";
        let tokens = highlight_line(original, CodeLanguage::JavaScript);
        let wrapped = wrap_highlighted_line(tokens, 18);
        assert!(wrapped.len() > 1, "{wrapped:?}");
        let joined: String = wrapped
            .iter()
            .flat_map(|line| line.iter())
            .map(|(text, _)| text.as_str())
            .collect();
        assert_eq!(joined, original);
    }

    #[test]
    fn syntax_highlight_distinguishes_keyword_string_and_comment() {
        let spans = highlight_line(
            "const token = \"segredo\"; // nota",
            CodeLanguage::JavaScript,
        );
        assert!(spans
            .iter()
            .any(|(text, color)| text == "const" && *color == KEYWORD));
        assert!(spans
            .iter()
            .any(|(text, color)| text == "\"segredo\"" && *color == STRING));
        assert!(spans
            .iter()
            .any(|(text, color)| text.starts_with("//") && *color == COMMENT));
    }
}
