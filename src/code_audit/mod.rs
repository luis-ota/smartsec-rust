pub mod python;

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::domain::severity::Severity;
use crate::domain::vulnerability::{FindingSource, Vulnerability};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeAuditFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub evidence: String,
    pub recommendation: String,
    pub didactic: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeAuditReport {
    pub findings: Vec<CodeAuditFinding>,
    pub files_scanned: usize,
    pub limitation: Option<String>,
}

pub fn to_vulnerability(finding: &CodeAuditFinding) -> Vulnerability {
    Vulnerability {
        title: finding.title.clone(),
        severity: finding.severity,
        description: format!(
            "{} detectada em {}:{}.",
            finding.title, finding.file, finding.line
        ),
        tool: "code-audit".to_string(),
        recommendation: finding.recommendation.clone(),
        didactic: finding.didactic.clone(),
        source: FindingSource::CodeAudit,
        target: finding.file.clone(),
        evidence: format!("{}:{} · {}", finding.file, finding.line, finding.evidence),
        detected_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ..Vulnerability::default()
    }
}

pub const MAX_DEPTH: usize = 8;
pub const MAX_FILES: usize = 400;
pub const MAX_FILE_BYTES: u64 = 512 * 1024;

const IGNORED_DIRS: &[&str] = &[
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "target",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    "vendor",
    ".tox",
];

pub fn audit_project(root: &Path, max_files: usize, max_file_bytes: u64) -> CodeAuditReport {
    let Ok(workspace) = crate::code_agent::workspace::Workspace::open(root) else {
        return CodeAuditReport {
            limitation: Some(format!("projeto não pôde ser aberto em {}", root.display())),
            ..CodeAuditReport::default()
        };
    };

    let mut findings = Vec::new();
    let mut files_scanned = 0usize;
    let mut limitations: Vec<String> = Vec::new();

    for path in collect_sources(&workspace, ".", MAX_DEPTH) {
        if files_scanned >= max_files {
            limitations.push(format!(
                "varredura interrompida no limite de {max_files} arquivos; \
                 o restante do projeto não foi coberto"
            ));
            break;
        }

        let Ok(resolved) = workspace.resolve(&path) else {
            continue;
        };
        let Ok(raw) = std::fs::read_to_string(&resolved) else {
            continue;
        };
        if raw.len() as u64 > max_file_bytes {
            limitations.push(format!(
                "{path} tem {} bytes, acima do limite de {max_file_bytes}; não foi coberto",
                raw.len()
            ));
            continue;
        }

        findings.extend(python::scan(&path, &raw));
        files_scanned += 1;
    }

    findings.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));

    CodeAuditReport {
        findings,
        files_scanned,
        limitation: (!limitations.is_empty()).then(|| limitations.join("; ")),
    }
}

fn collect_sources(
    workspace: &crate::code_agent::workspace::Workspace,
    dir: &str,
    depth: usize,
) -> Vec<String> {
    if depth == 0 {
        return Vec::new();
    }
    let Ok(entries) = workspace.list_dir(dir) else {
        return Vec::new();
    };

    let mut files = Vec::new();
    for entry in entries {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let path = if dir == "." {
            trimmed.to_string()
        } else {
            format!("{dir}{trimmed}")
        };

        if trimmed.ends_with('/') {
            if !IGNORED_DIRS.contains(&trimmed.trim_end_matches('/')) {
                files.extend(collect_sources(workspace, &path, depth - 1));
            }
        } else if path.ends_with(".py") {
            files.push(path);
        }
    }
    files
}

#[cfg(test)]
mod tests;
