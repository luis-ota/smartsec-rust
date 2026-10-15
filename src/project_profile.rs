//! Perfil rápido do projeto analisado, usado para pré-selecionar ferramentas na
//! tela de Ferramentas da TUI.
//!
//! A varredura é barata e capada e produz **indícios**, não certezas: a ausência
//! de sinal nunca desmarca uma ferramenta por dúvida (o SQLMap sem indícios de
//! banco fica marcado). O walker reaproveita o sandbox de leitura do agente de
//! código, com os mesmos diretórios ignorados do `code_audit`.

use crate::code_agent::workspace::Workspace;
use std::collections::BTreeMap;
use std::path::Path;

/// Teto de arquivos vistos pela varredura do perfil, igual ao do `code_audit`.
pub const MAX_PROFILE_FILES: usize = 400;
const MAX_PROFILE_DEPTH: usize = 8;
const MAX_PROFILE_FILE_BYTES: usize = 64 * 1024;

/// Mesma lista de diretórios ignorados do `code_audit`.
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

const LANGUAGE_BY_EXTENSION: &[(&str, &str)] = &[
    ("py", "Python"),
    ("js", "JavaScript"),
    ("mjs", "JavaScript"),
    ("cjs", "JavaScript"),
    ("jsx", "JavaScript"),
    ("ts", "TypeScript"),
    ("tsx", "TypeScript"),
    ("php", "PHP"),
    ("java", "Java"),
    ("go", "Go"),
    ("rb", "Ruby"),
    ("rs", "Rust"),
    ("kt", "Kotlin"),
    ("cs", "C#"),
    ("sql", "SQL"),
    ("html", "HTML"),
    ("htm", "HTML"),
];

/// Manifests de dependências cujo conteúdo entra na busca por sinais.
const MANIFEST_FILES: &[&str] = &[
    "package.json",
    "pyproject.toml",
    "pipfile",
    "gemfile",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "go.mod",
    "cargo.toml",
];

/// Extensões de código cujo conteúdo entra na busca por sinais.
const SOURCE_EXTENSIONS: &[&str] = &[
    "py", "js", "mjs", "cjs", "jsx", "ts", "tsx", "php", "java", "go", "rb", "rs", "kt", "cs",
    "gradle",
];

/// Sinais de aplicação web em código e manifests. A busca é por substring, de
/// propósito: falso positivo mantém a ferramenta marcada, o lado seguro.
const WEB_SIGNALS: &[&str] = &[
    "flask",
    "django",
    "fastapi",
    "http.server",
    "express",
    "spring",
    "rails",
    "laravel",
    "symfony",
    "gunicorn",
    "uvicorn",
];

/// Sinais de banco SQL: drivers, ORMs e arquivos `.sql`.
const SQL_SIGNALS: &[&str] = &[
    "sqlite",
    "sqlalchemy",
    "psycopg",
    "pymysql",
    "mysql",
    "postgres",
    "jdbc",
    "sequelize",
    "typeorm",
    "prisma",
    "knex",
    "diesel",
    "sqlx",
    "rusqlite",
    "hibernate",
    "doctrine",
    "gorm",
    "activerecord",
];

/// Sinais de banco NoSQL: drivers e serviços.
const NOSQL_SIGNALS: &[&str] = &[
    "pymongo",
    "mongoose",
    "mongodb",
    "redis",
    "ioredis",
    "cassandra",
    "dynamodb",
    "firebase",
    "firestore",
    "elasticsearch",
    "couchdb",
    "neo4j",
];

/// Indícios coletados do projeto, sem juízo de valor sobre o alvo.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectProfile {
    /// Arquivos por linguagem reconhecida, do maior para o menor.
    pub languages: Vec<(String, usize)>,
    pub web_app: bool,
    pub sql_database: bool,
    pub nosql_database: bool,
    pub git_repository: bool,
    pub files_scanned: usize,
}

/// Recomendação de seleção para uma ferramenta do catálogo embutido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolRecommendation {
    pub selected: bool,
    pub reason: &'static str,
}

pub const NMAP_REASON: &str = "descoberta de portas e serviços";
pub const NUCLEI_REASON: &str = "varredura genérica de vulnerabilidades";
pub const WEB_REASON: &str = "indício de aplicação web no projeto";
pub const NO_WEB_REASON: &str = "nenhum indício de aplicação web no projeto";
pub const SQL_REASON: &str = "indício de banco SQL no projeto";
pub const NO_SQL_NOSQL_REASON: &str = "nenhum indício de banco SQL (projeto parece NoSQL)";
pub const SQL_UNKNOWN_REASON: &str = "sem indícios de banco; mantida por precaução";
pub const GIT_REASON: &str = "repositório git presente; histórico será varrido";
pub const NO_GIT_REASON: &str = "sem repositório git para varrer o histórico";

/// Perfil do projeto, ou `None` quando o diretório não pode ser aberto: sem
/// perfil, nenhuma ferramenta é desmarcada por dúvida.
pub fn profile_project(root: &Path) -> Option<ProjectProfile> {
    let workspace = Workspace::open(root).ok()?;
    let mut profile = ProjectProfile {
        git_repository: workspace.root().join(".git").exists(),
        ..ProjectProfile::default()
    };

    let mut files = Vec::new();
    collect_files(&workspace, ".", MAX_PROFILE_DEPTH, &mut files);

    let mut languages: BTreeMap<&'static str, usize> = BTreeMap::new();
    for path in &files {
        scan_file(&workspace, path, &mut profile, &mut languages);
    }

    profile.files_scanned = files.len();
    profile.languages = languages
        .into_iter()
        .map(|(language, count)| (language.to_string(), count))
        .collect();
    profile
        .languages
        .sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Some(profile)
}

/// Recomendação da ferramenta a partir do perfil; `None` para ferramentas fora
/// do catálogo embutido, que não têm heurística própria.
pub fn recommendation_for(tool_name: &str, profile: &ProjectProfile) -> Option<ToolRecommendation> {
    let keep = |reason| {
        Some(ToolRecommendation {
            selected: true,
            reason,
        })
    };
    let drop = |reason| {
        Some(ToolRecommendation {
            selected: false,
            reason,
        })
    };
    match tool_name.trim().to_ascii_lowercase().as_str() {
        "nmap" => keep(NMAP_REASON),
        "nuclei" => keep(NUCLEI_REASON),
        "nikto" | "zap" => {
            if profile.web_app {
                keep(WEB_REASON)
            } else {
                drop(NO_WEB_REASON)
            }
        }
        "sqlmap" => {
            if profile.sql_database {
                keep(SQL_REASON)
            } else if profile.nosql_database {
                drop(NO_SQL_NOSQL_REASON)
            } else {
                keep(SQL_UNKNOWN_REASON)
            }
        }
        "trufflehog" => {
            if profile.git_repository {
                keep(GIT_REASON)
            } else {
                drop(NO_GIT_REASON)
            }
        }
        _ => None,
    }
}

/// Resumo curto do perfil para a tela de Ferramentas, em pt-BR.
pub fn summary_pt_br(profile: &ProjectProfile) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some((language, count)) = profile.languages.first() {
        parts.push(format!("{language} ({count} arquivo(s))"));
    }
    if profile.web_app {
        parts.push("aplicação web".to_string());
    }
    if profile.sql_database {
        parts.push("banco SQL".to_string());
    }
    if profile.nosql_database {
        parts.push("NoSQL".to_string());
    }
    if profile.git_repository {
        parts.push("git".to_string());
    }
    if parts.is_empty() {
        parts.push("sem sinais relevantes".to_string());
    }
    parts.join(" · ")
}

fn collect_files(workspace: &Workspace, dir: &str, depth: usize, files: &mut Vec<String>) {
    if depth == 0 || files.len() >= MAX_PROFILE_FILES {
        return;
    }
    let Ok(entries) = workspace.list_dir(dir) else {
        return;
    };
    for entry in entries {
        if files.len() >= MAX_PROFILE_FILES {
            return;
        }
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
                collect_files(workspace, &path, depth - 1, files);
            }
        } else {
            files.push(path);
        }
    }
}

fn scan_file(
    workspace: &Workspace,
    path: &str,
    profile: &mut ProjectProfile,
    languages: &mut BTreeMap<&'static str, usize>,
) {
    let name = path.rsplit('/').next().unwrap_or(path);
    let lower = name.to_ascii_lowercase();
    let extension = lower.rsplit_once('.').map_or("", |(_, ext)| ext);

    if let Some((_, language)) = LANGUAGE_BY_EXTENSION
        .iter()
        .find(|(candidate, _)| *candidate == extension)
    {
        *languages.entry(language).or_default() += 1;
    }
    if extension == "sql" {
        profile.sql_database = true;
    }
    if matches!(extension, "html" | "htm" | "php") {
        profile.web_app = true;
    }

    let is_manifest = MANIFEST_FILES.contains(&lower.as_str())
        || (lower.starts_with("requirements") && lower.ends_with(".txt"));
    if !is_manifest && !SOURCE_EXTENSIONS.contains(&extension) {
        return;
    }
    let Ok(text) = workspace.read_text(path, Some(MAX_PROFILE_FILE_BYTES)) else {
        return;
    };
    let text = text.to_ascii_lowercase();
    if WEB_SIGNALS.iter().any(|signal| text.contains(signal)) {
        profile.web_app = true;
    }
    if SQL_SIGNALS.iter().any(|signal| text.contains(signal)) {
        profile.sql_database = true;
    }
    if NOSQL_SIGNALS.iter().any(|signal| text.contains(signal)) {
        profile.nosql_database = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_project(label: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "smartsec-perfil-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn a_python_project_with_sqlite_keeps_sqlmap_selected() {
        let root = temp_project("python-sqlite");
        write(
            &root,
            "app.py",
            "import sqlite3\n\nconexao = sqlite3.connect('dados.db')\n",
        );

        let profile = profile_project(&root).expect("perfil do projeto");

        assert!(profile.sql_database, "{profile:?}");
        assert!(!profile.nosql_database, "{profile:?}");
        assert_eq!(
            profile
                .languages
                .first()
                .map(|(name, count)| (name.as_str(), *count)),
            Some(("Python", 1)),
            "{profile:?}"
        );
        let recommendation = recommendation_for("SQLMap", &profile).unwrap();
        assert!(recommendation.selected, "{recommendation:?}");
        assert_eq!(recommendation.reason, SQL_REASON);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_node_project_with_mongoose_and_redis_drops_sqlmap_with_reason() {
        let root = temp_project("node-nosql");
        write(
            &root,
            "package.json",
            r#"{"dependencies":{"mongoose":"^8.0.0","redis":"^4.6.0"}}"#,
        );
        write(
            &root,
            "server.js",
            "const mongoose = require('mongoose');\n",
        );

        let profile = profile_project(&root).unwrap();

        assert!(profile.nosql_database, "{profile:?}");
        assert!(!profile.sql_database, "{profile:?}");
        let recommendation = recommendation_for("sqlmap", &profile).unwrap();
        assert!(!recommendation.selected, "{recommendation:?}");
        assert_eq!(recommendation.reason, NO_SQL_NOSQL_REASON);
        assert!(recommendation.reason.contains("NoSQL"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_project_without_web_signals_drops_nikto_and_zap() {
        let root = temp_project("sem-web");
        write(&root, "src/lib.rs", "pub fn executar() {}\n");

        let profile = profile_project(&root).unwrap();

        assert!(!profile.web_app, "{profile:?}");
        for tool in ["Nikto", "ZAP"] {
            let recommendation = recommendation_for(tool, &profile).unwrap();
            assert!(!recommendation.selected, "{tool}: {recommendation:?}");
            assert_eq!(recommendation.reason, NO_WEB_REASON);
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_flask_project_keeps_nikto_and_zap_selected() {
        let root = temp_project("flask");
        write(
            &root,
            "app.py",
            "from flask import Flask\napp = Flask(__name__)\n",
        );

        let profile = profile_project(&root).unwrap();

        assert!(profile.web_app, "{profile:?}");
        for tool in ["Nikto", "ZAP"] {
            let recommendation = recommendation_for(tool, &profile).unwrap();
            assert!(recommendation.selected, "{tool}: {recommendation:?}");
            assert_eq!(recommendation.reason, WEB_REASON);
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn trufflehog_follows_the_presence_of_a_git_repository() {
        let root = temp_project("git");
        write(&root, "main.go", "package main\n");

        let without_git = profile_project(&root).unwrap();
        assert!(!without_git.git_repository, "{without_git:?}");
        let recommendation = recommendation_for("TruffleHog", &without_git).unwrap();
        assert!(!recommendation.selected, "{recommendation:?}");
        assert_eq!(recommendation.reason, NO_GIT_REASON);

        fs::create_dir_all(root.join(".git")).unwrap();
        let with_git = profile_project(&root).unwrap();
        assert!(with_git.git_repository, "{with_git:?}");
        let recommendation = recommendation_for("TruffleHog", &with_git).unwrap();
        assert!(recommendation.selected, "{recommendation:?}");
        assert_eq!(recommendation.reason, GIT_REASON);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unreadable_project_produces_no_profile() {
        let missing = std::env::temp_dir().join(format!(
            "smartsec-perfil-inexistente-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&missing);

        assert!(profile_project(&missing).is_none());
    }

    #[test]
    fn an_inconclusive_database_signal_keeps_sqlmap_selected() {
        let root = temp_project("sem-banco");
        write(&root, "app.py", "print('olá')\n");

        let profile = profile_project(&root).unwrap();

        assert!(
            !profile.sql_database && !profile.nosql_database,
            "{profile:?}"
        );
        let recommendation = recommendation_for("SQLMap", &profile).unwrap();
        assert!(recommendation.selected, "{recommendation:?}");
        assert_eq!(recommendation.reason, SQL_UNKNOWN_REASON);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn dependencies_inside_ignored_directories_do_not_count_as_signals() {
        let root = temp_project("ignorados");
        write(
            &root,
            "node_modules/pacote/package.json",
            r#"{"dependencies":{"mongoose":"^8"}}"#,
        );
        write(
            &root,
            "notes.md",
            "redis, mongoose e flask citados na documentação",
        );

        let profile = profile_project(&root).unwrap();

        assert!(!profile.nosql_database, "{profile:?}");
        assert!(!profile.web_app, "{profile:?}");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_scan_stops_at_the_file_cap() {
        let root = temp_project("cap");
        for index in 0..(MAX_PROFILE_FILES + 10) {
            write(&root, &format!("f{index:04}.py"), "print('ok')\n");
        }

        let profile = profile_project(&root).unwrap();

        assert_eq!(profile.files_scanned, MAX_PROFILE_FILES);
        assert_eq!(
            profile.languages.first().map(|(_, count)| *count),
            Some(MAX_PROFILE_FILES)
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn tools_outside_the_builtin_catalog_have_no_recommendation() {
        let profile = ProjectProfile::default();

        assert!(recommendation_for("ScannerExemplo", &profile).is_none());
    }

    #[test]
    fn always_on_tools_keep_their_reason_even_in_an_empty_profile() {
        let profile = ProjectProfile::default();

        assert_eq!(
            recommendation_for("Nmap", &profile).unwrap().reason,
            NMAP_REASON
        );
        assert_eq!(
            recommendation_for("Nuclei", &profile).unwrap().reason,
            NUCLEI_REASON
        );
    }
}
